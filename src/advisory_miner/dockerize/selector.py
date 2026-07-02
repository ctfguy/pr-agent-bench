from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from advisory_miner.openai_client import OpenAIClient

from .census import build_census
from .detect import WebAppKind, discover_candidates, has_docker_setup


SYSTEM_PROMPT = """You select the best web application root for Dockerization.
Use only the candidate roots and repository summary provided.
Return JSON only with keys: selected_root, rationale, confidence.
selected_root must be exactly one candidate root_path, or null if no candidate should be dockerized.
Prefer backend/API/fullstack roots over frontend-only roots when only one service can be generated.
Do not invent paths, files, frameworks, ports, or dependencies.
"""


@dataclass
class RepoProfile:
    root: str
    total_files: int
    top_level_entries: list[str]
    extension_counts: dict[str, int]
    existing_docker: dict[str, Any]
    repo_census: dict[str, Any]
    candidates: list[dict[str, Any]]


def select_web_app(client: OpenAIClient | None, repo_path: Path) -> WebAppKind | None:
    candidates = discover_candidates(repo_path)
    if not candidates:
        return None
    if len(candidates) == 1 or client is None:
        return candidates[0]

    profile = build_repo_profile(repo_path, candidates)
    try:
        result = client.json_response(SYSTEM_PROMPT, asdict(profile), max_output_tokens=1000)
    except Exception:
        return candidates[0]

    selected = result.get("selected_root")
    if selected is None:
        return None
    for candidate in candidates:
        if candidate.root_path == selected:
            return candidate
    return candidates[0]


def build_repo_profile(repo_path: Path, candidates: list[WebAppKind] | None = None) -> RepoProfile:
    candidates = candidates if candidates is not None else discover_candidates(repo_path)
    files = [path for path in repo_path.rglob("*") if path.is_file() and _is_profile_file(repo_path, path)]
    extensions = Counter(_extension(path) for path in files)
    return RepoProfile(
        root=str(repo_path),
        total_files=len(files),
        top_level_entries=sorted(path.name for path in repo_path.iterdir())[:80],
        extension_counts=dict(extensions.most_common(30)),
        existing_docker=has_docker_setup(repo_path),
        repo_census=build_census(repo_path),
        candidates=[_candidate_payload(repo_path, candidate) for candidate in candidates],
    )


def _candidate_payload(repo_path: Path, candidate: WebAppKind) -> dict[str, Any]:
    root = repo_path / candidate.root_path
    return {
        **candidate.to_dict(),
        "signal_files": _signal_files(root),
        "directory_entries": sorted(path.name for path in root.iterdir())[:60] if root.exists() else [],
        "existing_docker": has_docker_setup(root),
    }


def _signal_files(root: Path) -> list[str]:
    names = {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "go.mod",
        "go.sum",
        "vite.config.js",
        "next.config.js",
        "nuxt.config.js",
        "manage.py",
        "Dockerfile",
        "compose.yml",
        "compose.yaml",
    }
    found = []
    for path in root.rglob("*"):
        if path.is_file() and path.name in names:
            try:
                found.append(path.relative_to(root).as_posix())
            except ValueError:
                pass
        if len(found) >= 80:
            break
    return sorted(found)


def _is_profile_file(repo_path: Path, path: Path) -> bool:
    try:
        parts = path.relative_to(repo_path).parts
    except ValueError:
        return False
    return not any(part in {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv"} for part in parts)


def _extension(path: Path) -> str:
    return path.suffix.lower() or "[none]"
