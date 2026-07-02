from __future__ import annotations

import re
from pathlib import Path
from typing import Any


RUN_SECTION_RE = re.compile(
    r"(?im)^(?:#+\s*)?(?:running|run locally|development|quick start|getting started|start)\b.*$"
)


def build_census(repo_path: Path) -> dict[str, Any]:
    return {
        "ci_files": _read_named_files(repo_path, _ci_paths(repo_path), 4000),
        "deploy_files": _read_named_files(repo_path, _deploy_paths(repo_path), 4000),
        "makefile_targets": _make_targets(repo_path / "Makefile"),
        "readme_run_excerpt": _readme_run_excerpt(repo_path),
    }


def _ci_paths(repo_path: Path) -> list[Path]:
    paths: list[Path] = []
    workflows = repo_path / ".github" / "workflows"
    if workflows.exists():
        paths.extend(sorted(p for p in workflows.glob("*.y*ml") if p.is_file())[:10])
    circle = repo_path / ".circleci" / "config.yml"
    if circle.exists():
        paths.append(circle)
    return paths


def _deploy_paths(repo_path: Path) -> list[Path]:
    names = ["Procfile", "fly.toml", "render.yaml", "render.yml", "railway.json", "app.json"]
    return [repo_path / name for name in names if (repo_path / name).exists()]


def _read_named_files(repo_path: Path, paths: list[Path], limit: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in paths:
        try:
            key = path.relative_to(repo_path).as_posix()
        except ValueError:
            key = path.name
        try:
            out[key] = path.read_text(encoding="utf-8", errors="replace")[:limit]
        except OSError:
            continue
    return out


def _make_targets(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    targets = []
    for line in text.splitlines():
        if line.startswith("\t") or ":" not in line:
            continue
        name = line.split(":", 1)[0].strip()
        if name and re.match(r"^[A-Za-z0-9_.-]+$", name):
            targets.append(name)
    return targets[:40]


def _readme_run_excerpt(repo_path: Path, limit: int = 2500) -> str:
    for name in ("README.md", "README.rst", "README.txt"):
        path = repo_path / name
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = RUN_SECTION_RE.search(text)
        if not match:
            return text[:limit]
        return text[match.start() : match.start() + limit]
    return ""
