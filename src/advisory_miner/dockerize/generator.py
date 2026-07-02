"""LLM-driven generation of Dockerfile, .dockerignore, compose.yml.

The prompt is intentionally strict: single-stage builds, port exposed, no
auxiliary services unless manifest evidence supports them. The runner feeds
back validation errors so the model can repair its output across retries.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from advisory_miner.openai_client import OpenAIClient

from .census import build_census
from .detect import WebAppKind


SYSTEM_PROMPT = """You generate minimal Docker setups for simple web apps.

Return JSON only with exactly these keys:
  dockerfile  — full text of a Dockerfile
  dockerignore — full text of a .dockerignore
  compose_yml — full text of a compose.yml using compose spec v3+ syntax

Rules:
- Single-stage builds where feasible; multi-stage only for Go binaries.
- Use the minimal official base image for the language (python:3.x-slim,
  node:20-alpine, golang:1.22-alpine).
- Expose the application port via EXPOSE and the compose `ports:` block.
- The container must start the app automatically (CMD or ENTRYPOINT) and
  bind the server to 0.0.0.0, not localhost.
- Do NOT add extra services (postgres / redis / mysql / mongo) unless the
  manifest_contents you were given mention them as a dependency.
- compose.yml must contain a single `app` service under `services:` and
  publish the app port.
- Do not invent files that are not present in manifest_contents.
- If a previous attempt was provided in `feedback_from_previous_attempt`,
  read the error log carefully and adjust your output to fix the failure.
"""


def generate_files(
    client: OpenAIClient,
    repo_path: Path,
    kind: WebAppKind,
    feedback: str | None = None,
    max_output_tokens: int = 4000,
) -> tuple[str, str, str]:
    payload: dict[str, Any] = {
        "language": kind.language,
        "framework": kind.framework,
        "entry_point": kind.entry_point,
        "start_command": kind.start_command,
        "port": kind.port,
        "app_root": ".",
        "selected_repo_root": kind.root_path,
        "manifest_contents": _read_manifests(repo_path, kind.manifest_files),
        "readme_excerpt": _read_excerpt(repo_path / "README.md", 1500),
        "repo_census": build_census(repo_path),
        "feedback_from_previous_attempt": feedback,
    }
    result = client.json_response(SYSTEM_PROMPT, payload, max_output_tokens=max_output_tokens)
    dockerfile = result.get("dockerfile") or ""
    dockerignore = result.get("dockerignore") or ""
    compose_yml = result.get("compose_yml") or ""
    if not dockerfile or not compose_yml:
        raise ValueError("Generator returned an empty dockerfile or compose_yml")
    return dockerfile, dockerignore, compose_yml


def _read_manifests(repo_path: Path, files: list[str], char_limit: int = 4000) -> dict[str, str]:
    contents: dict[str, str] = {}
    for relative in files:
        path = repo_path / relative
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        contents[relative] = text[:char_limit]
    return contents


def _read_excerpt(path: Path, char_limit: int) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:char_limit]
    except OSError:
        return ""
