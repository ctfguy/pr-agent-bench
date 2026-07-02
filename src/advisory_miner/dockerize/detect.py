"""Web-app kind detection for the Dockerize agent.

We deliberately scope detection to Node/Python/Go apps with a recognizable
HTTP framework (Express/Koa/Fastify/Next/Nuxt/Nest for Node;
Flask/Django/FastAPI/Sanic/Starlette/Bottle/Tornado for Python; net/http,
Gin, Echo, Chi for Go). Libraries, CLIs, and mobile apps return ``None``;
the runner will not attempt to dockerize them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class WebAppKind:
    language: str
    framework: str | None
    entry_point: str | None
    start_command: str | None
    port: int
    manifest_files: list[str]
    root_path: str = "."

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "framework": self.framework,
            "entry_point": self.entry_point,
            "start_command": self.start_command,
            "port": self.port,
            "manifest_files": self.manifest_files,
            "root_path": self.root_path,
        }


NODE_FRAMEWORKS = (
    "express",
    "koa",
    "fastify",
    "next",
    "nuxt",
    "vite",
    "react",
    "@nestjs/core",
    "nestjs",
)
PYTHON_FRAMEWORKS = (
    "fastapi",
    "flask",
    "django",
    "sanic",
    "starlette",
    "bottle",
    "tornado",
)
GO_FRAMEWORKS = (
    "gin-gonic/gin",
    "labstack/echo",
    "go-chi/chi",
    "gorilla/mux",
)

DEFAULT_PORTS = {
    "next": 3000,
    "nuxt": 3000,
    "vite": 5173,
    "react": 5173,
    "express": 3000,
    "koa": 3000,
    "fastify": 3000,
    "@nestjs/core": 3000,
    "nestjs": 3000,
    "flask": 8000,
    "django": 8000,
    "fastapi": 8000,
    "sanic": 8000,
    "starlette": 8000,
    "bottle": 8080,
    "tornado": 8888,
    "gin-gonic/gin": 8080,
    "labstack/echo": 8080,
    "go-chi/chi": 8080,
    "gorilla/mux": 8080,
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "__pycache__",
    "coverage",
    "docs",
    "doc",
    "test",
    "tests",
    "spec",
}


def detect(repo_path: Path) -> WebAppKind | None:
    return discover_web_app(repo_path)


def discover_web_app(repo_path: Path, max_depth: int = 4) -> WebAppKind | None:
    candidates = discover_candidates(repo_path, max_depth=max_depth)
    return candidates[0] if candidates else None


def discover_candidates(repo_path: Path, max_depth: int = 4) -> list[WebAppKind]:
    candidates: list[tuple[int, WebAppKind]] = []
    root_kind = _detect_at_root(repo_path)
    if root_kind:
        candidates.append((_score_candidate(root_kind, "."), root_kind))

    for candidate_root in _candidate_roots(repo_path, max_depth=max_depth):
        if candidate_root == repo_path:
            continue
        kind = _detect_at_root(candidate_root)
        if not kind:
            continue
        relative = candidate_root.relative_to(repo_path).as_posix()
        kind.root_path = relative
        candidates.append((_score_candidate(kind, relative), kind))

    candidates.sort(key=lambda item: item[0], reverse=True)
    return [candidate for _, candidate in candidates]


def _detect_at_root(repo_path: Path) -> WebAppKind | None:
    package_json = repo_path / "package.json"
    if package_json.exists():
        kind = _detect_node(repo_path, package_json)
        if kind:
            return kind
    if (repo_path / "requirements.txt").exists() or (repo_path / "pyproject.toml").exists():
        kind = _detect_python(repo_path)
        if kind:
            return kind
    if (repo_path / "go.mod").exists():
        kind = _detect_go(repo_path)
        if kind:
            return kind
    return None


def _candidate_roots(repo_path: Path, max_depth: int) -> list[Path]:
    roots: list[Path] = []
    seen: set[Path] = set()
    manifests = {"package.json", "requirements.txt", "pyproject.toml", "go.mod"}
    for path in repo_path.rglob("*"):
        if not path.is_file() or path.name not in manifests:
            continue
        try:
            relative_parts = path.parent.relative_to(repo_path).parts
        except ValueError:
            continue
        if len(relative_parts) > max_depth or any(part in SKIP_DIRS for part in relative_parts):
            continue
        if path.parent not in seen:
            roots.append(path.parent)
            seen.add(path.parent)
    roots.sort(key=lambda path: (len(path.relative_to(repo_path).parts), path.as_posix()))
    return roots


def _score_candidate(kind: WebAppKind, relative: str) -> int:
    lowered = relative.lower()
    score = 10
    if kind.language == "node" and kind.framework in {"express", "koa", "fastify", "@nestjs/core", "nestjs"}:
        score += 20
    if kind.language in {"python", "go"}:
        score += 18
    if any(token in lowered for token in ("backend", "server", "api", "service", "app")):
        score += 8
    if any(token in lowered for token in ("client", "frontend", "web", "ui")):
        score += 4
    if kind.entry_point:
        score += 4
    return score


def has_docker_setup(repo_path: Path) -> dict[str, Any]:
    dockerfile = repo_path / "Dockerfile"
    compose_candidates = [
        repo_path / "compose.yml",
        repo_path / "compose.yaml",
        repo_path / "docker-compose.yml",
        repo_path / "docker-compose.yaml",
    ]
    compose = next((p for p in compose_candidates if p.exists()), None)
    return {
        "dockerfile_path": str(dockerfile) if dockerfile.exists() else None,
        "compose_path": str(compose) if compose else None,
    }


def _detect_node(repo_path: Path, package_json: Path) -> WebAppKind | None:
    try:
        manifest = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    deps = {**(manifest.get("dependencies") or {}), **(manifest.get("devDependencies") or {})}
    framework = next((f for f in NODE_FRAMEWORKS if f in deps), None)
    scripts = manifest.get("scripts") or {}
    start_script = scripts.get("start")
    if not framework and not (start_script and any(token in start_script for token in ("node", "next", "nuxt", "nest"))):
        return None
    entry_candidates = (
        "server.js",
        "app.js",
        "index.js",
        "src/index.js",
        "src/server.js",
        "src/main.js",
    )
    entry = next((c for c in entry_candidates if (repo_path / c).exists()), None)
    manifest_files = ["package.json"]
    if (repo_path / "package-lock.json").exists():
        manifest_files.append("package-lock.json")
    if (repo_path / "yarn.lock").exists():
        manifest_files.append("yarn.lock")
    return WebAppKind(
        language="node",
        framework=framework,
        entry_point=entry,
        start_command=start_script or (f"node {entry}" if entry else None),
        port=DEFAULT_PORTS.get(framework or "", 3000),
        manifest_files=manifest_files,
    )


def _detect_python(repo_path: Path) -> WebAppKind | None:
    manifest_files: list[str] = []
    text = ""
    requirements = repo_path / "requirements.txt"
    pyproject = repo_path / "pyproject.toml"
    if requirements.exists():
        try:
            text += requirements.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        manifest_files.append("requirements.txt")
    if pyproject.exists():
        try:
            text += pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        manifest_files.append("pyproject.toml")
    lowered = text.lower()
    framework = next((f for f in PYTHON_FRAMEWORKS if f in lowered), None)
    if not framework:
        return None
    if framework == "django":
        entry_candidates = ("manage.py",)
    else:
        entry_candidates = ("app.py", "main.py", "wsgi.py", "asgi.py", "server.py", "src/app.py", "src/main.py")
    entry = next((c for c in entry_candidates if (repo_path / c).exists()), None)
    return WebAppKind(
        language="python",
        framework=framework,
        entry_point=entry,
        start_command=_python_start_command(framework, entry),
        port=DEFAULT_PORTS.get(framework, 8000),
        manifest_files=manifest_files,
    )


def _detect_go(repo_path: Path) -> WebAppKind | None:
    main = repo_path / "main.go"
    if not main.exists():
        # main.go in cmd/<name>/main.go is also fine.
        candidates = list(repo_path.glob("cmd/*/main.go"))
        if not candidates:
            return None
        main = candidates[0]
    try:
        text = main.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lowered = text.lower()
    if "net/http" not in lowered and not any(framework_token(f) in lowered for f in GO_FRAMEWORKS):
        return None
    framework = next((f for f in GO_FRAMEWORKS if framework_token(f) in lowered), None) or "net/http"
    manifest_files = ["go.mod"]
    if (repo_path / "go.sum").exists():
        manifest_files.append("go.sum")
    return WebAppKind(
        language="go",
        framework=framework,
        entry_point=str(main.relative_to(repo_path)),
        start_command="./app",
        port=DEFAULT_PORTS.get(framework, 8080),
        manifest_files=manifest_files,
    )


def framework_token(framework: str) -> str:
    # Match against the dotted import path's tail (e.g. "github.com/gin-gonic/gin").
    return framework.lower()


def _python_start_command(framework: str, entry: str | None) -> str:
    if framework == "django":
        return "python manage.py runserver 0.0.0.0:8000"
    if framework == "flask":
        module = (entry or "app").replace(".py", "").replace("/", ".")
        return f"flask --app {module} run --host=0.0.0.0 --port=8000"
    if framework == "fastapi" or framework == "starlette":
        module = (entry or "main").replace(".py", "").replace("/", ".")
        return f"uvicorn {module}:app --host 0.0.0.0 --port 8000"
    if framework == "sanic":
        module = (entry or "app").replace(".py", "").replace("/", ".")
        return f"python -m sanic {module}:app --host 0.0.0.0 --port 8000"
    return f"python {entry or 'app.py'}"
