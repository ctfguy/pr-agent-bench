"""Scoped Dockerize agent — generate Docker assets for simple Node / Python / Go web apps."""

from .detect import WebAppKind, detect, discover_candidates, has_docker_setup
from .generator import generate_files
from .runner import dockerize_repo
from .selector import select_web_app

__all__ = [
    "WebAppKind",
    "detect",
    "discover_candidates",
    "has_docker_setup",
    "generate_files",
    "dockerize_repo",
    "select_web_app",
]
