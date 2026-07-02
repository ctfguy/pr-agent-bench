"""Validate-or-generate-and-validate Docker setups inside a cloned repo.

Pipeline:
  1. detect(repo_path) → WebAppKind or None (None means we won't try).
  2. If a Dockerfile / compose file already exists, validate it via
     ``docker compose config`` and stop.
  3. Otherwise, ask the LLM to generate Dockerfile + .dockerignore +
     compose.yml. Write them, then validate via config → build → up
     → HTTP probe. On any failure, feed the logs back to the LLM and
     retry, bounded by ``max_retries``.
  4. Always ``docker compose down -v`` before returning to avoid leaving
     containers running.

Returns a dict suitable for embedding under ``AnalysisResult.dockerization``.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from advisory_miner.openai_client import OpenAIClient

from .detect import WebAppKind, has_docker_setup
from .generator import generate_files
from .selector import select_web_app


GENERATED_FILES = ("Dockerfile", ".dockerignore", "compose.yml")


def dockerize_repo(
    repo_path: Path,
    client: OpenAIClient | None,
    max_retries: int = 3,
    force_generate: bool = False,
    skip_runtime: bool = False,
) -> dict[str, Any]:
    """Top-level entry point. ``skip_runtime`` short-circuits docker subprocess
    calls (used in tests when docker isn't available)."""
    if not repo_path.exists():
        return _outcome(False, reason="repo path does not exist")

    root_existing = has_docker_setup(repo_path)
    detection = select_web_app(client, repo_path)
    if detection is None:
        if (root_existing["dockerfile_path"] or root_existing["compose_path"]) and not force_generate:
            return _validate_existing(repo_path, None, root_existing, skip_runtime=skip_runtime)
        return _outcome(False, attempted=False, reason="not a recognized web app")

    app_path = repo_path / detection.root_path
    if (root_existing["dockerfile_path"] or root_existing["compose_path"]) and not force_generate:
        return _validate_existing(repo_path, detection, root_existing, skip_runtime=skip_runtime)

    existing = has_docker_setup(app_path)
    if (existing["dockerfile_path"] or existing["compose_path"]) and not force_generate:
        return _validate_existing(app_path, detection, existing, skip_runtime=skip_runtime)

    if client is None:
        return _outcome(False, attempted=False, kind=detection, reason="OpenAI client not configured")

    return _generate_and_validate(app_path, client, detection, max_retries, skip_runtime=skip_runtime)


def _validate_existing(
    repo_path: Path,
    kind: WebAppKind | None,
    existing: dict[str, Any],
    skip_runtime: bool,
) -> dict[str, Any]:
    evidence = []
    if existing["dockerfile_path"]:
        evidence.append(f"Dockerfile present at {existing['dockerfile_path']}")
    if existing["compose_path"]:
        evidence.append(f"Compose file present at {existing['compose_path']}")

    if skip_runtime:
        return _outcome(True, attempted=True, kind=kind, mode="validate_existing", evidence=evidence)

    if not _docker_available():
        evidence.append("docker CLI not available; skipping config check")
        return _outcome(True, attempted=True, kind=kind, mode="validate_existing", evidence=evidence)

    if existing["compose_path"]:
        ok, log = _run_cmd(["docker", "compose", "config"], repo_path, timeout=60)
        evidence.append(f"docker compose config: {'ok' if ok else 'failed'}")
        return _outcome(ok, attempted=True, kind=kind, mode="validate_existing", evidence=evidence, logs_excerpt=log[-1500:])

    return _outcome(True, attempted=True, kind=kind, mode="validate_existing", evidence=evidence)


def _generate_and_validate(
    repo_path: Path,
    client: OpenAIClient,
    kind: WebAppKind,
    max_retries: int,
    skip_runtime: bool,
) -> dict[str, Any]:
    backups = _backup_existing(repo_path)
    feedback: str | None = None
    attempt_log: list[dict[str, Any]] = []
    files_written: list[str] = []

    try:
        for attempt in range(max_retries + 1):
            try:
                dockerfile, dockerignore, compose_yml = generate_files(
                    client, repo_path, kind, feedback=feedback
                )
            except Exception as exc:
                attempt_log.append({"attempt": attempt, "stage": "generate", "ok": False, "log": str(exc)[:500]})
                feedback = f"Previous generation crashed: {exc}"
                continue

            files_written = _write_files(repo_path, dockerfile, dockerignore, compose_yml)

            if skip_runtime or not _docker_available():
                # Without docker we can't truly validate; mark as generated only.
                evidence = ["generated without runtime validation (docker CLI unavailable or skipped)"]
                return _outcome(
                    False,
                    attempted=True,
                    kind=kind,
                    mode="generated",
                    files_written=files_written,
                    retries=attempt,
                    evidence=evidence,
                )

            ok, summary, logs = _run_validation_pipeline(repo_path, kind.port)
            attempt_log.append({"attempt": attempt, "stage": "pipeline", "ok": ok, "summary": summary, "log": logs[-1500:]})
            if ok:
                return _outcome(
                    True,
                    attempted=True,
                    kind=kind,
                    mode="generated",
                    files_written=files_written,
                    retries=attempt,
                    evidence=summary,
                )
            feedback = "Previous attempt failed:\n" + "\n".join(summary) + "\n\nLogs (tail):\n" + logs[-3000:]
        return _outcome(
            False,
            attempted=True,
            kind=kind,
            mode="generated",
            files_written=files_written,
            retries=max_retries,
            attempt_log=attempt_log,
        )
    finally:
        _restore_backups(repo_path, backups)


def _run_validation_pipeline(repo_path: Path, port: int) -> tuple[bool, list[str], str]:
    summary: list[str] = []
    full_log = ""

    ok, log = _run_cmd(["docker", "compose", "config"], repo_path, timeout=60)
    full_log += "\n=== compose config ===\n" + log
    if not ok:
        summary.append("docker compose config: failed")
        return False, summary, full_log
    summary.append("docker compose config: ok")

    ok, log = _run_cmd(["docker", "compose", "build"], repo_path, timeout=600)
    full_log += "\n=== compose build ===\n" + log
    if not ok:
        summary.append("docker compose build: failed")
        return False, summary, full_log
    summary.append("docker compose build: ok")

    ok, log = _run_cmd(["docker", "compose", "up", "-d", "--wait"], repo_path, timeout=300)
    full_log += "\n=== compose up ===\n" + log
    if not ok:
        summary.append("docker compose up: failed")
        _run_cmd(["docker", "compose", "logs", "--tail=200"], repo_path, timeout=60)
        _run_cmd(["docker", "compose", "down", "-v"], repo_path, timeout=60)
        return False, summary, full_log
    summary.append("docker compose up: ok")

    try:
        probe_ok = _http_probe("127.0.0.1", port, timeout=30)
        if probe_ok:
            summary.append(f"HTTP probe on port {port}: ok")
        else:
            summary.append(f"HTTP probe on port {port}: failed")
        return probe_ok, summary, full_log
    finally:
        _run_cmd(["docker", "compose", "down", "-v"], repo_path, timeout=60)


def _backup_existing(repo_path: Path) -> dict[str, Path | None]:
    backups: dict[str, Path | None] = {}
    for relative in GENERATED_FILES:
        path = repo_path / relative
        if path.exists():
            backup = path.with_suffix(path.suffix + ".advisory_miner_backup")
            shutil.copy2(path, backup)
            backups[relative] = backup
        else:
            backups[relative] = None
    return backups


def _restore_backups(repo_path: Path, backups: dict[str, Path | None]) -> None:
    for relative, backup in backups.items():
        path = repo_path / relative
        if backup is None:
            if path.exists():
                path.unlink()
        else:
            shutil.move(str(backup), str(path))


def _write_files(repo_path: Path, dockerfile: str, dockerignore: str, compose_yml: str) -> list[str]:
    targets = (
        ("Dockerfile", dockerfile),
        (".dockerignore", dockerignore),
        ("compose.yml", compose_yml),
    )
    written: list[str] = []
    for relative, content in targets:
        path = repo_path / relative
        path.write_text(content, encoding="utf-8")
        written.append(relative)
    return written


def _run_cmd(args: list[str], cwd: Path, timeout: int = 120) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            args, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode == 0, (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        return False, f"timed out after {timeout}s: {exc.stdout or ''}\n{exc.stderr or ''}"
    except FileNotFoundError as exc:
        return False, f"command not found: {exc}"


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _http_probe(host: str, port: int, timeout: int = 30) -> bool:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://{host}:{port}/", timeout=3) as response:
                return response.status < 500
        except urllib.error.HTTPError as exc:
            return exc.code < 500
        except (urllib.error.URLError, ConnectionError) as exc:
            last_error = str(exc)
            time.sleep(1)
    return False


def _outcome(
    success: bool,
    attempted: bool = True,
    kind: WebAppKind | None = None,
    mode: str | None = None,
    evidence: list[str] | None = None,
    files_written: list[str] | None = None,
    retries: int | None = None,
    reason: str | None = None,
    attempt_log: list[dict[str, Any]] | None = None,
    logs_excerpt: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempted": attempted,
        "success": success,
        "kind": kind.to_dict() if kind else None,
        "mode": mode,
        "evidence": evidence or [],
        "files_written": files_written or [],
        "retries": retries,
        "reason": reason,
    }
    if attempt_log:
        payload["attempt_log"] = attempt_log
    if logs_excerpt:
        payload["logs_excerpt"] = logs_excerpt
    return payload
