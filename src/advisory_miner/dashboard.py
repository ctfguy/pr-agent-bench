from __future__ import annotations

import json
import os
import random
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from advisory_miner.agents.advisory_parser import AdvisoryParser
from advisory_miner.agents.critic import EvidenceCritic
from advisory_miner.agents.fix_verifier import FixVerifier
from advisory_miner.agents.introducer_classifier import IntroducerClassifier
from advisory_miner.agents.investigator import Investigator
from advisory_miner.agents.model_reviewer import ModelReviewer
from advisory_miner.agents.orchestrator import AdvisoryAnalyzer
from advisory_miner.collector import collect_by_advisory_id, collect_by_url, collect_latest, date_range
from advisory_miner.config import load_config
from advisory_miner.github_client import GitHubClient
from advisory_miner.langfuse_tracing import build_langfuse_tracer
from advisory_miner.openai_client import OpenAIClient
from advisory_miner.persistence import make_run_id
from advisory_miner.runtime import RateBudget, ResponseCache
from advisory_miner.tools.git_tools import GitTools
from advisory_miner.tools.github_tools import GitHubTools


SEVERITIES = {"critical", "high", "medium", "low"}
DONE_STATES = {"completed", "failed"}


class DashboardState:
    def __init__(self, results_dir: Path, cache_root: Path):
        self.results_dir = results_dir
        self.cache_root = cache_root
        self.dashboard_dir = cache_root / "dashboard"
        self.archive_path = self.dashboard_dir / "archive.json"
        self.jobs: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.dashboard_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.archive: list[dict[str, Any]] = self._load_archive()

    def create_job(self, request: dict[str, Any]) -> dict[str, Any]:
        if not request.get("force_rescan"):
            cached = self._cached_job_for_request(request)
            if cached is not None:
                return cached
        run_id = make_run_id("dashboard")
        job = {
            "id": run_id,
            "created_at": time.time(),
            "updated_at": time.time(),
            "state": "queued",
            "request": request,
            "progress": {"total": 0, "completed": 0, "failed": 0, "percent": 0},
            "advisories": [],
            "errors": [],
            "output_path": str(self.results_dir / f"{run_id}_analyzed.json"),
            "collected_path": str(self.results_dir / f"{run_id}_collected.json"),
        }
        with self.lock:
            self.jobs[run_id] = job
        thread = threading.Thread(target=self._run_job, args=(run_id,), daemon=True)
        thread.start()
        return job

    def _cached_job_for_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        requested = set(request.get("advisory_ids") or [])
        if request.get("urls") or not requested:
            return None
        with self.lock:
            for archived in self.archive:
                if archived.get("state") != "completed":
                    continue
                advisories = archived.get("advisories") or []
                found = {item.get("ghsa_id") for item in advisories if item.get("state") == "completed"}
                if requested and requested.issubset(found):
                    cached = _copy_json(archived)
                    cached["cache_hit"] = True
                    return cached
        return None

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.lock:
            job = self.jobs.get(job_id)
            if job:
                return _copy_json(job)
            for item in self.archive:
                if item.get("id") == job_id:
                    return _copy_json(item)
        return None

    def list_jobs(self) -> dict[str, Any]:
        with self.lock:
            active = [_copy_json(job) for job in self.jobs.values()]
            archive = [_archive_summary(item) for item in self.archive]
        active.sort(key=lambda item: item.get("created_at", 0), reverse=True)
        archive.sort(key=lambda item: item.get("created_at", 0), reverse=True)
        return {"active": active, "archive": archive, "advisory_archive": self.list_archived_advisories()}

    def list_archived_advisories(self) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        with self.lock:
            archive = list(self.archive)
        for job in archive:
            for index, advisory in enumerate(job.get("advisories") or []):
                ghsa_id = advisory.get("ghsa_id")
                if not ghsa_id:
                    continue
                current = unique.get(ghsa_id)
                if current and (current.get("updated_at") or 0) >= (advisory.get("updated_at") or job.get("updated_at") or 0):
                    continue
                result = advisory.get("result") or {}
                unique[ghsa_id] = {
                    "ghsa_id": ghsa_id,
                    "summary": advisory.get("summary"),
                    "severity": advisory.get("severity"),
                    "repository": advisory.get("repository") or ((result.get("repository") or {}).get("value")),
                    "state": advisory.get("state"),
                    "job_id": job.get("id"),
                    "index": index,
                    "updated_at": advisory.get("updated_at") or job.get("updated_at"),
                    "created_at": advisory.get("created_at") or job.get("created_at"),
                    "fix_commit": (result.get("fix_commit") or {}).get("value"),
                    "introduced_commit": (result.get("introduced_commit") or {}).get("value"),
                }
        rows = list(unique.values())
        rows.sort(key=lambda item: item.get("updated_at") or 0, reverse=True)
        return rows

    def _run_job(self, job_id: str) -> None:
        try:
            self._set_job(job_id, state="collecting")
            request = self.get_job(job_id)["request"]  # type: ignore[index]
            advisories = self._collect(request)
            advisory_rows = [_advisory_item(advisory) for advisory in advisories]
            self._set_job(
                job_id,
                state="analyzing",
                advisories=advisory_rows,
                progress={"total": len(advisory_rows), "completed": 0, "failed": 0, "percent": 5},
            )
            collected_path = Path(self.get_job(job_id)["collected_path"])  # type: ignore[index]
            _write_json(collected_path, advisories)
            self._analyze(job_id, advisories)
            final_job = self.get_job(job_id)
            if final_job:
                self._archive_job(final_job)
        except Exception as exc:  # noqa: BLE001
            self._append_job_error(job_id, f"{exc}", traceback.format_exc(limit=8))
            self._set_job(job_id, state="failed")
            final_job = self.get_job(job_id)
            if final_job:
                self._archive_job(final_job)

    def _collect(self, request: dict[str, Any]) -> list[dict[str, Any]]:
        config = load_config()
        if not config.github_token and not request.get("allow_unauthenticated"):
            raise RuntimeError("GITHUB_TOKEN is required unless allow unauthenticated is enabled.")
        client = GitHubClient(
            token=config.github_token,
            cache=ResponseCache(self.cache_root, "github"),
            budget=RateBudget(per_hour=int(request.get("github_rate_budget") or 4500)),
        )
        include_raw = not bool(request.get("no_raw", True))
        enrich = not bool(request.get("no_enrich", False))
        advisories = []
        for ghsa_id in request.get("advisory_ids") or []:
            if ghsa_id:
                advisories.append(collect_by_advisory_id(client, ghsa_id, include_raw=include_raw, enrich=enrich).to_dict())
        for url in request.get("urls") or []:
            if url:
                advisories.append(collect_by_url(client, url, include_raw=include_raw, enrich=enrich).to_dict())
        if not advisories:
            severity = str(request.get("severity") or "critical").lower()
            if severity not in SEVERITIES:
                raise ValueError(f"Unsupported severity: {severity}")
            limit = max(1, min(int(request.get("limit") or 5), 50))
            published_since = request.get("published_since") or None
            published_until = request.get("published_until") or None
            if request.get("random_range"):
                published_since, published_until = _random_range()
            advisories = [
                item.to_dict()
                for item in collect_latest(
                    client,
                    limit=limit,
                    severity=severity,
                    published=date_range(published_since, published_until),
                    include_raw=include_raw,
                    enrich=enrich,
                )
            ]
        if not advisories:
            raise RuntimeError("No advisories were collected.")
        unique: dict[str, dict[str, Any]] = {}
        for advisory in advisories:
            unique[advisory["ghsa_id"]] = advisory
        return list(unique.values())

    def _analyze(self, job_id: str, advisories: list[dict[str, Any]]) -> None:
        analyzer, tracer = _build_analyzer(job_id, self.cache_root)
        workers = max(1, min(int(self.get_job(job_id)["request"].get("workers") or 2), len(advisories)))  # type: ignore[index]
        results: list[dict[str, Any]] = []
        completed = 0
        failed = 0
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(analyzer.analyze, advisory, False): advisory for advisory in advisories}
            for future in as_completed(futures):
                advisory = futures[future]
                ghsa_id = advisory.get("ghsa_id") or "UNKNOWN"
                try:
                    result = future.result()
                    payload = result.to_dict()
                    state = "completed" if not result.errors else "failed"
                except Exception as exc:  # noqa: BLE001
                    payload = {"ghsa_id": ghsa_id, "errors": [str(exc)], "limitations": [], "metrics": {}}
                    state = "failed"
                results.append(payload)
                completed += 1
                failed += 1 if state == "failed" else 0
                self._update_advisory(job_id, ghsa_id, state, payload)
                percent = int((completed / max(1, len(advisories))) * 100)
                self._set_job(
                    job_id,
                    progress={"total": len(advisories), "completed": completed, "failed": failed, "percent": percent},
                )
                _write_json(Path(self.get_job(job_id)["output_path"]), sorted(results, key=lambda item: item.get("ghsa_id", "")))  # type: ignore[index]
        if tracer is not None:
            tracer.flush()
        self._set_job(job_id, state="completed" if failed == 0 else "failed")

    def _set_job(self, job_id: str, **updates: Any) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job.update(updates)
            job["updated_at"] = time.time()

    def _update_advisory(self, job_id: str, ghsa_id: str, state: str, result: dict[str, Any]) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            for item in job.get("advisories") or []:
                if item.get("ghsa_id") == ghsa_id:
                    item["state"] = state
                    item["result"] = result
                    item["updated_at"] = time.time()
                    return

    def _append_job_error(self, job_id: str, message: str, detail: str | None = None) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job.setdefault("errors", []).append({"message": message, "detail": detail, "time": time.time()})

    def _archive_job(self, job: dict[str, Any]) -> None:
        with self.lock:
            self.archive = [item for item in self.archive if item.get("id") != job.get("id")]
            self.archive.insert(0, _copy_json(job))
            self.archive = self.archive[:100]
            _write_json(self.archive_path, self.archive)

    def _load_archive(self) -> list[dict[str, Any]]:
        if not self.archive_path.exists():
            return []
        try:
            data = json.loads(self.archive_path.read_text(encoding="utf-8"))
        except Exception:
            return []
        return data if isinstance(data, list) else []


def serve_dashboard(host: str, port: int, results_dir: Path, cache_root: Path) -> None:
    state = DashboardState(results_dir=results_dir, cache_root=cache_root)

    class Handler(DashboardHandler):
        dashboard_state = state

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Dashboard: http://{host}:{port}")
    server.serve_forever()


class DashboardHandler(BaseHTTPRequestHandler):
    dashboard_state: DashboardState

    def do_HEAD(self) -> None:  # noqa: N802
        if urlparse(self.path).path in {"/", "/details", "/api/jobs", "/api/archive"} or self.path.startswith("/api/jobs/"):
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            return
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(DASHBOARD_HTML)
            return
        if parsed.path == "/details":
            self._send_html(DETAIL_HTML)
            return
        if parsed.path == "/api/jobs":
            self._send_json(self.dashboard_state.list_jobs())
            return
        if parsed.path.startswith("/api/jobs/") and "/advisories/" in parsed.path:
            parts = parsed.path.strip("/").split("/")
            if len(parts) == 5 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "advisories":
                job = self.dashboard_state.get_job(parts[2])
                if not job:
                    self._send_json({"error": "job not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                try:
                    index = int(parts[4])
                    advisory = (job.get("advisories") or [])[index]
                except Exception:
                    self._send_json({"error": "advisory not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                self._send_json({"job": _archive_summary(job), "advisory": advisory, "index": index})
                return
        if parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.rsplit("/", 1)[-1]
            job = self.dashboard_state.get_job(job_id)
            if not job:
                self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            self._send_json(job)
            return
        if parsed.path == "/api/archive":
            self._send_json({"archive": self.dashboard_state.list_archived_advisories()})
            return
        self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/api/run":
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        try:
            payload = self._read_json()
            request = _normalize_request(payload)
            job = self.dashboard_state.create_job(request)
            self._send_json(job, status=HTTPStatus.CREATED)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        return data

    def _send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _build_analyzer(run_id: str, cache_root: Path) -> tuple[Any, Any]:
    config = load_config()
    if not config.github_token:
        raise RuntimeError("GITHUB_TOKEN is required for dashboard analysis.")
    if not config.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY is required for dashboard analysis.")
    github_cache = ResponseCache(cache_root, "github")
    openai_cache = ResponseCache(cache_root, "openai")
    github = GitHubTools(GitHubClient(token=config.github_token, cache=github_cache, budget=RateBudget(per_hour=4500)))
    git = GitTools(config.repo_cache_dir)
    tracer = build_langfuse_tracer(session_id=f"advisory-miner:{run_id}")
    model_client = OpenAIClient(config.openai_api_key, config.openai_model, cache=openai_cache, tracer=tracer)
    validator_client = OpenAIClient(config.openai_api_key, config.openai_validator_model, cache=openai_cache, tracer=tracer)
    analyzer = AdvisoryAnalyzer(
        github,
        git,
        reviewer=ModelReviewer(validator_client),
        critic=EvidenceCritic(validator_client),
        investigator=Investigator(model_client, github, git),
        parser=AdvisoryParser(model_client),
        fix_verifier=FixVerifier(model_client, github),
        introducer_classifier=IntroducerClassifier(model_client, github, git),
        per_advisory_cost_cap_usd=config.per_advisory_cost_cap_usd,
        tracer=tracer,
    )
    from advisory_miner.agents.langgraph_workflow import LangGraphAnalyzer

    return LangGraphAnalyzer(analyzer), tracer


def _normalize_request(payload: dict[str, Any]) -> dict[str, Any]:
    advisory_ids = _split_lines(payload.get("advisory_ids") or payload.get("advisory_id"))
    urls = _split_lines(payload.get("urls") or payload.get("url"))
    severity = str(payload.get("severity") or "critical").lower()
    if severity not in SEVERITIES:
        severity = "critical"
    return {
        "advisory_ids": advisory_ids,
        "urls": urls,
        "severity": severity,
        "limit": max(1, min(int(payload.get("limit") or 5), 50)),
        "published_since": (payload.get("published_since") or "").strip(),
        "published_until": (payload.get("published_until") or "").strip(),
        "random_range": bool(payload.get("random_range")),
        "workers": max(1, min(int(payload.get("workers") or 2), 8)),
        "no_raw": bool(payload.get("no_raw", True)),
        "no_enrich": bool(payload.get("no_enrich", False)),
        "allow_unauthenticated": bool(payload.get("allow_unauthenticated", False)),
        "force_rescan": bool(payload.get("force_rescan", False)),
    }


def _split_lines(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        items = value
    else:
        items = str(value).replace(",", "\n").splitlines()
    return [str(item).strip() for item in items if str(item).strip()]


def _random_range() -> tuple[str, str]:
    today = date.today()
    start = today - timedelta(days=random.randint(60, 365 * 5))
    end = start + timedelta(days=random.randint(14, 75))
    if end > today:
        end = today
    return start.isoformat(), end.isoformat()


def _advisory_item(advisory: dict[str, Any]) -> dict[str, Any]:
    repo = advisory.get("repository")
    if isinstance(repo, dict):
        repo_name = repo.get("full_name") or repo.get("name")
    else:
        repo_name = repo
    return {
        "ghsa_id": advisory.get("ghsa_id"),
        "summary": advisory.get("summary"),
        "severity": advisory.get("severity"),
        "repository": repo_name,
        "html_url": advisory.get("html_url") or advisory.get("url"),
        "state": "queued",
        "created_at": time.time(),
        "updated_at": time.time(),
    }


def _archive_summary(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": job.get("id"),
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "state": job.get("state"),
        "progress": job.get("progress"),
        "request": job.get("request"),
        "advisory_count": len(job.get("advisories") or []),
        "output_path": job.get("output_path"),
    }


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    tmp.replace(path)


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Advisory Miner Dashboard</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #080b12;
      --panel: #101622;
      --panel2: #151d2b;
      --muted: #8e9bb0;
      --text: #eef4ff;
      --line: #253044;
      --accent: #7c9cff;
      --good: #37d99e;
      --bad: #ff687a;
      --warn: #ffd166;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top left, #172033 0, #080b12 36rem);
      color: var(--text);
    }
    .shell { max-width: 1360px; margin: 0 auto; padding: 28px; }
    header { display: flex; justify-content: space-between; gap: 20px; align-items: flex-start; margin-bottom: 22px; }
    h1 { margin: 0; font-size: 30px; letter-spacing: -0.04em; }
    p { color: var(--muted); line-height: 1.5; }
    .grid { display: grid; grid-template-columns: 380px 1fr; gap: 18px; align-items: start; }
    .card { background: color-mix(in srgb, var(--panel) 88%, transparent); border: 1px solid var(--line); border-radius: 20px; padding: 18px; }
    .card h2 { margin: 0 0 14px; font-size: 15px; color: #cbd6ea; text-transform: uppercase; letter-spacing: .12em; }
    .section { border: 1px solid var(--line); border-radius: 16px; padding: 14px; background: #0b111d; margin-top: 12px; }
    .section h3 { margin: 0 0 6px; font-size: 14px; }
    .or { display: grid; grid-template-columns: 1fr auto 1fr; align-items: center; gap: 10px; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .16em; margin: 12px 0; }
    .or:before, .or:after { content: ""; height: 1px; background: var(--line); display: block; }
    .hint { font-size: 12px; color: var(--muted); margin: 0 0 8px; }
    label { display: block; font-size: 12px; color: var(--muted); margin: 12px 0 6px; }
    input, textarea, select {
      width: 100%; border: 1px solid var(--line); border-radius: 12px; padding: 11px 12px;
      background: #0b101a; color: var(--text); outline: none;
    }
    textarea { min-height: 88px; resize: vertical; }
    input:focus, textarea:focus, select:focus { border-color: var(--accent); }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .check { display: flex; align-items: center; gap: 8px; color: var(--muted); margin-top: 10px; font-size: 13px; }
    .check input { width: auto; }
    button {
      border: 0; border-radius: 13px; padding: 12px 14px; background: var(--accent);
      color: #061024; font-weight: 800; cursor: pointer; margin-top: 14px; width: 100%;
    }
    button.secondary { background: #1b2537; color: var(--text); border: 1px solid var(--line); }
    .jobs { display: grid; gap: 12px; }
    .job, .advisory { background: var(--panel2); border: 1px solid var(--line); border-radius: 16px; padding: 14px; cursor: pointer; }
    .job:hover, .advisory:hover { border-color: color-mix(in srgb, var(--accent) 60%, var(--line)); }
    .topline { display: flex; justify-content: space-between; gap: 10px; align-items: center; }
    .title { font-weight: 800; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .pill { font-size: 11px; color: #cbd6ea; padding: 4px 8px; border: 1px solid var(--line); border-radius: 999px; background: #0c1220; white-space: nowrap; }
    .pill.completed { color: var(--good); border-color: color-mix(in srgb, var(--good) 40%, var(--line)); }
    .pill.failed { color: var(--bad); border-color: color-mix(in srgb, var(--bad) 40%, var(--line)); }
    .pill.analyzing, .pill.collecting { color: var(--warn); border-color: color-mix(in srgb, var(--warn) 35%, var(--line)); }
    .bar { height: 8px; background: #080d16; border-radius: 999px; overflow: hidden; margin: 12px 0 4px; border: 1px solid #1d2637; }
    .bar > div { height: 100%; background: linear-gradient(90deg, var(--accent), #66e2b3); width: 0%; transition: width .3s ease; }
    .muted { color: var(--muted); font-size: 13px; }
    .split { display: grid; grid-template-columns: 1fr; gap: 18px; margin-top: 18px; }
    pre { white-space: pre-wrap; word-break: break-word; background: #070b12; border: 1px solid var(--line); border-radius: 14px; padding: 14px; max-height: 560px; overflow: auto; }
    .findings { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-top: 12px; }
    .finding { background: #0b111d; border: 1px solid var(--line); border-radius: 14px; padding: 12px; }
    .finding b { display: block; color: #cbd6ea; margin-bottom: 6px; }
    .value { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #dce6f8; }
    .kv { display: grid; grid-template-columns: 110px 1fr; gap: 8px; padding: 6px 0; border-bottom: 1px solid #1c2638; }
    .kv:last-child { border-bottom: 0; }
    .kv span:first-child { color: var(--muted); }
    .evidence-list { display: grid; gap: 8px; margin-top: 10px; }
    .evidence { border: 1px solid var(--line); border-radius: 12px; padding: 10px; background: #090e18; }
    .evidence .source { color: var(--accent); font-size: 12px; font-weight: 800; margin-bottom: 5px; }
    details { border: 1px solid var(--line); border-radius: 12px; padding: 10px; background: #090e18; margin-top: 12px; }
    summary { cursor: pointer; color: #cbd6ea; font-weight: 700; }
    .tabs { display: flex; gap: 8px; margin-bottom: 12px; }
    .tabs button { width: auto; margin: 0; padding: 8px 10px; }
    .search { margin-bottom: 12px; }
    .hidden { display: none; }
    @media (max-width: 1000px) { .grid, .split { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <div>
        <h1>Advisory Miner</h1>
        <p>Run CVE/advisory analysis, watch progress, and inspect evidence-backed fix and introducer findings.</p>
      </div>
      <div class="muted">Temporal + Langfuse aware<br/>Archive stored locally</div>
    </header>

    <div class="grid">
      <section class="card">
        <h2>Start run</h2>
        <div class="section">
          <h3>Advisory IDs</h3>
          <p class="hint">Paste one or more GHSA IDs. Use this for exact targets.</p>
          <textarea id="advisory_ids" placeholder="GHSA-j35x-w4gj-pf7w"></textarea>
        </div>
        <div class="or">or</div>
        <div class="section">
          <h3>Advisory URLs</h3>
          <p class="hint">Paste GitHub advisory URLs. Multiple URLs are supported.</p>
          <textarea id="urls" placeholder="https://github.com/advisories/GHSA-j35x-w4gj-pf7w"></textarea>
        </div>
        <div class="or">or</div>
        <div class="section">
          <h3>Custom selector</h3>
          <p class="hint">Fetch advisories by severity and optional published date range.</p>
          <div class="row">
            <div>
              <label>Severity</label>
              <select id="severity"><option>critical</option><option>high</option><option>medium</option><option>low</option></select>
            </div>
            <div>
              <label>Limit</label>
              <input id="limit" type="number" min="1" max="50" value="5" />
            </div>
          </div>
          <div class="row">
            <div>
              <label>Published since</label>
              <input id="published_since" type="date" />
            </div>
            <div>
              <label>Published until</label>
              <input id="published_until" type="date" />
            </div>
          </div>
        </div>
        <div class="section">
          <h3>Config</h3>
          <div class="row">
            <div>
              <label>Workers</label>
              <input id="workers" type="number" min="1" max="8" value="2" />
            </div>
            <div class="check" style="align-self:end"><input id="random_range" type="checkbox" /> random range</div>
          </div>
          <div class="check"><input id="no_enrich" type="checkbox" /> skip OSV/NVD enrichment</div>
          <div class="check"><input id="force_rescan" type="checkbox" /> force rescan even if archived</div>
        </div>
        <button onclick="startRun()">Run analysis</button>
        <button class="secondary" onclick="refresh()">Refresh</button>
      </section>

      <section class="card">
        <div class="tabs">
          <button class="secondary" onclick="showTab('active')">Active</button>
          <button class="secondary" onclick="showTab('archive')">Archive</button>
        </div>
        <div id="active" class="jobs"></div>
        <div id="archivePanel" class="hidden">
          <input class="search" id="archive_search" placeholder="Search GHSA, summary, repository, commit..." oninput="renderArchive()" />
          <div id="archive" class="jobs"></div>
        </div>
      </section>
    </div>

    <div class="split">
      <section class="card">
        <h2>Advisories</h2>
        <div id="advisories" class="jobs"><p class="muted">Select a run to see advisory progress.</p></div>
      </section>
    </div>
  </div>
  <script>
    let selectedJob = null;
    let selectedTab = 'active';
    let advisoryCache = {};

    async function api(path, opts={}) {
      const res = await fetch(path, opts);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'request failed');
      return data;
    }

    function showTab(tab) {
      selectedTab = tab;
      document.getElementById('active').classList.toggle('hidden', tab !== 'active');
      document.getElementById('archivePanel').classList.toggle('hidden', tab !== 'archive');
    }

    async function startRun() {
      const payload = {
        advisory_ids: document.getElementById('advisory_ids').value,
        urls: document.getElementById('urls').value,
        severity: document.getElementById('severity').value,
        limit: Number(document.getElementById('limit').value || 5),
        workers: Number(document.getElementById('workers').value || 2),
        published_since: document.getElementById('published_since').value,
        published_until: document.getElementById('published_until').value,
        random_range: document.getElementById('random_range').checked,
        no_enrich: document.getElementById('no_enrich').checked,
        force_rescan: document.getElementById('force_rescan').checked
      };
      const job = await api('/api/run', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
      selectedJob = job.id;
      showTab(job.cache_hit ? 'archive' : 'active');
      await refresh();
    }

    async function refresh() {
      const data = await api('/api/jobs');
      renderJobs('active', data.active || []);
      window.archiveRows = data.advisory_archive || [];
      renderArchive();
      if (selectedJob) await loadJob(selectedJob);
    }

    function renderJobs(target, jobs) {
      const el = document.getElementById(target);
      if (!jobs.length) { el.innerHTML = '<p class="muted">No runs yet.</p>'; return; }
      el.innerHTML = jobs.map(job => {
        const p = job.progress || {};
        const percent = p.percent || 0;
        return `<div class="job" onclick="loadJob('${job.id}')">
          <div class="topline"><div class="title">${job.id}</div><span class="pill ${job.state}">${job.cache_hit ? 'cached' : job.state}</span></div>
          <div class="bar"><div style="width:${percent}%"></div></div>
          <div class="muted">${p.completed || 0}/${p.total || job.advisory_count || 0} done · ${new Date((job.created_at||0)*1000).toLocaleString()}</div>
        </div>`;
      }).join('');
    }

    function renderArchive() {
      const el = document.getElementById('archive');
      const query = (document.getElementById('archive_search')?.value || '').toLowerCase();
      const rows = (window.archiveRows || []).filter(item => {
        const haystack = [
          item.ghsa_id, item.summary, item.repository, item.severity,
          item.fix_commit, item.introduced_commit
        ].join(' ').toLowerCase();
        return !query || haystack.includes(query);
      });
      if (!rows.length) { el.innerHTML = '<p class="muted">No archived advisories match.</p>'; return; }
      el.innerHTML = rows.map(item => `
        <div class="advisory" onclick="openAdvisory('${item.job_id}', ${item.index})">
          <div class="topline"><div class="title">${escapeHtml(item.ghsa_id || 'unknown')}</div><span class="pill ${escapeHtml(item.state || '')}">${escapeHtml(item.state || '')}</span></div>
          <div class="muted">${escapeHtml(item.severity || '')} ${item.repository ? '· ' + escapeHtml(item.repository) : ''}</div>
          <div class="muted">${escapeHtml(item.summary || '')}</div>
          <div class="muted" style="margin-top:8px">${item.fix_commit ? 'fix ' + escapeHtml(item.fix_commit.slice(0, 12)) : 'fix unknown'} · ${item.introduced_commit ? 'intro ' + escapeHtml(item.introduced_commit.slice(0, 12)) : 'intro unknown'}</div>
        </div>
      `).join('');
    }

    async function loadJob(id) {
      selectedJob = id;
      const job = await api('/api/jobs/' + id);
      const advisories = job.advisories || [];
      const el = document.getElementById('advisories');
      el.innerHTML = advisories.length ? advisories.map((a, index) => {
        const result = a.result || {};
        const repo = a.repository || (result.repository && result.repository.value) || '';
        return `<div class="advisory" onclick="openAdvisory('${id}', ${index})">
          <div class="topline"><div class="title">${escapeHtml(a.ghsa_id || 'unknown')}</div><span class="pill ${escapeHtml(a.state || '')}">${escapeHtml(a.state || '')}</span></div>
          <div class="muted">${escapeHtml(a.severity || '')} ${repo ? '· ' + escapeHtml(repo) : ''}</div>
          <div class="muted">${escapeHtml(a.summary || '')}</div>
          <div class="muted" style="margin-top:8px">Open details →</div>
        </div>`;
      }).join('') : '<p class="muted">No advisories collected yet.</p>';
    }

    function openAdvisory(jobId, index) {
      window.open(`/details?job=${encodeURIComponent(jobId)}&index=${index}`, '_blank');
    }

    function kv(key, value) {
      return `<div class="kv"><span>${escapeHtml(key)}</span><span>${escapeHtml(value)}</span></div>`;
    }

    function shorten(text, max) {
      text = String(text || '');
      return text.length > max ? text.slice(0, max - 1) + '…' : text;
    }

    function escapeHtml(text) {
      return String(text).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[ch]));
    }

    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>"""


DETAIL_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Advisory Details</title>
  <style>
    :root { color-scheme: dark; --bg:#070b12; --panel:#101622; --panel2:#151d2b; --line:#253044; --text:#eef4ff; --muted:#91a0b8; --accent:#7c9cff; --good:#37d99e; --bad:#ff687a; --warn:#ffd166; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at top left, #172033 0, var(--bg) 36rem); color:var(--text); }
    .shell { max-width: 1280px; margin: 0 auto; padding: 30px; }
    a { color: var(--accent); text-decoration: none; }
    h1 { margin: 8px 0 8px; font-size: 30px; letter-spacing: -0.04em; }
    h2 { margin: 0 0 12px; font-size: 15px; text-transform: uppercase; letter-spacing: .12em; color:#cbd6ea; }
    h3 { margin: 0 0 8px; font-size: 15px; }
    p { color: var(--muted); line-height: 1.55; }
    .top { display:flex; justify-content:space-between; gap:20px; align-items:flex-start; margin-bottom:20px; }
    .card { background: color-mix(in srgb, var(--panel) 90%, transparent); border:1px solid var(--line); border-radius:20px; padding:18px; margin-bottom:16px; }
    .grid { display:grid; grid-template-columns: 1.1fr .9fr; gap:16px; align-items:start; }
    .findings { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:12px; }
    .finding { background:var(--panel2); border:1px solid var(--line); border-radius:16px; padding:14px; min-height:112px; }
    .finding b { display:block; color:#cbd6ea; margin-bottom:8px; }
    .value { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; overflow-wrap:anywhere; color:#e5edff; }
    .pill { display:inline-flex; font-size:11px; color:#cbd6ea; padding:4px 8px; border:1px solid var(--line); border-radius:999px; background:#0c1220; margin-top:8px; }
    .pill.high,.pill.completed { color:var(--good); border-color: color-mix(in srgb, var(--good) 40%, var(--line)); }
    .pill.medium,.pill.low { color:var(--warn); border-color: color-mix(in srgb, var(--warn) 40%, var(--line)); }
    .pill.failed { color:var(--bad); border-color: color-mix(in srgb, var(--bad) 40%, var(--line)); }
    .kv { display:grid; grid-template-columns: 150px 1fr; gap:10px; padding:8px 0; border-bottom:1px solid #1d2739; }
    .kv:last-child { border-bottom:0; }
    .kv span:first-child { color:var(--muted); }
    .evidence-grid { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:12px; }
    .evidence { border:1px solid var(--line); border-radius:14px; padding:13px; background:#0a101b; }
    .source { color:var(--accent); font-size:12px; font-weight:800; margin-bottom:6px; }
    .detail { color:#dce6f8; line-height:1.5; overflow-wrap:anywhere; }
    details { border:1px solid var(--line); border-radius:14px; padding:13px; background:#0a101b; margin-top:12px; }
    summary { cursor:pointer; font-weight:800; color:#cbd6ea; }
    pre { white-space:pre-wrap; word-break:break-word; max-height:640px; overflow:auto; background:#050910; border:1px solid var(--line); border-radius:12px; padding:14px; }
    .muted { color:var(--muted); }
    .actions { display:flex; gap:10px; flex-wrap:wrap; }
    .button { border:1px solid var(--line); background:#121b2a; color:var(--text); padding:9px 12px; border-radius:12px; cursor:pointer; }
    @media (max-width: 1000px) { .grid,.findings,.evidence-grid { grid-template-columns:1fr; } .top { flex-direction:column; } }
  </style>
</head>
<body>
  <div class="shell">
    <div class="top">
      <div>
        <a href="/">← Dashboard</a>
        <h1 id="title">Advisory details</h1>
        <p id="summary">Loading…</p>
      </div>
      <div class="actions">
        <button class="button" onclick="location.reload()">Refresh</button>
      </div>
    </div>

    <section class="card">
      <h2>Findings</h2>
      <div id="findings" class="findings"></div>
    </section>

    <div class="grid">
      <section class="card">
        <h2>Advisory</h2>
        <div id="advisory"></div>
      </section>
      <section class="card">
        <h2>Run Metrics</h2>
        <div id="metrics"></div>
      </section>
    </div>

    <section class="card">
      <h2>Evidence Highlights</h2>
      <div id="evidence" class="evidence-grid"></div>
    </section>

    <section id="notes" class="card"></section>

    <section class="card">
      <h2>Raw Data</h2>
      <details>
        <summary>Open raw JSON</summary>
        <pre id="raw"></pre>
      </details>
    </section>
  </div>
  <script>
    const params = new URLSearchParams(location.search);
    const jobId = params.get('job');
    const index = params.get('index') || '0';

    async function api(path) {
      const res = await fetch(path);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'request failed');
      return data;
    }

    async function load() {
      try {
        const data = await api(`/api/jobs/${encodeURIComponent(jobId)}/advisories/${index}`);
        render(data.advisory, data.job);
      } catch (err) {
        document.getElementById('summary').textContent = err.message;
      }
    }

    function render(item, job) {
      const r = item.result || {};
      const parsed = r.parsed_advisory || {};
      const metrics = r.metrics || {};
      document.getElementById('title').textContent = item.ghsa_id || 'Advisory details';
      document.getElementById('summary').textContent = item.summary || '';
      document.getElementById('findings').innerHTML = [
        finding('Fix commit', r.fix_commit),
        finding('Fix PR', r.fix_pr),
        finding('Introducer commit', r.introduced_commit),
        finding('Introducer PR', r.introduced_pr),
      ].join('');
      document.getElementById('advisory').innerHTML = [
        kv('Repository', (r.repository && r.repository.value) || item.repository || 'unknown'),
        kv('Severity', item.severity || 'unknown'),
        kv('State', item.state || 'unknown'),
        kv('Class', parsed.vulnerability_class || 'unknown'),
        kv('CWE', parsed.cwe_id || 'unknown'),
        kv('Endpoints', (parsed.affected_endpoints || []).join(', ') || 'unknown'),
        kv('Root cause', parsed.vulnerable_construct || 'unknown'),
        kv('Expected fix', parsed.expected_fix_behavior || 'unknown'),
        kv('Output', job.output_path || 'unknown'),
      ].join('');
      document.getElementById('metrics').innerHTML = [
        kv('Wall time', metrics.wall_clock_ms ? `${Math.round(metrics.wall_clock_ms / 1000)}s` : 'unknown'),
        kv('LLM calls', metrics.openai_calls ?? 0),
        kv('Input tokens', metrics.openai_input_tokens ?? 0),
        kv('Output tokens', metrics.openai_output_tokens ?? 0),
        kv('Tool calls', metrics.tool_calls_used ?? 0),
        kv('GitHub calls', metrics.github_calls ?? 0),
        kv('Estimated cost', metrics.estimated_openai_cost_usd ? `$${Number(metrics.estimated_openai_cost_usd).toFixed(4)}` : '$0'),
      ].join('');
      const evidence = ['fix_commit','fix_pr','introduced_commit','introduced_pr'].flatMap(key => {
        const f = r[key] || {};
        return (f.evidence || []).map(ev => ({target:key, source:ev.source || 'evidence', detail:ev.detail || ''}));
      });
      document.getElementById('evidence').innerHTML = evidence.length
        ? evidence.map(ev => `<div class="evidence"><div class="source">${escapeHtml(label(ev.target))} · ${escapeHtml(ev.source)}</div><div class="detail">${escapeHtml(ev.detail)}</div></div>`).join('')
        : '<p class="muted">No evidence recorded yet.</p>';
      const limitations = r.limitations || [];
      const errors = r.errors || [];
      document.getElementById('notes').innerHTML = `
        <h2>Notes</h2>
        ${limitations.length ? '<h3>Limitations</h3>' + limitations.map(x => `<p>${escapeHtml(x)}</p>`).join('') : '<p class="muted">No limitations recorded.</p>'}
        ${errors.length ? '<h3>Errors</h3>' + errors.map(x => `<p>${escapeHtml(x)}</p>`).join('') : ''}`;
      document.getElementById('raw').textContent = JSON.stringify(r || item, null, 2);
    }

    function finding(name, obj) {
      const value = obj && obj.value ? obj.value : 'unknown';
      const confidence = obj && obj.confidence ? obj.confidence : 'unknown';
      return `<div class="finding"><b>${escapeHtml(name)}</b><div class="value">${escapeHtml(value)}</div><span class="pill ${escapeHtml(confidence)}">${escapeHtml(confidence)}</span></div>`;
    }

    function kv(key, value) {
      return `<div class="kv"><span>${escapeHtml(key)}</span><span>${escapeHtml(String(value ?? 'unknown'))}</span></div>`;
    }

    function label(key) {
      return key.replaceAll('_', ' ');
    }

    function escapeHtml(text) {
      return String(text).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[ch]));
    }

    load();
  </script>
</body>
</html>"""
