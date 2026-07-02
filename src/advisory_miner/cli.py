from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .agents.advisory_parser import AdvisoryParser
from .agents.critic import EvidenceCritic
from .agents.fix_verifier import FixVerifier
from .agents.introducer_classifier import IntroducerClassifier
from .agents.investigator import Investigator
from .agents.orchestrator import AdvisoryAnalyzer, analyze_parallel, load_collected, write_analysis
from .agents.model_reviewer import ModelReviewer
from .config import load_config
from .collector import collect_by_advisory_id, collect_by_url, collect_latest, date_range, write_collected
from .eval import evaluate, load_json_list, render_report
from .github_client import GitHubClient
from .langfuse_tracing import build_langfuse_tracer
from .openai_client import OpenAIClient
from .persistence import SQLiteStore, make_run_id
from .runtime import RateBudget, ResponseCache
from .tools.git_tools import GitTools
from .tools.github_tools import GitHubTools


SEVERITIES = ("critical", "high", "medium", "low")


def build_collect_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect normalized data from the GitHub Advisory Database.")
    parser.add_argument("--advisory", action="append", default=[], help="GHSA ID to collect. Can be repeated.")
    parser.add_argument("--url", action="append", default=[], help="GitHub advisory URL to collect. Can be repeated.")
    parser.add_argument("--limit", type=int, default=20, help="Number of latest advisories to collect. Default: 20")
    parser.add_argument("--severity", choices=SEVERITIES, default="critical", help="Severity for latest advisories.")
    parser.add_argument("--published-since", help="Filter advisories published on or after this date/time.")
    parser.add_argument("--published-until", help="Filter advisories published on or before this date/time.")
    parser.add_argument("--updated-since", help="Filter advisories updated on or after this date/time.")
    parser.add_argument("--updated-until", help="Filter advisories updated on or before this date/time.")
    parser.add_argument("--output", default="results/advisories.json", help="JSON output path.")
    parser.add_argument("--no-raw", action="store_true", help="Do not include the raw GitHub API response.")
    parser.add_argument("--no-enrich", action="store_true", help="Skip OSV + NVD enrichment (faster, less evidence).")
    parser.add_argument("--allow-unauthenticated", action="store_true", help="Allow unauthenticated GitHub API calls.")
    return parser


def build_analyze_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze collected advisories for fixing and introducing commits/PRs.")
    parser.add_argument("--input", required=True, help="Collector JSON input path.")
    parser.add_argument("--output", default="results/analyzed.json", help="Analysis JSON output path.")
    parser.add_argument("--workers", type=int, default=None, help="Parallel advisory workers.")
    parser.add_argument("--cache-dir", default=None, help="Local git repository cache directory.")
    parser.add_argument("--skip-git", action="store_true", help="Skip local clone/diff/blame introducer analysis.")
    parser.add_argument("--no-cache", action="store_true", help="Disable GitHub + OpenAI response caches.")
    parser.add_argument("--no-resume", action="store_true", help="Disable resumable run; re-analyze advisories present in --output.")
    parser.add_argument("--no-progress", action="store_true", help="Suppress per-advisory progress output.")
    parser.add_argument("--github-rate-budget", type=int, default=4500, help="Per-hour GitHub REST budget (default 4500).")
    parser.add_argument("--cache-root", default=".cache", help="Root directory for response caches (default .cache).")
    parser.add_argument("--cost-cap-usd", type=float, default=None, help="Optional per-advisory OpenAI cost cap in USD.")
    parser.add_argument("--db-path", default=None, help="SQLite DB path for durable run/results persistence.")
    parser.add_argument("--allow-unauthenticated", action="store_true", help="Allow unauthenticated GitHub API calls.")
    return parser


def build_eval_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate analysis output against ground-truth labels.")
    parser.add_argument("--labels", required=True, help="Path to labels JSON (train set).")
    parser.add_argument("--holdout", default=None, help="Optional path to a holdout labels JSON for end-of-phase scoring.")
    parser.add_argument("--analysis", required=True, help="Path to analysis JSON.")
    parser.add_argument("--report", default=None, help="Optional JSON report output path.")
    return parser


def build_dockerize_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate or validate Docker setup for a repository.")
    parser.add_argument("--repo", required=True, help="owner/repo to clone (or local path with --local).")
    parser.add_argument("--local", action="store_true", help="Treat --repo as a local path instead of cloning.")
    parser.add_argument("--cache-dir", default=None, help="Local git repository cache directory (for --repo owner/repo).")
    parser.add_argument("--max-retries", type=int, default=3, help="Max regeneration retries when validation fails.")
    parser.add_argument("--force", action="store_true", help="Regenerate Docker assets even if existing ones are found.")
    parser.add_argument("--skip-runtime", action="store_true", help="Skip docker subprocess calls (generation only).")
    parser.add_argument("--output", default=None, help="Optional JSON path to write the dockerization outcome.")
    return parser


def build_temporal_worker_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a Temporal worker for advisory analysis workflows.")
    parser.add_argument("--address", default="localhost:7233")
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--task-queue", default="advisory-miner")
    return parser


def build_temporal_submit_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Submit advisory collection and analysis to Temporal.")
    parser.add_argument("--input", default=None, help="Optional pre-collected JSON input. If omitted, collection runs inside Temporal.")
    parser.add_argument("--advisory", action="append", default=[], help="GHSA ID to collect in the Temporal workflow. Can be repeated.")
    parser.add_argument("--url", action="append", default=[], help="GitHub advisory URL to collect in the Temporal workflow. Can be repeated.")
    parser.add_argument("--limit", type=int, default=20, help="Number of latest advisories to collect when no advisory/url is provided.")
    parser.add_argument("--severity", choices=SEVERITIES, default="critical", help="Severity for latest advisories.")
    parser.add_argument("--published-since")
    parser.add_argument("--published-until")
    parser.add_argument("--updated-since")
    parser.add_argument("--updated-until")
    parser.add_argument("--no-raw", action="store_true", help="Do not include raw GitHub API response in collected advisories.")
    parser.add_argument("--no-enrich", action="store_true", help="Skip OSV + NVD enrichment during Temporal collection.")
    parser.add_argument("--allow-unauthenticated", action="store_true", help="Allow unauthenticated GitHub collection.")
    parser.add_argument("--address", default="localhost:7233")
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--task-queue", default="advisory-miner")
    parser.add_argument("--skip-git", action="store_true")
    parser.add_argument("--cache-root", default=".cache")
    parser.add_argument("--cache-dir", default=None)
    parser.add_argument("--github-rate-budget", type=int, default=4500)
    parser.add_argument("--timeout-minutes", type=int, default=30)
    parser.add_argument("--collect-timeout-minutes", type=int, default=10)
    return parser


def build_dashboard_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local Advisory Miner dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--cache-root", default=".cache")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["analyze"]:
        return _main_analyze(argv[1:])
    if argv[:1] == ["eval"]:
        return _main_eval(argv[1:])
    if argv[:1] == ["dockerize"]:
        return _main_dockerize(argv[1:])
    if argv[:1] == ["temporal-worker"]:
        return _main_temporal_worker(argv[1:])
    if argv[:1] == ["temporal-submit"]:
        return _main_temporal_submit(argv[1:])
    if argv[:1] == ["db-init"]:
        return _main_db_init(argv[1:])
    if argv[:1] == ["dashboard"]:
        return _main_dashboard(argv[1:])
    argv = _normalize_collect_argv(argv)
    parser = build_collect_parser()
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN")
    if not token and not args.allow_unauthenticated:
        parser.error("GITHUB_TOKEN is required unless --allow-unauthenticated is set")

    client = GitHubClient(token=token)
    try:
        advisories = _collect(client, args)
    except Exception as exc:
        print(f"failed to collect advisories: {exc}", file=sys.stderr)
        return 1

    if not advisories:
        print("no advisories found", file=sys.stderr)
        return 1

    write_collected(Path(args.output), advisories)
    print(f"collected {len(advisories)} advisories -> {args.output}", file=sys.stderr)
    return 0


def _main_analyze(argv: list[str]) -> int:
    parser = build_analyze_parser()
    args = parser.parse_args(argv)
    config = load_config()
    if not config.github_token and not args.allow_unauthenticated:
        parser.error("GITHUB_TOKEN is required unless --allow-unauthenticated is set")
    cache_root = Path(args.cache_root)
    github_cache = None if args.no_cache else ResponseCache(cache_root, "github")
    openai_cache = None if args.no_cache else ResponseCache(cache_root, "openai")
    budget = RateBudget(per_hour=max(1, args.github_rate_budget))
    run_id = make_run_id("analyze")
    session_id = os.environ.get("LANGFUSE_SESSION_ID") or f"advisory-miner:{run_id}"
    langfuse_tracer = build_langfuse_tracer(session_id=session_id)

    client = GitHubClient(token=config.github_token, cache=github_cache, budget=budget)
    cache_dir = Path(args.cache_dir) if args.cache_dir else config.repo_cache_dir
    advisories = load_collected(Path(args.input))
    store = None
    db_path = Path(args.db_path) if args.db_path else config.db_path
    if config.database_url:
        from .storage import PostgresStore

        store = PostgresStore(config.database_url)
    elif db_path is not None:
        store = SQLiteStore(db_path)
    if store is not None:
        store.start_run(
            run_id,
            args.input,
            args.output,
            {
                "workers": args.workers,
                "skip_git": args.skip_git,
                "github_rate_budget": args.github_rate_budget,
                "cost_cap_usd": args.cost_cap_usd or config.per_advisory_cost_cap_usd,
                "langfuse_session_id": session_id,
                "agentic_mode": True,
            },
        )
        for advisory in advisories:
            store.upsert_advisory(advisory)
    github_tools = GitHubTools(client)
    git_tools = GitTools(cache_dir)
    if not config.openai_api_key:
        parser.error("OPENAI_API_KEY is required for analysis (LLM verification is mandatory). Set it in .env or the environment.")
    reviewer = ModelReviewer(
        OpenAIClient(config.openai_api_key, config.openai_validator_model, cache=openai_cache, tracer=langfuse_tracer)
    )
    critic = EvidenceCritic(
        OpenAIClient(config.openai_api_key, config.openai_validator_model, cache=openai_cache, tracer=langfuse_tracer)
    )
    investigator = Investigator(
        OpenAIClient(config.openai_api_key, config.openai_model, cache=openai_cache, tracer=langfuse_tracer),
        github_tools,
        git_tools=None if args.skip_git else git_tools,
    )
    advisory_parser = AdvisoryParser(
        OpenAIClient(config.openai_api_key, config.openai_model, cache=openai_cache, tracer=langfuse_tracer)
    )
    fix_verifier = FixVerifier(
        OpenAIClient(config.openai_api_key, config.openai_model, cache=openai_cache, tracer=langfuse_tracer),
        github_tools,
    )
    introducer_classifier = IntroducerClassifier(
        OpenAIClient(config.openai_api_key, config.openai_model, cache=openai_cache, tracer=langfuse_tracer),
        github_tools,
        git_tools,
    )
    analyzer = AdvisoryAnalyzer(
        github_tools,
        git_tools,
        reviewer=reviewer,
        critic=critic,
        investigator=investigator,
        parser=advisory_parser,
        fix_verifier=fix_verifier,
        introducer_classifier=introducer_classifier,
        per_advisory_cost_cap_usd=args.cost_cap_usd or config.per_advisory_cost_cap_usd,
        tracer=langfuse_tracer,
    )
    from .agents.langgraph_workflow import LangGraphAnalyzer
    analyzer = LangGraphAnalyzer(analyzer)
    output_path = Path(args.output)
    workers = args.workers if args.workers is not None else min(config.agent_workers, max(1, len(advisories)))
    results = analyze_parallel(
        advisories,
        analyzer,
        workers=workers,
        skip_git=args.skip_git,
        output_path=output_path,
        resume=not args.no_resume,
        progress=not args.no_progress,
        store=store,
        run_id=run_id,
    )
    if langfuse_tracer is not None:
        langfuse_tracer.flush()
    if store is not None:
        store.complete_run(run_id, "completed")
        store.close()
    print(f"analyzed {len(results)} new advisories -> {args.output}", file=sys.stderr)
    return 0


def _main_db_init(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Initialize advisory-miner persistence schema.")
    parser.add_argument("--database-url", default=None, help="Postgres URL. Defaults to ADVISORY_MINER_DATABASE_URL.")
    parser.add_argument("--sqlite-path", default=None, help="SQLite fallback path.")
    args = parser.parse_args(argv)
    database_url = args.database_url or os.environ.get("ADVISORY_MINER_DATABASE_URL")
    if database_url:
        from .storage import PostgresStore

        store = PostgresStore(database_url)
        store.close()
        print("Postgres schema initialized", file=sys.stderr)
        return 0
    path = Path(args.sqlite_path or os.environ.get("ADVISORY_MINER_DB", ".cache/advisory_miner.sqlite3"))
    store = SQLiteStore(path)
    store.close()
    print(f"SQLite schema initialized at {path}", file=sys.stderr)
    return 0


def _main_dashboard(argv: list[str]) -> int:
    from .dashboard import serve_dashboard

    parser = build_dashboard_parser()
    args = parser.parse_args(argv)
    serve_dashboard(args.host, args.port, Path(args.results_dir), Path(args.cache_root))
    return 0


def _main_eval(argv: list[str]) -> int:
    parser = build_eval_parser()
    args = parser.parse_args(argv)
    labels = load_json_list(Path(args.labels))
    analysis = load_json_list(Path(args.analysis))
    report = evaluate(labels, analysis)
    print("=== TRAIN ===")
    print(render_report(report))
    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        print(f"eval report written -> {args.report}", file=sys.stderr)
    if args.holdout:
        holdout_labels = load_json_list(Path(args.holdout))
        holdout_report = evaluate(holdout_labels, analysis)
        print()
        print("=== HOLDOUT ===")
        print(render_report(holdout_report))
        if args.report:
            holdout_path = Path(args.report).with_name(Path(args.report).stem + "_holdout.json")
            holdout_path.write_text(json.dumps(holdout_report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
            print(f"holdout report written -> {holdout_path}", file=sys.stderr)
    return 0


def _main_dockerize(argv: list[str]) -> int:
    from .dockerize import dockerize_repo

    parser = build_dockerize_parser()
    args = parser.parse_args(argv)
    config = load_config()

    if args.local:
        repo_path = Path(args.repo).resolve()
        if not repo_path.exists():
            parser.error(f"local repo path does not exist: {repo_path}")
    else:
        if "/" not in args.repo:
            parser.error("--repo must be in owner/repo form (or use --local for a local path)")
        owner, repo = args.repo.split("/", 1)
        cache_dir = Path(args.cache_dir) if args.cache_dir else config.repo_cache_dir
        client = GitHubClient(token=config.github_token)
        github_tools = GitHubTools(client)  # noqa: F841 - constructed for symmetry / future use
        git = GitTools(cache_dir)
        try:
            repo_path = git.ensure_repo(owner, repo)
        except Exception as exc:
            print(f"failed to ensure repo {owner}/{repo}: {exc}", file=sys.stderr)
            return 1
        try:
            git._git(["checkout", "HEAD", "--", "."], repo_path, 120)  # noqa: SLF001 - tolerated for dockerize prep
        except Exception:
            pass

    openai_client = None
    if config.openai_api_key:
        openai_client = OpenAIClient(config.openai_api_key, config.openai_model, tracer=build_langfuse_tracer())

    outcome = dockerize_repo(
        repo_path,
        openai_client,
        max_retries=args.max_retries,
        force_generate=args.force,
        skip_runtime=args.skip_runtime,
    )
    if openai_client is not None and openai_client.tracer is not None:
        openai_client.tracer.flush()

    print(json.dumps(outcome, indent=2, default=str))
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(outcome, indent=2, default=str), encoding="utf-8")
    return 0 if outcome.get("success") else 1


def _main_temporal_worker(argv: list[str]) -> int:
    import asyncio

    from .temporal_app import run_worker

    parser = build_temporal_worker_parser()
    args = parser.parse_args(argv)
    try:
        asyncio.run(run_worker(args.address, args.namespace, args.task_queue))
    except RuntimeError as exc:
        parser.error(str(exc))
    return 0


def _main_temporal_submit(argv: list[str]) -> int:
    import asyncio

    from .temporal_app import submit_batch, submit_collection

    parser = build_temporal_submit_parser()
    args = parser.parse_args(argv)
    try:
        if args.input:
            advisories = load_collected(Path(args.input))
            workflow_id = asyncio.run(
                submit_batch(args.address, args.namespace, args.task_queue, advisories, skip_git=args.skip_git)
            )
        else:
            workflow_id = asyncio.run(
                submit_collection(
                    args.address,
                    args.namespace,
                    args.task_queue,
                    _collect_payload_from_args(args),
                    skip_git=args.skip_git,
                    cache_root=args.cache_root,
                    cache_dir=args.cache_dir,
                    github_rate_budget=args.github_rate_budget,
                    timeout_minutes=args.timeout_minutes,
                    collect_timeout_minutes=args.collect_timeout_minutes,
                )
            )
    except RuntimeError as exc:
        parser.error(str(exc))
    print(workflow_id)
    return 0


def _normalize_collect_argv(argv: list[str]) -> list[str]:
    if argv[:1] == ["collect"]:
        return argv[1:]
    return argv


def _collect_payload_from_args(args: argparse.Namespace) -> dict[str, object]:
    return {
        "advisory": args.advisory,
        "url": args.url,
        "limit": args.limit,
        "severity": args.severity,
        "published_since": args.published_since,
        "published_until": args.published_until,
        "updated_since": args.updated_since,
        "updated_until": args.updated_until,
        "no_raw": args.no_raw,
        "no_enrich": args.no_enrich,
        "allow_unauthenticated": args.allow_unauthenticated,
    }


def _collect(client: GitHubClient, args: argparse.Namespace):
    include_raw = not args.no_raw
    enrich = not args.no_enrich
    collected = []
    for ghsa_id in args.advisory:
        collected.append(collect_by_advisory_id(client, ghsa_id, include_raw=include_raw, enrich=enrich))
    for url in args.url:
        collected.append(collect_by_url(client, url, include_raw=include_raw, enrich=enrich))
    if collected:
        return collected
    return collect_latest(
        client,
        limit=args.limit,
        severity=args.severity,
        published=date_range(args.published_since, args.published_until),
        updated=date_range(args.updated_since, args.updated_until),
        include_raw=include_raw,
        enrich=enrich,
    )
