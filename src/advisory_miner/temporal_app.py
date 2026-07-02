from __future__ import annotations

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any

from temporalio import activity, workflow


def temporal_available() -> bool:
    return True


@activity.defn
def collect_advisories_activity(payload: dict[str, Any]) -> list[dict[str, Any]]:
    from advisory_miner.collector import collect_by_advisory_id, collect_by_url, collect_latest, date_range
    from advisory_miner.config import load_config
    from advisory_miner.github_client import GitHubClient
    from advisory_miner.runtime import RateBudget, ResponseCache

    config = load_config()
    collect = payload.get("collect") or {}
    if not config.github_token and not collect.get("allow_unauthenticated"):
        raise RuntimeError("GITHUB_TOKEN is required for Temporal advisory collection")

    cache_root = Path(payload.get("cache_root") or ".cache")
    client = GitHubClient(
        token=config.github_token,
        cache=ResponseCache(cache_root, "github"),
        budget=RateBudget(per_hour=int(payload.get("github_rate_budget") or 4500)),
    )
    include_raw = not bool(collect.get("no_raw"))
    enrich = not bool(collect.get("no_enrich"))
    advisories = []
    for ghsa_id in collect.get("advisory") or []:
        advisories.append(collect_by_advisory_id(client, ghsa_id, include_raw=include_raw, enrich=enrich))
    for url in collect.get("url") or []:
        advisories.append(collect_by_url(client, url, include_raw=include_raw, enrich=enrich))
    if not advisories:
        advisories = collect_latest(
            client,
            limit=int(collect.get("limit") or 20),
            severity=collect.get("severity") or "critical",
            published=date_range(collect.get("published_since"), collect.get("published_until")),
            updated=date_range(collect.get("updated_since"), collect.get("updated_until")),
            include_raw=include_raw,
            enrich=enrich,
        )
    return [advisory.to_dict() if hasattr(advisory, "to_dict") else advisory for advisory in advisories]


@activity.defn
def analyze_advisory_activity(payload: dict[str, Any]) -> dict[str, Any]:
    from advisory_miner.agents.advisory_parser import AdvisoryParser
    from advisory_miner.agents.critic import EvidenceCritic
    from advisory_miner.agents.fix_verifier import FixVerifier
    from advisory_miner.agents.introducer_classifier import IntroducerClassifier
    from advisory_miner.agents.investigator import Investigator
    from advisory_miner.agents.model_reviewer import ModelReviewer
    from advisory_miner.agents.orchestrator import AdvisoryAnalyzer
    from advisory_miner.config import load_config
    from advisory_miner.github_client import GitHubClient
    from advisory_miner.langfuse_tracing import build_langfuse_tracer
    from advisory_miner.openai_client import OpenAIClient
    from advisory_miner.runtime import RateBudget, ResponseCache
    from advisory_miner.tools.git_tools import GitTools
    from advisory_miner.tools.github_tools import GitHubTools

    config = load_config()
    if not config.github_token:
        raise RuntimeError("GITHUB_TOKEN is required for Temporal advisory analysis")
    if not config.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY is required for Temporal advisory analysis")

    cache_root = Path(payload.get("cache_root") or ".cache")
    github = GitHubTools(
        GitHubClient(
            token=config.github_token,
            cache=ResponseCache(cache_root, "github"),
            budget=RateBudget(per_hour=int(payload.get("github_rate_budget") or 4500)),
        )
    )
    git = GitTools(Path(payload.get("cache_dir") or config.repo_cache_dir))
    session_id = payload.get("session_id") or f"advisory-miner:{payload.get('run_id') or 'temporal'}"
    tracer = build_langfuse_tracer(session_id=str(session_id))
    model_client = OpenAIClient(config.openai_api_key, config.openai_model, cache=ResponseCache(cache_root, "openai"), tracer=tracer)
    validator_client = OpenAIClient(config.openai_api_key, config.openai_validator_model, cache=ResponseCache(cache_root, "openai"), tracer=tracer)
    analyzer = AdvisoryAnalyzer(
        github,
        git,
        reviewer=ModelReviewer(validator_client),
        critic=EvidenceCritic(validator_client),
        investigator=Investigator(model_client, github, None if payload.get("skip_git") else git),
        parser=AdvisoryParser(model_client),
        fix_verifier=FixVerifier(model_client, github),
        introducer_classifier=IntroducerClassifier(model_client, github, git),
        per_advisory_cost_cap_usd=config.per_advisory_cost_cap_usd,
        tracer=tracer,
    )
    try:
        result = analyzer.analyze(payload["advisory"], skip_git=bool(payload.get("skip_git")))
    finally:
        tracer.flush()
    database_url = getattr(config, "database_url", None)
    if database_url:
        from advisory_miner.storage import PostgresStore

        store = PostgresStore(database_url)
        run_id = str(payload.get("run_id") or payload.get("session_id") or "temporal")
        store.start_run(
            run_id,
            "temporal",
            "postgres",
            {
                "langfuse_session_id": session_id,
                "workflow_id": payload.get("workflow_id"),
                "agentic_mode": True,
            },
        )
        store.upsert_advisory(payload["advisory"])
        store.record_result(run_id, result)
        store.close()
    return result.to_dict()


@workflow.defn
class AdvisoryAnalysisWorkflow:
    @workflow.run
    async def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await workflow.execute_activity(
            analyze_advisory_activity,
            payload,
            start_to_close_timeout=timedelta(minutes=int(payload.get("timeout_minutes") or 30)),
        )


@workflow.defn
class AdvisoryBatchWorkflow:
    @workflow.run
    async def run(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        if payload.get("collect") is not None:
            advisories = await workflow.execute_activity(
                collect_advisories_activity,
                payload,
                start_to_close_timeout=timedelta(minutes=int(payload.get("collect_timeout_minutes") or 10)),
            )
        else:
            advisories = payload.get("advisories") or []
        parent_id = workflow.info().workflow_id
        child_payload = dict(payload)
        child_payload.pop("advisories", None)
        child_payload.pop("collect", None)
        tasks = [
            workflow.execute_child_workflow(
                AdvisoryAnalysisWorkflow.run,
                {**child_payload, "advisory": advisory, "workflow_id": f"{parent_id}-advisory-{index}-{advisory.get('ghsa_id') or 'unknown'}"},
                id=f"{parent_id}-advisory-{index}-{advisory.get('ghsa_id') or 'unknown'}",
            )
            for index, advisory in enumerate(advisories)
        ]
        if not tasks:
            return []
        return await asyncio.gather(*tasks)


def build_temporal_components():
    return [AdvisoryAnalysisWorkflow, AdvisoryBatchWorkflow], [collect_advisories_activity, analyze_advisory_activity]


async def run_worker(address: str, namespace: str, task_queue: str) -> None:
    from temporalio.client import Client
    from temporalio.worker import Worker

    workflows, activities = build_temporal_components()
    client = await Client.connect(address, namespace=namespace)
    worker = Worker(
        client,
        task_queue=task_queue,
        workflows=workflows,
        activities=activities,
        activity_executor=ThreadPoolExecutor(max_workers=8),
    )
    await worker.run()


async def submit_batch(address: str, namespace: str, task_queue: str, advisories: list[dict[str, Any]], skip_git: bool = False) -> str:
    from temporalio.client import Client

    client = await Client.connect(address, namespace=namespace)
    workflow_id = f"advisory-batch-{uuid.uuid4().hex[:12]}"
    session_id = f"advisory-miner:{workflow_id}"
    await client.start_workflow(
        AdvisoryBatchWorkflow.run,
        {"advisories": advisories, "skip_git": skip_git, "run_id": workflow_id, "session_id": session_id},
        id=workflow_id,
        task_queue=task_queue,
    )
    return workflow_id


async def submit_collection(address: str, namespace: str, task_queue: str, collect: dict[str, Any], **options: Any) -> str:
    from temporalio.client import Client

    client = await Client.connect(address, namespace=namespace)
    workflow_id = f"advisory-batch-{uuid.uuid4().hex[:12]}"
    payload = {"collect": collect, "run_id": workflow_id, "session_id": f"advisory-miner:{workflow_id}", **options}
    await client.start_workflow(
        AdvisoryBatchWorkflow.run,
        payload,
        id=workflow_id,
        task_queue=task_queue,
    )
    return workflow_id
