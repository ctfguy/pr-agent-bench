from __future__ import annotations

import os
import unittest
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from advisory_miner.langfuse_tracing import build_langfuse_tracer, LangfuseTracer
from advisory_miner.temporal_app import build_temporal_components, temporal_available


class FrameworkIntegrationTests(unittest.TestCase):
    def test_langfuse_tracer_exists_without_env_but_is_not_connected(self):
        with patch.dict(os.environ, {}, clear=True):
            tracer = build_langfuse_tracer()
            self.assertIsNotNone(tracer)
            assert tracer is not None
            self.assertFalse(tracer.available)

    def test_langfuse_tracer_noops_without_sdk_or_keys(self):
        tracer = LangfuseTracer(enabled=False)
        self.assertFalse(tracer.available)
        tracer.generation("x", "model", {}, {}, usage={})

    def test_langfuse_tracer_scores_active_span(self):
        class FakeSpan:
            def __init__(self):
                self.scores = []

            def score_trace(self, **kwargs):
                self.scores.append(kwargs)

        class FakeManager:
            def __init__(self, span):
                self.span = span

            def __enter__(self):
                return self.span

            def __exit__(self, exc_type, exc, tb):
                return False

        class FakeClient:
            def __init__(self, span):
                self.span = span
                self.fallback_called = False

            def start_as_current_observation(self, **kwargs):
                return FakeManager(self.span)

            def score_current_trace(self, **kwargs):
                self.fallback_called = True

        span = FakeSpan()
        client = FakeClient(span)
        tracer = LangfuseTracer(enabled=False)
        tracer.client = client

        with patch("langfuse.propagate_attributes", return_value=nullcontext()):
            with tracer.span("analysis"):
                tracer.score("tool_coverage", 1.0, metadata={"ghsa_id": "GHSA-test"})

        self.assertFalse(client.fallback_called)
        self.assertEqual(
            span.scores,
            [
                {
                    "name": "tool_coverage",
                    "value": 1.0,
                    "data_type": "NUMERIC",
                    "metadata": {"ghsa_id": "GHSA-test"},
                }
            ],
        )

    def test_temporal_optional_dependency_behavior(self):
        self.assertTrue(temporal_available())
        workflows, activities = build_temporal_components()
        self.assertTrue(workflows)
        self.assertTrue(activities)


class TemporalRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_batch_workflow_runs_in_temporal_test_environment(self):
        from temporalio.client import Client
        from temporalio.testing import WorkflowEnvironment
        from temporalio.worker import Worker

        workflows, activities = build_temporal_components()
        batch_workflow = workflows[1]
        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue="test-task-queue",
                workflows=workflows,
                activities=activities,
                activity_executor=ThreadPoolExecutor(max_workers=2),
            ):
                result = await env.client.execute_workflow(
                    batch_workflow.run,
                    {"advisories": []},
                    id="test-empty-batch",
                    task_queue="test-task-queue",
                )
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
