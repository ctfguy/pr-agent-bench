from __future__ import annotations

import unittest

from advisory_miner.agents.model_reviewer import ModelReviewer
from advisory_miner.models import AnalysisResult, Finding
from advisory_miner.openai_client import parse_json_object


class FakeOpenAIClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def json_response(self, system, user, max_output_tokens=1800):
        self.calls.append((system, user, max_output_tokens))
        return self.response


class ModelReviewerTests(unittest.TestCase):
    def test_parse_json_object_handles_fenced_json(self):
        self.assertEqual(parse_json_object('```json\n{"status":"ok"}\n```'), {"status": "ok"})

    def test_model_reviewer_downgrades_confidence_without_wiping_value(self):
        """Regression: the reviewer must never null out a value the deterministic
        tools produced. If it says `unknown`, we demote confidence to `low`
        instead so the deterministic finding stays auditable."""
        result = AnalysisResult(ghsa_id="GHSA-test-test-test")
        result.fix_commit = Finding(value="abc", confidence="medium")
        result.introduced_commit = Finding(value="def", confidence="medium")
        reviewer = ModelReviewer(
            FakeOpenAIClient(
                {
                    "status": "reviewed",
                    "fix_commit_review": {"value": "abc", "confidence": "high", "rationale": "direct evidence"},
                    "fix_pr_review": {"value": None, "confidence": "unknown", "rationale": "missing"},
                    "introduced_commit_review": {"value": None, "confidence": "unknown", "rationale": "weak evidence"},
                    "introduced_pr_review": {"value": None, "confidence": "unknown", "rationale": "missing"},
                    "validation_notes": ["downgraded introducer"],
                    "reasoning_trace": "fix supported; introducer unsupported",
                }
            )
        )
        reviewed = reviewer.review({"ghsa_id": "GHSA-test-test-test"}, result)
        self.assertEqual(reviewed.fix_commit.confidence, "high")
        # CRITICAL: value must NOT be wiped — deterministic finding stays.
        self.assertEqual(reviewed.introduced_commit.value, "def")
        # Reviewer wanted "unknown" + value-present → demote to "low".
        self.assertEqual(reviewed.introduced_commit.confidence, "low")
        self.assertEqual(reviewed.model_review["status"], "reviewed")

    def test_model_reviewer_skip_records_status_without_polluting_errors(self):
        """Reviewer parse/network failures should be recorded on model_review,
        not appended to errors[]."""
        result = AnalysisResult(ghsa_id="GHSA-test-test-test")
        result.fix_commit = Finding(value="abc", confidence="high")

        class FailingClient:
            def json_response(self, system, user, max_output_tokens=1800):
                from advisory_miner.openai_client import OpenAIClientError
                raise OpenAIClientError("simulated parse failure")

        reviewer = ModelReviewer(FailingClient())
        reviewed = reviewer.review({"ghsa_id": "GHSA-test-test-test"}, result)
        self.assertEqual(reviewed.errors, [])
        self.assertEqual(reviewed.model_review["status"], "skipped")
        # Original finding untouched.
        self.assertEqual(reviewed.fix_commit.value, "abc")
        self.assertEqual(reviewed.fix_commit.confidence, "high")


if __name__ == "__main__":
    unittest.main()
