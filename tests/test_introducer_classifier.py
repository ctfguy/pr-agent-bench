from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from advisory_miner.agents.introducer_classifier import IntroducerClassifier
from advisory_miner.models import AnalysisResult, CandidateCommit, Finding


class FakeOpenAIClient:
    def __init__(self, responses):
        # responses keyed by candidate SHA prefix
        self.responses = responses
        self.calls: list[tuple[str, str]] = []
        self.payloads: list[dict] = []

    def json_response(self, system, user, max_output_tokens=1200):
        # Extract candidate sha from the payload (user is JSON string).
        import json as _json
        body = _json.loads(user)
        self.payloads.append(body)
        sha = body["candidate"]["sha"]
        self.calls.append((sha, body["diff"][:80]))
        for prefix, response in self.responses.items():
            if sha.startswith(prefix):
                return response
        return {"verdict": "uncertain", "is_vulnerable_callable_after": False, "rationale": "no match"}


def make_result_with_candidates() -> AnalysisResult:
    result = AnalysisResult(ghsa_id="GHSA-test-test-test")
    result.repository = Finding(value="owner/repo", confidence="high")
    result.parsed_advisory = {
        "parse_status": "parsed",
        "vulnerability_class": "sql_injection",
        "vulnerable_construct": "dynamic SQL from bundleId",
        "high_signal_search_patterns": ["bundleId"],
        "vulnerable_functions": ["getStatus"],
        "vulnerable_parameters": ["bundleId"],
    }
    result.introducer_candidates = [
        CandidateCommit(sha="aaa" * 14 + "a", score=100, subject="Move getStatus to new module", strategies=["classical_blame"]),
        CandidateCommit(sha="bbb" * 14 + "b", score=80, subject="Add error handling", strategies=["pickaxe"]),
        CandidateCommit(sha="ccc" * 14 + "c", score=60, subject="docs", strategies=["pickaxe"]),
    ]
    return result


class IntroducerClassifierTests(unittest.TestCase):
    def test_selects_first_introduced_classification(self):
        result = make_result_with_candidates()
        result.introduced_pr = Finding(value="owner/repo#999", confidence="medium")
        classifier = IntroducerClassifier(
            FakeOpenAIClient(
                {
                    "aaa": {"verdict": "refactored", "is_vulnerable_callable_after": True, "rationale": "moved code"},
                    "bbb": {"verdict": "introduced", "is_vulnerable_callable_after": True, "rationale": "adds the regex"},
                    "ccc": {"verdict": "unrelated", "is_vulnerable_callable_after": False, "rationale": "docs"},
                }
            ),
            MagicMock(get_commit=MagicMock(return_value={"commit": {"message": "x"}, "files": [{"filename": "f.py", "patch": "+ vuln_code"}]}), commit_pulls=MagicMock(return_value=[])),
            MagicMock(commit_diff=MagicMock(side_effect=Exception("force fallback to github"))),
        )
        classifier.classify_and_select({"ghsa_id": "GHSA-test-test-test"}, result, repo_path=None)
        self.assertEqual(result.introduced_commit.value, "bbb" * 14 + "b")
        self.assertEqual(result.introduced_commit.confidence, "medium")
        self.assertIsNone(result.introduced_pr.value)

    def test_emits_unknown_when_no_candidate_is_introduced(self):
        result = make_result_with_candidates()
        classifier = IntroducerClassifier(
            FakeOpenAIClient(
                {
                    "aaa": {"verdict": "refactored", "is_vulnerable_callable_after": True, "rationale": "moved"},
                    "bbb": {"verdict": "refactored", "is_vulnerable_callable_after": True, "rationale": "renamed"},
                    "ccc": {"verdict": "unrelated", "is_vulnerable_callable_after": False, "rationale": "docs"},
                }
            ),
            MagicMock(get_commit=MagicMock(return_value={"commit": {"message": "x"}, "files": [{"filename": "f.py", "patch": "diff"}]})),
            MagicMock(commit_diff=MagicMock(side_effect=Exception("force fallback to github"))),
        )
        classifier.classify_and_select({"ghsa_id": "GHSA-test-test-test"}, result, repo_path=None)
        self.assertIsNone(result.introduced_commit.value)
        self.assertEqual(result.introduced_commit.confidence, "unknown")
        # Evidence should explain why.
        sources = [e.source for e in result.introduced_commit.evidence]
        self.assertIn("introducer_classifier", sources)

    def test_skipped_when_parsed_low_quality(self):
        result = make_result_with_candidates()
        result.parsed_advisory = {"parse_status": "low_quality", "high_signal_search_patterns": []}
        original_intro = result.introduced_commit
        classifier = IntroducerClassifier(
            FakeOpenAIClient({}),
            MagicMock(),
            MagicMock(),
        )
        classifier.classify_and_select({"ghsa_id": "GHSA-test-test-test"}, result, repo_path=None)
        # Untouched: classifier returned without doing anything.
        self.assertIs(result.introduced_commit, original_intro)

    def test_low_confidence_when_callable_after_false(self):
        result = make_result_with_candidates()
        classifier = IntroducerClassifier(
            FakeOpenAIClient(
                {
                    "aaa": {"verdict": "introduced", "is_vulnerable_callable_after": False, "rationale": "added but not callable"},
                    "bbb": {"verdict": "unrelated", "is_vulnerable_callable_after": False, "rationale": "x"},
                    "ccc": {"verdict": "unrelated", "is_vulnerable_callable_after": False, "rationale": "x"},
                }
            ),
            MagicMock(get_commit=MagicMock(return_value={"commit": {"message": "x"}, "files": [{"filename": "f", "patch": "diff"}]}), commit_pulls=MagicMock(return_value=[])),
            MagicMock(commit_diff=MagicMock(side_effect=Exception("force fallback to github"))),
        )
        classifier.classify_and_select({"ghsa_id": "GHSA-test-test-test"}, result, repo_path=None)
        self.assertEqual(result.introduced_commit.confidence, "low")

    def test_passes_affected_lower_bounds_to_model(self):
        result = make_result_with_candidates()
        client = FakeOpenAIClient(
            {"aaa": {"verdict": "unrelated", "is_vulnerable_callable_after": False, "rationale": "x"}}
        )
        classifier = IntroducerClassifier(
            client,
            MagicMock(get_commit=MagicMock(return_value={"commit": {"message": "x"}, "files": [{"filename": "f", "patch": "diff"}]})),
            MagicMock(commit_diff=MagicMock(side_effect=Exception("force fallback to github"))),
            top_k=1,
        )

        classifier.classify_and_select(
            {
                "ghsa_id": "GHSA-test-test-test",
                "vulnerabilities": [{"vulnerable_version_range": ">= 7.5.0, < 7.15.2"}],
            },
            result,
            repo_path=None,
        )

        self.assertEqual(client.payloads[0]["affected_version_lower_bounds"], ["7.5.0"])
        self.assertIn("ranking_reasons", client.payloads[0]["candidate"])


if __name__ == "__main__":
    unittest.main()
