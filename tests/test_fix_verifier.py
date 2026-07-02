from __future__ import annotations

import unittest

from advisory_miner.agents.fix_verifier import FixVerifier, _should_verify
from advisory_miner.models import AnalysisResult, Evidence, Finding, FixCandidate


class FakeOpenAIClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def json_response(self, system, user, max_output_tokens=1500):
        self.calls.append((system, user, max_output_tokens))
        return self.response


class QueueOpenAIClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def json_response(self, system, user, max_output_tokens=1500):
        self.calls.append((system, user, max_output_tokens))
        return self.responses.pop(0)


class FakeGitHubTools:
    def __init__(self, commit_payload):
        self.commit_payload = commit_payload

    def get_commit(self, owner, repo, sha):
        if isinstance(self.commit_payload, dict) and sha in self.commit_payload:
            return self.commit_payload[sha]
        return self.commit_payload


def make_result_with_direct_ref(score: int = 100) -> AnalysisResult:
    result = AnalysisResult(ghsa_id="GHSA-test-test-test")
    result.repository = Finding(value="owner/repo", confidence="high")
    result.fix_commit = Finding(value="abc1234567890abc1234567890abc1234567890a", confidence="high")
    result.parsed_advisory = {
        "parse_status": "parsed",
        "vulnerability_class": "sql_injection",
        "vulnerable_construct": "dynamic SQL from bundleId",
        "vulnerable_functions": ["getPublishAuditStatuses"],
        "vulnerable_parameters": ["bundleId"],
        "expected_fix_behavior": "parameterized query",
        "high_signal_search_patterns": ["getPublishAuditStatuses", "bundleId"],
        "low_signal_patterns_to_avoid": [],
    }
    result.fix_candidates.append(
        FixCandidate(
            sha="abc1234567890abc1234567890abc1234567890a",
            url="https://github.com/owner/repo/commit/abc1234567890abc1234567890abc1234567890a",
            score=score,
            reasons=["Advisory directly references this commit"],
            message="fix: parameterize bundleId query",
        )
    )
    return result


COMMIT_PAYLOAD_FIXES = {
    "commit": {"message": "fix: parameterize bundleId query"},
    "files": [
        {
            "filename": "AuditPublishingResource.java",
            "patch": (
                "@@ -10,3 +10,3 @@\n"
                "-    String sql = \"SELECT * FROM x WHERE bundleId='\" + bundleId + \"'\";\n"
                "+    String sql = \"SELECT * FROM x WHERE bundleId = ?\";\n"
                "+    stmt.setString(1, bundleId);\n"
            ),
        }
    ],
}


COMMIT_PAYLOAD_UNRELATED = {
    "commit": {"message": "docs: typo"},
    "files": [
        {
            "filename": "README.md",
            "patch": "-Welcome\n+Wellcome\n",
        }
    ],
}


class FixVerifierGatingTests(unittest.TestCase):
    def test_skip_when_direct_ref_and_high_confidence_and_no_close_alternative(self):
        result = make_result_with_direct_ref(score=100)
        top = result.fix_candidates[0]
        self.assertFalse(_should_verify(result, top))

    def test_verify_when_search_derived(self):
        result = make_result_with_direct_ref()
        # Replace reason with a search-derived one.
        top = result.fix_candidates[0]
        top.reasons = ["GitHub commit search matched advisory identifier"]
        self.assertTrue(_should_verify(result, top))

    def test_verify_when_close_alternative_exists(self):
        result = make_result_with_direct_ref(score=100)
        result.fix_candidates.append(
            FixCandidate(sha="0" * 40, score=85, reasons=["heuristic"])
        )
        self.assertTrue(_should_verify(result, result.fix_candidates[0]))

    def test_verify_when_confidence_is_medium(self):
        result = make_result_with_direct_ref()
        result.fix_commit.confidence = "medium"
        self.assertTrue(_should_verify(result, result.fix_candidates[0]))


class FixVerifierApplyTests(unittest.TestCase):
    def test_fixes_verdict_keeps_confidence_high(self):
        result = make_result_with_direct_ref(score=10)  # forces _should_verify=True
        result.fix_commit.confidence = "medium"
        verifier = FixVerifier(
            FakeOpenAIClient({"verdict": "fixes", "rationale": "matches construct", "covered_constructs": ["bundleId"]}),
            FakeGitHubTools(COMMIT_PAYLOAD_FIXES),
        )
        verdict = verifier.verify_top_candidate({"ghsa_id": "GHSA-test"}, result)
        self.assertIsNotNone(verdict)
        assert verdict is not None
        self.assertEqual(verdict.verdict, "fixes")
        self.assertEqual(result.fix_commit.confidence, "medium")  # no demotion on "fixes"
        sources = [e.source for e in result.fix_commit.evidence]
        self.assertIn("fix_verifier", sources)

    def test_partial_verdict_demotes_one_level(self):
        result = make_result_with_direct_ref(score=10)
        result.fix_commit.confidence = "high"
        # Force gating: make candidate search-derived so verifier runs.
        result.fix_candidates[0].reasons = ["GitHub commit search matched advisory identifier"]
        verifier = FixVerifier(
            FakeOpenAIClient({"verdict": "partial", "rationale": "only one endpoint patched"}),
            FakeGitHubTools(COMMIT_PAYLOAD_FIXES),
        )
        verifier.verify_top_candidate({"ghsa_id": "GHSA-test"}, result)
        self.assertEqual(result.fix_commit.confidence, "medium")  # high -> medium

    def test_unrelated_verdict_demotes_to_low(self):
        result = make_result_with_direct_ref(score=10)
        result.fix_commit.confidence = "high"
        # Force gating: make candidate search-derived so verifier runs.
        result.fix_candidates[0].reasons = ["GitHub commit search matched advisory identifier"]
        verifier = FixVerifier(
            FakeOpenAIClient({"verdict": "unrelated", "rationale": "diff is a typo fix"}),
            FakeGitHubTools(COMMIT_PAYLOAD_UNRELATED),
        )
        verifier.verify_top_candidate({"ghsa_id": "GHSA-test"}, result)
        self.assertEqual(result.fix_commit.confidence, "low")

    def test_skipped_when_parsed_advisory_low_quality(self):
        result = make_result_with_direct_ref()
        result.parsed_advisory = {"parse_status": "low_quality", "high_signal_search_patterns": []}
        # Force gating to want verification.
        result.fix_candidates[0].reasons = ["GitHub commit search matched advisory identifier"]
        verifier = FixVerifier(FakeOpenAIClient({"verdict": "fixes"}), FakeGitHubTools(COMMIT_PAYLOAD_FIXES))
        verdict = verifier.verify_top_candidate({"ghsa_id": "GHSA-test"}, result)
        self.assertIsNone(verdict)

    def test_value_never_wiped_by_verifier(self):
        """Regression: verifier must NEVER null out the fix_commit value."""
        result = make_result_with_direct_ref(score=10)
        original_value = result.fix_commit.value
        result.fix_candidates[0].reasons = ["GitHub commit search matched advisory identifier"]
        verifier = FixVerifier(
            FakeOpenAIClient({"verdict": "unrelated", "rationale": "x"}),
            FakeGitHubTools(COMMIT_PAYLOAD_UNRELATED),
        )
        verifier.verify_top_candidate({"ghsa_id": "GHSA-test"}, result)
        self.assertEqual(result.fix_commit.value, original_value)

    def test_unrelated_top_candidate_then_second_candidate_selected(self):
        result = make_result_with_direct_ref(score=50)
        first = result.fix_candidates[0]
        first.reasons = ["GitHub commit search matched advisory identifier"]
        second = FixCandidate(
            sha="b" * 40,
            url="https://github.com/owner/repo/commit/" + "b" * 40,
            score=40,
            reasons=["release range candidate"],
            message="fix: parameterize query",
        )
        result.fix_candidates.append(second)
        verifier = FixVerifier(
            QueueOpenAIClient(
                [
                    {"verdict": "unrelated", "rationale": "session refresh only"},
                    {"verdict": "fixes", "rationale": "adds parameterized query"},
                ]
            ),
            FakeGitHubTools({first.sha: COMMIT_PAYLOAD_UNRELATED, second.sha: COMMIT_PAYLOAD_FIXES}),
        )
        verdict = verifier.verify_top_candidate({"ghsa_id": "GHSA-test"}, result)
        self.assertIsNotNone(verdict)
        assert verdict is not None
        self.assertEqual(verdict.verdict, "fixes")
        self.assertEqual(result.fix_commit.value, second.sha)


if __name__ == "__main__":
    unittest.main()
