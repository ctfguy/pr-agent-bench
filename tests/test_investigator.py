from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from advisory_miner.agents.evidence import EvidenceLedger
from advisory_miner.agents.investigator import Investigator
from advisory_miner.models import AnalysisResult, Finding
from advisory_miner.openai_client import OpenAIClient


SAMPLE_ADVISORY = {
    "ghsa_id": "GHSA-zzzz-zzzz-zzzz",
    "cve_ids": ["CVE-2026-9999"],
    "summary": "Path traversal in fooserver",
    "description": "Allows arbitrary file read via untrusted path.",
    "references": ["https://github.com/fooorg/fooserver"],
    "vulnerabilities": [],
    "cwes": [{"cwe_id": "CWE-22", "name": "Path Traversal"}],
    "extracted_github": {"repositories": ["fooorg/fooserver"]},
}


def make_result_with_unknown_fix() -> AnalysisResult:
    result = AnalysisResult(ghsa_id=SAMPLE_ADVISORY["ghsa_id"])
    result.repository = Finding(
        value="fooorg/fooserver",
        url="https://github.com/fooorg/fooserver",
        confidence="high",
    )
    return result


class FakeGitHubTools:
    """Minimal stand-in — investigator handlers won't be invoked in mocked loops."""

    def __init__(self):
        self.calls = []

    def get_pr_bundle(self, *args, **kwargs):
        self.calls.append(("get_pr_bundle", args, kwargs))
        return {"pull_request": {"number": 42}, "commits": [], "files": []}

    def get_commit(self, *args, **kwargs):
        self.calls.append(("get_commit", args, kwargs))
        return {"sha": "abc1234"}

    def commit_pulls(self, *args, **kwargs):
        self.calls.append(("commit_pulls", args, kwargs))
        return []

    def search_prs(self, *args, **kwargs):
        self.calls.append(("search_prs", args, kwargs))
        return []

    def search_commits(self, *args, **kwargs):
        self.calls.append(("search_commits", args, kwargs))
        return []


class InvestigatorTests(unittest.TestCase):
    def _client(self) -> OpenAIClient:
        return OpenAIClient(api_key="sk-test", model="gpt-test", timeout=5)

    def test_residual_targets_skips_known_findings(self):
        result = make_result_with_unknown_fix()
        result.fix_commit = Finding(value="deadbeef" * 5, confidence="high")
        result.fix_pr = Finding(value="fooorg/fooserver#42", confidence="medium")
        investigator = Investigator(self._client(), FakeGitHubTools(), git_tools=None)
        residual = investigator._residual_targets(result)
        self.assertNotIn("fix_commit", residual)
        self.assertNotIn("fix_pr", residual)
        self.assertIn("introduced_commit", residual)
        self.assertIn("introduced_pr", residual)

    def test_apply_finalized_sets_findings_with_default_urls(self):
        result = make_result_with_unknown_fix()
        investigator = Investigator(self._client(), FakeGitHubTools(), git_tools=None)
        investigator._apply_finalized(
            result,
            {
                "fix_commit": {
                    "value": "abc1234567890abcdef1234567890abcdef12345",
                    "confidence": "medium",
                    "rationale": "matched CWE-22 in commit message and diff",
                },
                "fix_pr": {
                    "value": "fooorg/fooserver#42",
                    "confidence": "medium",
                    "rationale": "PR fixes path traversal",
                },
            },
            owner="fooorg",
            repo="fooserver",
        )
        self.assertEqual(result.fix_commit.value, "abc1234567890abcdef1234567890abcdef12345")
        self.assertEqual(
            result.fix_commit.url,
            "https://github.com/fooorg/fooserver/commit/abc1234567890abcdef1234567890abcdef12345",
        )
        self.assertEqual(result.fix_pr.value, "fooorg/fooserver#42")
        self.assertEqual(result.fix_pr.url, "https://github.com/fooorg/fooserver/pull/42")
        self.assertEqual(result.fix_pr.confidence, "medium")
        # Evidence trail records investigator rationale.
        self.assertTrue(any(e.source == "investigator" for e in result.fix_commit.evidence))

    def test_apply_finalized_respects_existing_high_confidence(self):
        result = make_result_with_unknown_fix()
        result.fix_commit = Finding(
            value="existinghighsha000000000000000000000000",
            url="https://github.com/x/y/commit/existinghigh",
            confidence="high",
        )
        investigator = Investigator(self._client(), FakeGitHubTools(), git_tools=None)
        investigator._apply_finalized(
            result,
            {
                "fix_commit": {
                    "value": "lowershamore0000000000000000000000000000",
                    "confidence": "medium",
                    "rationale": "weaker evidence",
                },
            },
            owner="x",
            repo="y",
        )
        # The existing high-confidence finding must not be overwritten.
        self.assertEqual(result.fix_commit.value, "existinghighsha000000000000000000000000")
        self.assertEqual(result.fix_commit.confidence, "high")

    def test_tool_schemas_include_finalize_finding(self):
        investigator = Investigator(self._client(), FakeGitHubTools(), git_tools=None)
        names = {schema["name"] for schema in investigator._tool_schemas(has_git=False)}
        self.assertIn("finalize_finding", names)
        self.assertIn("github_search_prs", names)
        # No git tools when has_git=False.
        self.assertNotIn("git_show_diff", names)

    def test_investigate_rejects_unbacked_tool_loop_finalized(self):
        result = make_result_with_unknown_fix()
        investigator = Investigator(self._client(), FakeGitHubTools(), git_tools=None)

        fake_response = {
            "finalized": {
                "fix_commit": {
                    "target": "fix_commit",
                    "value": "facadefacadefacadefacadefacadefacadeface",
                    "confidence": "medium",
                    "rationale": "Located via search; diff fixes CWE-22.",
                },
            },
            "tool_calls": [{"name": "github_search_prs", "arguments": {"query": "CVE-2026-9999"}}],
            "final_text": None,
            "usage": {"input_tokens": 500, "output_tokens": 200},
            "turns": 3,
        }

        with patch.object(OpenAIClient, "tool_loop", return_value=fake_response) as mocked:
            investigator.investigate(SAMPLE_ADVISORY, result, repo_path=None)

        mocked.assert_called_once()
        self.assertIsNone(result.fix_commit.value)
        self.assertTrue(any("rejected finalized fix_commit" in error for error in result.errors))

    def test_apply_finalized_accepts_ledger_backed_commit(self):
        result = make_result_with_unknown_fix()
        investigator = Investigator(self._client(), FakeGitHubTools(), git_tools=None)
        ledger = EvidenceLedger("fooorg", "fooserver")
        sha = "facadefacadefacadefacadefacadefacadeface"
        ledger.record_tool("git_show_diff", {"sha": sha}, {"sha": sha, "diff": "+ fixed CWE-22"})
        investigator._apply_finalized(
            result,
            {
                "fix_commit": {
                    "target": "fix_commit",
                    "value": sha,
                    "confidence": "medium",
                    "rationale": "Diff removes path traversal.",
                },
            },
            owner="fooorg",
            repo="fooserver",
            ledger=ledger,
            require_evidence=True,
        )
        self.assertEqual(result.fix_commit.value, sha)
        self.assertIn("supporting_evidence", result.fix_commit.evidence[-1].detail)

    def test_investigate_records_errors_without_repo(self):
        result = AnalysisResult(ghsa_id="GHSA-norepo")
        investigator = Investigator(self._client(), FakeGitHubTools(), git_tools=None)
        with patch.object(OpenAIClient, "tool_loop") as mocked:
            investigator.investigate(SAMPLE_ADVISORY, result, repo_path=None)
        mocked.assert_not_called()


class ToolLoopTests(unittest.TestCase):
    def test_tool_loop_terminates_on_no_function_calls(self):
        client = OpenAIClient(api_key="sk-test", model="gpt-test", timeout=5)
        responses = [
            {
                "output": [
                    {"type": "message", "content": [{"type": "output_text", "text": "done"}]}
                ],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            }
        ]

        def fake_post(body):
            return responses.pop(0)

        with patch.object(client, "_post", side_effect=fake_post):
            outcome = client.tool_loop(
                system="be brief",
                user_payload={"hello": "world"},
                tools=[],
                handlers={},
                max_turns=4,
            )
        self.assertEqual(outcome["final_text"], "done")
        self.assertEqual(outcome["turns"], 1)
        self.assertEqual(outcome["finalized"], {})

    def test_tool_loop_dispatches_tools_and_finalizes(self):
        client = OpenAIClient(api_key="sk-test", model="gpt-test", timeout=5)
        # Turn 1: model calls one search tool. Turn 2: model calls finalize_finding.
        responses = [
            {
                "output": [
                    {
                        "type": "function_call",
                        "name": "search_prs",
                        "call_id": "call-1",
                        "arguments": json.dumps({"query": "CVE-1"}),
                    }
                ],
                "usage": {"input_tokens": 20, "output_tokens": 10},
            },
            {
                "output": [
                    {
                        "type": "function_call",
                        "name": "finalize_finding",
                        "call_id": "call-2",
                        "arguments": json.dumps(
                            {
                                "target": "fix_pr",
                                "value": "owner/repo#7",
                                "confidence": "high",
                                "rationale": "ok",
                            }
                        ),
                    }
                ],
                "usage": {"input_tokens": 30, "output_tokens": 12},
            },
            {
                "output": [
                    {"type": "message", "content": [{"type": "output_text", "text": "all done"}]}
                ],
                "usage": {"input_tokens": 5, "output_tokens": 5},
            },
        ]

        def fake_post(body):
            return responses.pop(0)

        handler_called = {}

        def search_prs(args):
            handler_called["search_prs"] = args
            return {"prs": [{"number": 7}]}

        with patch.object(client, "_post", side_effect=fake_post):
            outcome = client.tool_loop(
                system="hunt",
                user_payload="payload",
                tools=[{"type": "function", "name": "search_prs"}],
                handlers={"search_prs": search_prs},
                max_turns=5,
            )

        self.assertEqual(handler_called.get("search_prs"), {"query": "CVE-1"})
        self.assertIn("fix_pr", outcome["finalized"])
        self.assertEqual(outcome["finalized"]["fix_pr"]["value"], "owner/repo#7")
        self.assertEqual(outcome["final_text"], "all done")
        self.assertEqual(outcome["usage"]["input_tokens"], 55)
        self.assertEqual(outcome["usage"]["output_tokens"], 27)
        self.assertEqual(outcome["turns"], 3)


if __name__ == "__main__":
    unittest.main()
