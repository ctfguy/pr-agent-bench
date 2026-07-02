from __future__ import annotations

import unittest

from advisory_miner.agents.advisory_parser import AdvisoryParser, ParsedAdvisory
from advisory_miner.agents.patterns import derive_patterns


SAMPLE_ADVISORY = {
    "ghsa_id": "GHSA-jpx3-25r2-jq5g",
    "cve_ids": ["CVE-2026-8054"],
    "summary": "SQL injection in dotCMS Core",
    "description": (
        "AuditPublishingResource.getPublishAuditStatuses builds a dynamic SQL query "
        "from the user-controlled bundleId parameter. The fix parameterizes the query."
    ),
    "cwes": [{"cwe_id": "CWE-89", "name": "SQL Injection"}],
    "vulnerabilities": [],
    "references": [],
}


SAMPLE_PARSER_OUTPUT = {
    "cwe_id": "CWE-89",
    "vulnerability_class": "sql_injection",
    "vulnerable_construct": "dynamic SQL built from user-controlled bundle ID",
    "vulnerable_functions": ["getPublishAuditStatuses"],
    "vulnerable_parameters": ["bundleId"],
    "affected_endpoints": ["/api/auditPublishing/getAll"],
    "expected_fix_behavior": "parameterized query + auth check",
    "high_signal_search_patterns": [
        "getPublishAuditStatuses",
        "bundleId",
        "AuditPublishingResource",
    ],
    "low_signal_patterns_to_avoid": ["audit", "publish", "valid"],
}


class FakeOpenAIClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def json_response(self, system, user, max_output_tokens=1800):
        self.calls.append((system, user, max_output_tokens))
        return self.response


class AdvisoryParserTests(unittest.TestCase):
    def test_parse_returns_structured_advisory(self):
        parser = AdvisoryParser(FakeOpenAIClient(SAMPLE_PARSER_OUTPUT))
        parsed = parser.parse(SAMPLE_ADVISORY)
        self.assertEqual(parsed.cwe_id, "CWE-89")
        self.assertEqual(parsed.vulnerability_class, "sql_injection")
        self.assertEqual(parsed.vulnerable_functions, ["getPublishAuditStatuses"])
        self.assertEqual(parsed.vulnerable_parameters, ["bundleId"])
        self.assertEqual(parsed.parse_status, "parsed")

    def test_parse_handles_empty_response_as_low_quality(self):
        parser = AdvisoryParser(FakeOpenAIClient({}))
        parsed = parser.parse(SAMPLE_ADVISORY)
        self.assertEqual(parsed.parse_status, "low_quality")
        self.assertEqual(parsed.high_signal_search_patterns, [])

    def test_parse_handles_client_error(self):
        class FailingClient:
            def json_response(self, system, user, max_output_tokens=1800):
                from advisory_miner.openai_client import OpenAIClientError
                raise OpenAIClientError("simulated failure")

        parser = AdvisoryParser(FailingClient())
        parsed = parser.parse(SAMPLE_ADVISORY)
        self.assertEqual(parsed.parse_status, "failed")
        self.assertIn("simulated failure", parsed.parse_error)

    def test_parse_skipped_without_client(self):
        parser = AdvisoryParser(None)
        parsed = parser.parse(SAMPLE_ADVISORY)
        self.assertEqual(parsed.parse_status, "skipped")

    def test_parse_dedupes_and_strips_lists(self):
        parser = AdvisoryParser(
            FakeOpenAIClient(
                {
                    "high_signal_search_patterns": [
                        "  foo  ",
                        "FOO",
                        "bar",
                        None,
                        "",
                        "baz",
                    ]
                }
            )
        )
        parsed = parser.parse(SAMPLE_ADVISORY)
        self.assertEqual(parsed.high_signal_search_patterns, ["foo", "bar", "baz"])


class PatternDerivationWithParsedTests(unittest.TestCase):
    """Phase 1 hook: when parsed advisory has signals, prefer them over
    commit-message keyword extraction."""

    def test_parsed_signals_replace_keyword_derivation(self):
        parsed = SAMPLE_PARSER_OUTPUT
        message = "fix audit publish stuff"  # noisy generic words
        diff = "+++ audit/publish/file.java"
        patterns = derive_patterns(message, diff, ["audit/publish/file.java"], parsed=parsed)
        # high-signal patterns come from parsed, not from message tokens
        self.assertIn("getPublishAuditStatuses", patterns)
        self.assertIn("bundleId", patterns)
        # low-signal exclusions are respected even if they appear in parser output
        self.assertNotIn("audit", [p.lower() for p in patterns])
        self.assertNotIn("publish", [p.lower() for p in patterns])

    def test_falls_back_to_keywords_when_parsed_is_low_quality(self):
        parsed = {"high_signal_search_patterns": [], "vulnerable_functions": [], "vulnerable_parameters": []}
        message = "Fix injection bug in getStatus method"
        diff = "-    getStatus(input);\n+    getStatus(sanitize(input));"
        patterns = derive_patterns(message, diff, ["api/status.py"], parsed=parsed)
        # falls back to old behavior — should still produce something
        self.assertGreater(len(patterns), 0)


if __name__ == "__main__":
    unittest.main()
