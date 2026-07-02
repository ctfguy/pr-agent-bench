from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from advisory_miner.advisories import fetch_advisories, normalize_advisory
from advisory_miner.cli import main
from advisory_miner.collector import date_range
from advisory_miner.extractors import extract_ghsa_id, extract_github_references


SAMPLE_ADVISORY = {
    "ghsa_id": "GHSA-jpx3-25r2-jq5g",
    "cve_id": "CVE-2026-8054",
    "url": "https://api.github.com/advisories/GHSA-jpx3-25r2-jq5g",
    "html_url": "https://github.com/advisories/GHSA-jpx3-25r2-jq5g",
    "summary": "SQL injection in dotCMS Core",
    "description": "Fixed by https://github.com/dotCMS/core/pull/35553 and commit https://github.com/dotCMS/core/commit/dc515d99851958b7b5bec9e43dbbf69617d82e70",
    "type": "unreviewed",
    "severity": "critical",
    "repository_advisory_url": None,
    "source_code_location": "https://github.com/dotCMS/core",
    "identifiers": [
        {"value": "GHSA-jpx3-25r2-jq5g", "type": "GHSA"},
        {"value": "CVE-2026-8054", "type": "CVE"},
    ],
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-8054",
        "https://github.com/dotCMS/core/pull/35553",
        "https://github.com/dotCMS/core/issues/35554",
        "https://github.com/dotCMS/core/compare/v26.04.28-02...v26.04.28-03",
        "https://github.com/dotCMS/core/releases/tag/v26.04.28-03",
        "https://github.com/advisories/GHSA-jpx3-25r2-jq5g",
    ],
    "published_at": "2026-05-27T09:31:17Z",
    "updated_at": "2026-05-27T09:31:29Z",
    "github_reviewed_at": None,
    "nvd_published_at": "2026-05-27T09:16:32Z",
    "withdrawn_at": None,
    "vulnerabilities": [
        {
            "package": {"ecosystem": "maven", "name": "com.dotcms:dotcms-core"},
            "vulnerable_version_range": ">=25.11.04-1, <26.04.28-03",
            "first_patched_version": {"identifier": "26.04.28-03"},
            "vulnerable_functions": ["PublishAuditAPIImpl.getPublishAuditStatuses"],
        }
    ],
    "cvss_severities": {"cvss_v4": {"score": 10.0, "vector_string": "CVSS:4.0/..."}},
    "cvss": {"score": None, "vector_string": None},
    "cwes": [{"cwe_id": "CWE-89", "name": "SQL Injection"}],
    "credits": [],
}


class FakeClient:
    def __init__(self, pages: list[list[dict]] | None = None):
        self.pages = pages or [[SAMPLE_ADVISORY]]
        self.calls: list[dict] = []
        self._page_idx = 0

    def get_json(self, path, params=None, accept="application/vnd.github+json"):
        self.calls.append({"method": "GET", "path": path, "params": params, "accept": accept})
        if path.startswith("/advisories/GHSA-"):
            return SAMPLE_ADVISORY
        raise AssertionError(path)

    def request_with_link(self, method, path, params=None, payload=None, accept="application/vnd.github+json"):
        self.calls.append({"method": method, "path": path, "params": params, "accept": accept})
        if path != "/advisories" and not path.startswith("https://"):
            raise AssertionError(path)
        if self._page_idx >= len(self.pages):
            return [], None
        data = self.pages[self._page_idx]
        self._page_idx += 1
        next_url = (
            f"https://api.github.com/advisories?after=cursor_{self._page_idx}"
            if self._page_idx < len(self.pages)
            else None
        )
        return data, next_url


class CollectorTests(unittest.TestCase):
    def test_extracts_ghsa_id_from_id_and_urls(self):
        self.assertEqual(extract_ghsa_id("GHSA-jpx3-25r2-jq5g"), "GHSA-JPX3-25R2-JQ5G")
        self.assertEqual(
            extract_ghsa_id("https://github.com/advisories/GHSA-jpx3-25r2-jq5g"),
            "GHSA-JPX3-25R2-JQ5G",
        )
        self.assertEqual(
            extract_ghsa_id("https://api.github.com/advisories/GHSA-jpx3-25r2-jq5g"),
            "GHSA-JPX3-25R2-JQ5G",
        )

    def test_extracts_github_references(self):
        refs = extract_github_references(SAMPLE_ADVISORY)
        self.assertEqual(refs.repositories, ["dotCMS/core"])
        self.assertEqual(refs.pull_requests[0].value, "35553")
        self.assertEqual(refs.commits[0].value, "dc515d99851958b7b5bec9e43dbbf69617d82e70")
        self.assertEqual(refs.issues[0].value, "35554")
        self.assertEqual(refs.compare_urls[0].value, "v26.04.28-02...v26.04.28-03")
        self.assertEqual(refs.release_urls[0].value, "v26.04.28-03")

    def test_extracts_github_api_repository_urls(self):
        advisory = {
            **SAMPLE_ADVISORY,
            "source_code_location": "",
            "repository_advisory_url": "https://api.github.com/repos/dotCMS/core/security-advisories/GHSA-jpx3-25r2-jq5g",
            "references": [
                "https://api.github.com/repos/dotCMS/core/pulls/35553",
                "https://api.github.com/repos/dotCMS/core/commits/dc515d99851958b7b5bec9e43dbbf69617d82e70",
                "https://api.github.com/repos/dotCMS/core/issues/35554",
            ],
        }
        refs = extract_github_references(advisory)
        self.assertEqual(refs.repositories, ["dotCMS/core"])
        self.assertEqual(refs.pull_requests[0].value, "35553")
        self.assertEqual(refs.commits[0].value, "dc515d99851958b7b5bec9e43dbbf69617d82e70")
        self.assertEqual(refs.issues[0].value, "35554")

    def test_normalizes_advisory_details(self):
        advisory = normalize_advisory(SAMPLE_ADVISORY)
        payload = advisory.to_dict()
        self.assertEqual(payload["ghsa_id"], "GHSA-jpx3-25r2-jq5g")
        self.assertEqual(payload["cve_ids"], ["CVE-2026-8054"])
        self.assertEqual(payload["vulnerabilities"][0]["first_patched_version"], "26.04.28-03")
        self.assertEqual(payload["extracted_github"]["repositories"], ["dotCMS/core"])
        self.assertEqual(payload["raw"]["ghsa_id"], "GHSA-jpx3-25r2-jq5g")

    def test_normalize_can_omit_raw(self):
        advisory = normalize_advisory(SAMPLE_ADVISORY, include_raw=False)
        self.assertIsNone(advisory.to_dict()["raw"])

    def test_date_range(self):
        self.assertEqual(date_range("2026-01-01", "2026-02-01"), "2026-01-01..2026-02-01")
        self.assertEqual(date_range("2026-01-01", None), ">=2026-01-01")
        self.assertEqual(date_range(None, "2026-02-01"), "<=2026-02-01")
        self.assertIsNone(date_range(None, None))

    def test_fetch_latest_passes_filters(self):
        client = FakeClient()
        advisories = fetch_advisories(
            client,
            severity="critical",
            limit=1,
            published=">=2026-01-01",
            updated="2026-01-01..2026-02-01",
        )
        self.assertEqual(len(advisories), 1)
        params = client.calls[0]["params"]
        self.assertEqual(params["severity"], "critical")
        self.assertEqual(params["published"], ">=2026-01-01")
        self.assertEqual(params["updated"], "2026-01-01..2026-02-01")

    def test_fetch_walks_cursor_and_dedupes(self):
        # Pages 1 and 2 are distinct; page 3 contains a duplicate of page 1 row.
        a1 = {**SAMPLE_ADVISORY, "ghsa_id": "GHSA-aaaa-aaaa-aaaa"}
        a2 = {**SAMPLE_ADVISORY, "ghsa_id": "GHSA-bbbb-bbbb-bbbb"}
        a3_dup = {**SAMPLE_ADVISORY, "ghsa_id": "GHSA-aaaa-aaaa-aaaa"}
        client = FakeClient(pages=[[a1], [a2], [a3_dup]])
        advisories = fetch_advisories(client, severity="critical", limit=10)
        self.assertEqual([a["ghsa_id"] for a in advisories], ["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"])
        # Follow-up requests must use the cursor URL with no extra params.
        self.assertEqual(client.calls[0]["path"], "/advisories")
        self.assertIsNotNone(client.calls[0]["params"])
        self.assertTrue(client.calls[1]["path"].startswith("https://api.github.com/advisories?after="))
        self.assertIsNone(client.calls[1]["params"])

    def test_fetch_respects_limit_mid_page(self):
        a1 = {**SAMPLE_ADVISORY, "ghsa_id": "GHSA-aaaa-aaaa-aaaa"}
        a2 = {**SAMPLE_ADVISORY, "ghsa_id": "GHSA-bbbb-bbbb-bbbb"}
        a3 = {**SAMPLE_ADVISORY, "ghsa_id": "GHSA-cccc-cccc-cccc"}
        client = FakeClient(pages=[[a1, a2, a3]])
        advisories = fetch_advisories(client, severity="critical", limit=2)
        self.assertEqual(len(advisories), 2)
        self.assertEqual([a["ghsa_id"] for a in advisories], ["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"])

    def test_cli_collects_by_advisory_id(self):
        self._run_cli_and_assert(["--advisory", "GHSA-jpx3-25r2-jq5g", "--no-enrich"])

    def test_cli_collects_by_advisory_url_with_collect_alias(self):
        self._run_cli_and_assert(
            ["collect", "--url", "https://github.com/advisories/GHSA-jpx3-25r2-jq5g", "--no-enrich"]
        )

    def test_cli_collects_latest_with_filters(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "latest.json"
            fake = FakeClient(pages=[[SAMPLE_ADVISORY, {**SAMPLE_ADVISORY, "ghsa_id": "GHSA-aaaa-bbbb-cccc"}]])
            with patch.dict(os.environ, {"GITHUB_TOKEN": "token"}), patch(
                "advisory_miner.cli.GitHubClient", return_value=fake
            ):
                exit_code = main(
                    [
                        "--limit",
                        "2",
                        "--severity",
                        "high",
                        "--published-since",
                        "2026-01-01",
                        "--no-enrich",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(payload), 2)
            params = fake.calls[0]["params"]
            self.assertEqual(params["severity"], "high")
            self.assertEqual(params["published"], ">=2026-01-01")

    def _run_cli_and_assert(self, args):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "advisory.json"
            fake = FakeClient()
            with patch.dict(os.environ, {"GITHUB_TOKEN": "token"}), patch(
                "advisory_miner.cli.GitHubClient", return_value=fake
            ):
                exit_code = main([*args, "--output", str(output)])
            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload[0]["ghsa_id"], "GHSA-jpx3-25r2-jq5g")
            self.assertEqual(payload[0]["extracted_github"]["repositories"], ["dotCMS/core"])


if __name__ == "__main__":
    unittest.main()
