from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from advisory_miner.enrichers.enrichment import (
    EnrichedRefs,
    _merge_nvd,
    _merge_osv,
    enrich_advisory,
)


OSV_PAYLOAD = {
    "id": "GHSA-test-test-test",
    "aliases": ["CVE-2026-9999"],
    "references": [
        {"type": "FIX", "url": "https://github.com/owner/repo/commit/abc1234567890abcdef1234567890abcdef1234"},
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999"},
    ],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "example-pkg"},
            "ranges": [
                {
                    "type": "GIT",
                    "events": [
                        {"introduced": "1111111111111111111111111111111111111111"},
                        {"fixed": "2222222222222222222222222222222222222222"},
                    ],
                },
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.0.0"},
                        {"fixed": "1.2.3"},
                    ],
                },
            ],
        }
    ],
}


NVD_PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-9999",
                "references": [
                    {"url": "https://github.com/owner/repo/commit/dead0000beef0000dead0000beef0000dead0000"},
                    {"url": "https://example.com/security-bulletin"},
                ],
            }
        }
    ]
}


class MergeOsvTests(unittest.TestCase):
    def test_merges_aliases_references_and_git_events(self):
        refs = EnrichedRefs()
        _merge_osv(refs, OSV_PAYLOAD)
        self.assertEqual(refs.osv_id, "GHSA-test-test-test")
        self.assertIn("CVE-2026-9999", refs.osv_aliases)
        self.assertIn(
            "1111111111111111111111111111111111111111",
            refs.osv_introduced_commits,
        )
        self.assertIn(
            "2222222222222222222222222222222222222222",
            refs.osv_fixed_commits,
        )
        # Reference URLs are tracked; commit-style refs ALSO land in extra_github_commit_urls.
        self.assertIn(
            "https://github.com/owner/repo/commit/abc1234567890abcdef1234567890abcdef1234",
            refs.extra_github_commit_urls,
        )
        # Package summary present.
        self.assertTrue(refs.osv_affected_packages)
        self.assertEqual(refs.osv_affected_packages[0]["ecosystem"], "PyPI")

    def test_handles_missing_payload(self):
        refs = EnrichedRefs()
        _merge_osv(refs, None)
        self.assertEqual(refs.osv_id, None)


class MergeNvdTests(unittest.TestCase):
    def test_extracts_extra_commit_urls(self):
        refs = EnrichedRefs()
        _merge_nvd(refs, NVD_PAYLOAD)
        self.assertIn(
            "https://github.com/owner/repo/commit/dead0000beef0000dead0000beef0000dead0000",
            refs.extra_github_commit_urls,
        )
        self.assertIn(
            "https://example.com/security-bulletin",
            refs.nvd_references,
        )


class EnrichAdvisoryTests(unittest.TestCase):
    def test_enrich_advisory_combines_osv_and_nvd(self):
        def fake_fetch_osv(identifier):
            if identifier == "GHSA-test-test-test":
                return OSV_PAYLOAD
            return None

        def fake_fetch_nvd(cve):
            if cve == "CVE-2026-9999":
                return NVD_PAYLOAD
            return None

        with patch("advisory_miner.enrichers.enrichment._fetch_osv", side_effect=fake_fetch_osv), \
            patch("advisory_miner.enrichers.enrichment._fetch_nvd", side_effect=fake_fetch_nvd):
            refs = enrich_advisory("GHSA-test-test-test", ["CVE-2026-9999"])
        self.assertEqual(refs.osv_id, "GHSA-test-test-test")
        self.assertIn("CVE-2026-9999", refs.osv_aliases)
        self.assertIn(
            "https://github.com/owner/repo/commit/dead0000beef0000dead0000beef0000dead0000",
            refs.extra_github_commit_urls,
        )
        self.assertIn("osv:GHSA-test-test-test", refs.sources)
        self.assertIn("nvd:CVE-2026-9999", refs.sources)

    def test_enrich_handles_404_silently(self):
        with patch("advisory_miner.enrichers.enrichment._fetch_osv", return_value=None), \
            patch("advisory_miner.enrichers.enrichment._fetch_nvd", return_value=None):
            refs = enrich_advisory("GHSA-missing", ["CVE-missing"])
        self.assertIsNone(refs.osv_id)
        self.assertEqual(refs.osv_introduced_commits, [])
        self.assertEqual(refs.errors, [])


class FixFinderEnrichmentIntegrationTests(unittest.TestCase):
    def test_enriched_commits_become_direct_evidence(self):
        from advisory_miner.agents.fix_finder import _commits_from_enriched

        advisory = {
            "extracted_github": {"repositories": ["owner/repo"]},
            "enriched_refs": {
                "extra_github_commit_urls": [
                    "https://github.com/owner/repo/commit/feedfacefeedfacefeedfacefeedfacefeedface"
                ],
                "osv_fixed_commits": ["1234123412341234123412341234123412341234"],
            },
        }
        commits = _commits_from_enriched(advisory)
        shas = {c["value"] for c in commits}
        self.assertIn("feedfacefeedfacefeedfacefeedfacefeedface", shas)
        self.assertIn("1234123412341234123412341234123412341234", shas)


if __name__ == "__main__":
    unittest.main()
