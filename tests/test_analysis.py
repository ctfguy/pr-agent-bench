from __future__ import annotations

import unittest

from advisory_miner.agents.fix_finder import FixFinder
from advisory_miner.agents.orchestrator import AdvisoryAnalyzer, analyze_parallel
from advisory_miner.agents.patterns import derive_patterns


ADVISORY = {
    "ghsa_id": "GHSA-jpx3-25r2-jq5g",
    "cve_ids": ["CVE-2026-8054"],
    "summary": "SQL injection in dotCMS Core",
    "description": "SQL injection in Publish Audit API endpoints /api/auditPublishing/get and /api/auditPublishing/getAll. The endpoints did not enforce authentication and accepted unsanitized input used in dynamically constructed SQL.",
    "extracted_github": {
        "repositories": ["dotCMS/core"],
        "pull_requests": [
            {
                "kind": "pull_request",
                "owner": "dotCMS",
                "repo": "core",
                "value": "35553",
                "url": "https://github.com/dotCMS/core/pull/35553",
            }
        ],
        "commits": [],
    },
}


class FakeGitHubTools:
    def get_pr_bundle(self, owner, repo, number):
        return {
            "pull_request": {
                "number": number,
                "title": "fix(publisher): parameterize getPublishAuditStatuses bundle-id query",
                "merge_commit_sha": "6a5f4188715baaf5b4ffdf0f8f80c402ccfb97ab",
            },
            "commits": [
                _commit("dc515d99851958b7b5bec9e43dbbf69617d82e70", "fix(publisher): parameterize getPublishAuditStatuses bundle-id query"),
                _commit("f783f9ddf11cb55105dd8eaec17d44e997568553", "test(publisher): regression tests for getPublishAuditStatuses parameterization"),
                _commit("f0bbd71bbd8d10c74456c6841c33474e4b5ca038", "Merge branch 'main' into security/fix-issue-581-1-publishauditapi"),
                _commit("10dcb6230e390a89ffdfd8b5fe7cf60381e40bb6", "fix(rest): require backend user + publishing-queue portlet on AuditPublishingResource"),
            ],
            "files": [
                {"filename": "dotCMS/src/main/java/com/dotcms/publisher/business/PublishAuditAPIImpl.java"},
                {"filename": "dotCMS/src/main/java/com/dotcms/rest/AuditPublishingResource.java"},
            ],
        }

    def commit_pulls(self, owner, repo, sha):
        return []

    def search_prs(self, owner, repo, terms, limit=5):
        return []

    def search_commits(self, owner, repo, terms, limit=5):
        return []


class FakeGitTools:
    pass


class AnalysisTests(unittest.TestCase):
    def test_fix_finder_ranks_security_fix_commits_over_tests_and_merges(self):
        result = FixFinder(FakeGitHubTools()).find(ADVISORY)
        ranked = [item.sha for item in result.fix_candidates[:3]]
        self.assertIn("dc515d99851958b7b5bec9e43dbbf69617d82e70", ranked)
        self.assertIn("10dcb6230e390a89ffdfd8b5fe7cf60381e40bb6", ranked)
        self.assertNotEqual(result.fix_candidates[0].sha, "f0bbd71bbd8d10c74456c6841c33474e4b5ca038")
        self.assertEqual(result.fix_pr.value, "dotCMS/core#35553")

    def test_pattern_derivation_prefers_fix_identifiers(self):
        patterns = derive_patterns(
            "fix(publisher): parameterize getPublishAuditStatuses bundle-id query",
            "+ dc.setSQL(String.format(SELECT_ALL_BY_BUNDLES_IDS, placeholders));\n+ bundleIds.forEach(dc::addParam);",
            ["dotCMS/src/main/java/com/dotcms/publisher/business/PublishAuditAPIImpl.java"],
        )
        self.assertIn("getPublishAuditStatuses", patterns)
        self.assertIn("SELECT_ALL_BY_BUNDLES_IDS", patterns)

    def test_parallel_analyzer_preserves_unknown_introducer_when_git_skipped(self):
        analyzer = AdvisoryAnalyzer(FakeGitHubTools(), FakeGitTools())
        results = analyze_parallel([ADVISORY], analyzer, workers=2, skip_git=True)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].repository.value, "dotCMS/core")
        self.assertEqual(results[0].fix_pr.value, "dotCMS/core#35553")
        self.assertEqual(results[0].introduced_commit.confidence, "unknown")


def _commit(sha: str, message: str):
    return {"sha": sha, "commit": {"message": message}}


if __name__ == "__main__":
    unittest.main()
