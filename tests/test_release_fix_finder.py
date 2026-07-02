from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from advisory_miner.agents.release_fix_finder import ReleaseFixFinder, fixed_versions
from advisory_miner.models import AnalysisResult, Finding
from advisory_miner.tools.git_tools import GitTools


class FakeGitHubTools:
    def commit_pulls(self, owner, repo, sha):
        return [{"number": 7, "html_url": f"https://github.com/{owner}/{repo}/pull/7"}]


class ReleaseFixFinderTests(unittest.TestCase):
    def test_fixed_versions_extracts_from_advisory_and_enrichment(self):
        advisory = {
            "vulnerabilities": [{"first_patched_version": "1.2.3"}],
            "enriched_refs": {"osv_affected_packages": [{"ranges": [{"fixed": "1.2.4"}]}]},
        }
        self.assertEqual(fixed_versions(advisory), ["1.2.3", "1.2.4"])

    def test_finds_fix_from_fixed_version_tag_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            self._git(repo, "init")
            self._git(repo, "config", "user.email", "test@example.com")
            self._git(repo, "config", "user.name", "Test User")
            (repo / "server.go").write_text("package main\nfunc main(){}\n", encoding="utf-8")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "initial")
            self._git(repo, "tag", "v1.0.0")
            (repo / "server.go").write_text(
                "package main\n// fix trusted proxy ip for X-Forwarded-Uri\nfunc main(){}\n",
                encoding="utf-8",
            )
            self._git(repo, "commit", "-am", "fix: add trusted-proxy-ip handling")
            fix = self._git(repo, "rev-parse", "HEAD").strip()
            self._git(repo, "tag", "v1.0.1")

            advisory = {
                "ghsa_id": "GHSA-test-test-test",
                "cve_ids": [],
                "summary": "X-Forwarded-Uri trusted proxy bypass",
                "description": "fixed by trusted-proxy-ip",
                "vulnerabilities": [{"first_patched_version": "1.0.1"}],
            }
            result = AnalysisResult(ghsa_id=advisory["ghsa_id"])
            result.repository = Finding(value="owner/repo", confidence="high")
            result.parsed_advisory = {
                "high_signal_search_patterns": ["trusted-proxy-ip", "X-Forwarded-Uri"],
                "vulnerable_parameters": ["X-Forwarded-Uri"],
            }

            git = GitTools(Path(tmp) / "cache")
            git.ensure_repo = lambda owner, name: repo  # type: ignore[method-assign]
            ReleaseFixFinder(git, FakeGitHubTools()).find(advisory, result)
            self.assertEqual(result.fix_commit.value, fix)
            self.assertEqual(result.fix_pr.value, "owner/repo#7")

    def _git(self, repo: Path, *args: str) -> str:
        env = os.environ.copy()
        env.update(
            {
                "GIT_AUTHOR_NAME": "Test User",
                "GIT_AUTHOR_EMAIL": "test@example.com",
                "GIT_COMMITTER_NAME": "Test User",
                "GIT_COMMITTER_EMAIL": "test@example.com",
            }
        )
        result = subprocess.run(
            ["git", *args],
            cwd=repo,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return result.stdout


if __name__ == "__main__":
    unittest.main()
