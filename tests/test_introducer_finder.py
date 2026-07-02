from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from advisory_miner.agents.introducer_finder import IntroducerFinder, affected_lower_bound_versions
from advisory_miner.models import CandidateCommit
from advisory_miner.tools.git_tools import GitTools


class FakeGitHubTools:
    def commit_pulls(self, owner, repo, sha):
        return []


class IntroducerFinderTests(unittest.TestCase):
    def test_affected_lower_bound_versions_extracts_ranges(self):
        advisory = {
            "vulnerabilities": [
                {"vulnerable_version_range": ">= 7.5.0, < 7.15.2"},
                {"vulnerable_version_range": "[1.2.3, 2.0.0)"},
            ],
            "enriched_refs": {
                "osv_affected_packages": [
                    {"ranges": [{"type": "SEMVER", "introduced": "3.4.5", "fixed": "3.4.6"}]},
                    {"ranges": [{"type": "GIT", "introduced": "0"}]},
                ]
            },
        }

        self.assertEqual(affected_lower_bound_versions(advisory), ["7.5.0", "1.2.3", "3.4.5"])

    def test_lower_bound_scoring_demotes_prerequisite_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            self._git(repo, "init")
            self._git(repo, "config", "user.email", "test@example.com")
            self._git(repo, "config", "user.name", "Test User")

            file_path = repo / "oauthproxy.go"
            file_path.write_text("package main\nconst TrustedIPs = true\n", encoding="utf-8")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "Implements trusted IP option")
            old_prerequisite = self._git(repo, "rev-parse", "HEAD").strip()
            self._git(repo, "tag", "v7.4.0")

            file_path.write_text(
                "package main\n"
                "const TrustedIPs = true\n"
                "const XForwardedURI = \"X-Forwarded-Uri\"\n"
                "func isAllowedPath() string { return XForwardedURI }\n",
                encoding="utf-8",
            )
            self._git(repo, "commit", "-am", "fix: use X-Forwarded-Uri for pathRegex match")
            actual_intro = self._git(repo, "rev-parse", "HEAD").strip()
            self._git(repo, "tag", "v7.5.0")

            file_path.write_text(
                "package main\n"
                "const TrustedIPs = true\n"
                "const XForwardedURI = \"X-Forwarded-Uri\"\n"
                "const TrustedProxyIP = \"trusted-proxy-ip\"\n"
                "func isAllowedPath() string { return TrustedProxyIP + XForwardedURI }\n",
                encoding="utf-8",
            )
            self._git(repo, "commit", "-am", "fix: require trusted-proxy-ip")
            later_fix = self._git(repo, "rev-parse", "HEAD").strip()

            git = GitTools(Path(tmp) / "cache")
            finder = IntroducerFinder(git, FakeGitHubTools())
            candidates = [
                CandidateCommit(sha=old_prerequisite, score=150, subject="Implements trusted IP option"),
                CandidateCommit(sha=actual_intro, score=10, subject="fix: use X-Forwarded-Uri for pathRegex match"),
                CandidateCommit(sha=later_fix, score=100, subject="fix: require trusted-proxy-ip"),
            ]

            finder._apply_lower_bound_scoring(candidates, [("v7.4.0", "v7.5.0", "7.5.0")], repo)
            candidates.sort(key=lambda item: item.score, reverse=True)

            self.assertEqual(candidates[0].sha, actual_intro)
            self.assertTrue(any("first affected version" in reason for reason in candidates[0].reasons))
            old = next(item for item in candidates if item.sha == old_prerequisite)
            self.assertTrue(any("predates all first-affected" in reason for reason in old.reasons))

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
