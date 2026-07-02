from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from advisory_miner.agents.sanity_validator import SanityValidator
from advisory_miner.confidence import calibrated_confidence
from advisory_miner.models import AnalysisResult, Evidence, Finding
from advisory_miner.tools.git_tools import GitTools


class ConfidenceTests(unittest.TestCase):
    def test_groups_require_distinct_evidence_for_high_introducer_confidence(self):
        finding = Finding(
            value="abc",
            confidence="medium",
            evidence=[
                Evidence("introducer_classifier", "verdict=introduced"),
                Evidence("validator", "candidate is ancestor"),
            ],
        )
        confidence, groups = calibrated_confidence(finding, preserve_direct_high=False)
        self.assertEqual(confidence, "high")
        self.assertTrue(groups.code_content)
        self.assertTrue(groups.history_topology)

    def test_single_history_signal_is_low(self):
        finding = Finding(
            value="abc",
            confidence="medium",
            evidence=[Evidence("introducer_finder", "git blame attributed one line")],
        )
        confidence, _ = calibrated_confidence(finding, preserve_direct_high=False)
        self.assertEqual(confidence, "low")


class SanityValidatorTests(unittest.TestCase):
    def test_rejects_merge_like_introducer_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            self._git(repo, "init")
            self._git(repo, "config", "user.email", "test@example.com")
            self._git(repo, "config", "user.name", "Test User")
            (repo / "a.txt").write_text("a\n", encoding="utf-8")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "initial")
            (repo / "a.txt").write_text("b\n", encoding="utf-8")
            self._git(repo, "commit", "-am", "Merge branch feature")
            merge_like = self._git(repo, "rev-parse", "HEAD").strip()
            (repo / "a.txt").write_text("c\n", encoding="utf-8")
            self._git(repo, "commit", "-am", "fix vulnerability")
            fix = self._git(repo, "rev-parse", "HEAD").strip()

            result = AnalysisResult(ghsa_id="GHSA-test-test-test")
            result.repository = Finding(value="owner/repo", confidence="high")
            result.fix_commit = Finding(value=fix, confidence="high", evidence=[Evidence("collector", "direct")])
            result.introduced_commit = Finding(
                value=merge_like,
                confidence="medium",
                evidence=[Evidence("introducer_finder", "blame")],
            )

            git = GitTools(Path(tmp) / "cache")
            git.ensure_repo = lambda owner, name: repo  # type: ignore[method-assign]
            SanityValidator(git).validate(result)
            self.assertIsNone(result.introduced_commit.value)
            self.assertEqual(result.introduced_commit.confidence, "unknown")

    def test_rejects_fix_commit_with_unrelated_verifier_verdict(self):
        result = AnalysisResult(ghsa_id="GHSA-test-test-test")
        result.repository = Finding(value="owner/repo", confidence="high")
        result.fix_commit = Finding(
            value="a" * 40,
            confidence="medium",
            evidence=[Evidence("fix_verifier", "verdict=unrelated; this fixes a different issue")],
        )
        result.fix_pr = Finding(value="owner/repo#1", confidence="medium")
        result.introduced_commit = Finding(value="b" * 40, confidence="medium")
        SanityValidator().validate(result, skip_git=True)
        self.assertIsNone(result.fix_commit.value)
        self.assertEqual(result.fix_commit.confidence, "unknown")
        self.assertIsNone(result.fix_pr.value)
        self.assertIsNone(result.introduced_commit.value)

    def test_keeps_single_parent_fix_with_bad_subject_and_source_diff_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            self._git(repo, "init")
            self._git(repo, "config", "user.email", "test@example.com")
            self._git(repo, "config", "user.name", "Test User")
            (repo / "a.go").write_text("package main\n", encoding="utf-8")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "initial")
            (repo / "a.go").write_text("package main\n// trusted proxy fix\n", encoding="utf-8")
            self._git(repo, "commit", "-am", "Merge commit from fork")
            fix = self._git(repo, "rev-parse", "HEAD").strip()

            result = AnalysisResult(ghsa_id="GHSA-test-test-test")
            result.repository = Finding(value="owner/repo", confidence="high")
            result.fix_commit = Finding(
                value=fix,
                confidence="medium",
                evidence=[Evidence("release_fix_finder", "parsed advisory patterns in source diff: trusted-proxy-ip")],
            )
            git = GitTools(Path(tmp) / "cache")
            git.ensure_repo = lambda owner, name: repo  # type: ignore[method-assign]
            SanityValidator(git).validate(result)
            self.assertEqual(result.fix_commit.value, fix)
            self.assertNotEqual(result.fix_commit.confidence, "unknown")

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
