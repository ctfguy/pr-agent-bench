from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from advisory_miner.agents.validator import Validator
from advisory_miner.models import AnalysisResult, CandidateCommit, Finding
from advisory_miner.tools.git_tools import GitTools


class ValidatorRecoveryTests(unittest.TestCase):
    def test_recovers_lower_ranked_semantic_ancestor_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            self._git(repo, "init")
            self._git(repo, "config", "user.email", "test@example.com")
            self._git(repo, "config", "user.name", "Test User")

            controller = repo / "cmd" / "dashboard" / "controller"
            controller.mkdir(parents=True)
            target = controller / "controller.go"
            target.write_text("package controller\n\nfunc setup() {}\n", encoding="utf-8")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "initial")
            initial = self._git(repo, "rev-parse", "HEAD").strip()

            target.write_text(
                "package controller\n\n"
                "func setup(r Router) {\n"
                "    r.NoRoute(fallbackToFrontend)\n"
                "}\n\n"
                "func fallbackToFrontend(c Context) {\n"
                "    if strings.HasPrefix(c.Request.URL.Path, \"/dashboard\") {\n"
                "        stripPath := strings.TrimPrefix(c.Request.URL.Path, \"/dashboard\")\n"
                "        localFilePath := path.Join(\"./admin-dist\", stripPath)\n"
                "        c.File(localFilePath)\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "feat: dev docker")
            good_intro = self._git(repo, "rev-parse", "HEAD").strip()

            target.write_text(
                target.read_text(encoding="utf-8")
                + "\nfunc commonHandler() {}\n",
                encoding="utf-8",
            )
            self._git(repo, "commit", "-am", "feat: generic helper")

            target.write_text(
                "package controller\n\n"
                "func setup(r Router) {\n"
                "    r.NoRoute(fallbackToFrontend)\n"
                "}\n\n"
                "func fallbackToFrontend(c Context) {\n"
                "    if strings.HasPrefix(c.Request.URL.Path, \"/dashboard/\") {\n"
                "        // safely serve only valid paths\n"
                "        checkLocalFileOrFs(c)\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            self._git(repo, "commit", "-am", "fix: dashboard path traversal")
            fix = self._git(repo, "rev-parse", "HEAD").strip()

            self._git(repo, "checkout", "-b", "side", initial)
            (repo / "side.go").write_text("package side\n\nfunc commonHandler() {}\n", encoding="utf-8")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "feat: unrelated side helper")
            unrelated = self._git(repo, "rev-parse", "HEAD").strip()
            self._git(repo, "checkout", "master")

            # Non-ancestor top candidate mirrors the observed failure: a
            # model/tool finalist that validator must reject and recover from.
            result = AnalysisResult(ghsa_id="GHSA-test")
            result.repository = Finding(value="owner/repo", confidence="high")
            result.fix_commit = Finding(value=fix, confidence="high")
            result.introduced_commit = Finding(value=unrelated, confidence="medium")
            result.parsed_advisory = {
                "high_signal_search_patterns": [
                    "r.NoRoute",
                    "strings.TrimPrefix(c.Request.URL.Path, \"/dashboard\")",
                    "path.Join",
                ],
                "vulnerable_functions": ["strings.HasPrefix", "strings.TrimPrefix"],
                "vulnerable_parameters": ["stripPath", "localFilePath"],
            }
            result.introducer_candidates = [
                CandidateCommit(sha=unrelated, score=300, subject="generic"),
                CandidateCommit(
                    sha=good_intro,
                    score=170,
                    subject="feat: dev docker",
                    matched_patterns=[
                        "r.NoRoute",
                        "strings.TrimPrefix(c.Request.URL.Path, \"/dashboard\")",
                        "strings.HasPrefix",
                        "path.Join",
                        "stripPath",
                        "localFilePath",
                    ],
                ),
            ]

            validator = Validator(GitTools(Path(tmp) / "cache"))
            # Use the repo path directly by monkeypatching ensure_repo to avoid
            # network access in this unit test.
            validator.git.ensure_repo = lambda owner, name: repo  # type: ignore[method-assign]
            validated = validator.validate(result)

            self.assertEqual(validated.introduced_commit.value, good_intro)
            self.assertTrue(any(ev.source == "validator_recovery" for ev in validated.introduced_commit.evidence))

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
