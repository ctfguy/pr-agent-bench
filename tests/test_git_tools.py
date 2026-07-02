from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from advisory_miner.tools.git_tools import GitTools


class GitToolsTests(unittest.TestCase):
    def test_blame_and_pickaxe_find_introducing_commit_candidates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "repo"
            repo.mkdir()
            self._git(repo, "init")
            self._git(repo, "config", "user.email", "test@example.com")
            self._git(repo, "config", "user.name", "Test User")
            src = repo / "src"
            src.mkdir()
            file_path = src / "audit.py"
            file_path.write_text(
                "def get_status(bundle):\n"
                "    sql = 'select * from audit where bundle=' + bundle\n"
                "    return sql\n",
                encoding="utf-8",
            )
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "add get_status audit query")
            introducing = self._git(repo, "rev-parse", "HEAD").strip()

            file_path.write_text(
                "def get_status(bundle):\n"
                "    sql = 'select * from audit where bundle=?'\n"
                "    return sql, [bundle]\n",
                encoding="utf-8",
            )
            self._git(repo, "commit", "-am", "fix: parameterize get_status audit query")
            fix = self._git(repo, "rev-parse", "HEAD").strip()
            parent = self._git(repo, "rev-parse", f"{fix}^1").strip()

            tools = GitTools(Path(temp_dir) / "cache")
            blame = tools.blame_deleted_lines(repo, fix, ["src/audit.py"])
            self.assertEqual(blame[0].sha, introducing)

            matches = tools.pickaxe_search(repo, parent, "get_status", ["src/audit.py"])
            self.assertTrue(any(item.sha == introducing for item in matches))

    def test_refactor_detection_and_rename_chase(self):
        """Simulate the eth-account-class failure: vulnerable code lives in file A,
        a later 'Move' commit extracts it into file B (A modified, B added with no
        R rename detected), then a fix patches file B. Classical blame on B lands
        on the move commit; refactor-aware chase must surface the real introducer
        from A's pre-refactor history."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "repo"
            repo.mkdir()
            self._git(repo, "init")
            self._git(repo, "config", "user.email", "test@example.com")
            self._git(repo, "config", "user.name", "Test User")

            # Commit 1: harmless baseline in signing.py
            signing = repo / "signing.py"
            signing.write_text("def sign(payload):\n    return payload\n", encoding="utf-8")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "initial signing skeleton")

            # Commit 2: TRUE INTRODUCER — adds the vulnerable regex to signing.py
            signing.write_text(
                "import re\n"
                "TYPE_REGEX = re.compile(r'.*')\n"
                "def sign(payload):\n"
                "    if not TYPE_REGEX.match(payload):\n"
                "        return None\n"
                "    return payload\n",
                encoding="utf-8",
            )
            self._git(repo, "commit", "-am", "Add error handling and validations")
            introducer = self._git(repo, "rev-parse", "HEAD").strip()

            # Commit 3: REFACTOR — Move the validation into a new utils/validation.py
            # without recording an R rename (Add new file + Modify old file).
            utils = repo / "utils"
            utils.mkdir()
            (utils / "__init__.py").write_text("", encoding="utf-8")
            (utils / "validation.py").write_text(
                "import re\n"
                "TYPE_REGEX = re.compile(r'.*')\n"
                "def validate(payload):\n"
                "    return bool(TYPE_REGEX.match(payload))\n",
                encoding="utf-8",
            )
            signing.write_text(
                "from utils.validation import validate\n"
                "def sign(payload):\n"
                "    if not validate(payload):\n"
                "        return None\n"
                "    return payload\n",
                encoding="utf-8",
            )
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "Move validation into separate utils module")
            refactor = self._git(repo, "rev-parse", "HEAD").strip()

            # Commit 4: FIX — patches the regex in utils/validation.py
            (utils / "validation.py").write_text(
                "import re\n"
                "TYPE_REGEX = re.compile(r'^[A-Za-z0-9_]+$')\n"
                "def validate(payload):\n"
                "    return bool(TYPE_REGEX.match(payload))\n",
                encoding="utf-8",
            )
            self._git(repo, "commit", "-am", "fix: tighten TYPE_REGEX validation")
            fix = self._git(repo, "rev-parse", "HEAD").strip()

            tools = GitTools(Path(temp_dir) / "cache")

            # The refactor commit must be classified as a refactor.
            self.assertTrue(tools.is_refactor_commit(repo, refactor))
            # The introducer commit must NOT be flagged as a refactor.
            self.assertFalse(tools.is_refactor_commit(repo, introducer))

            # Classical blame on the fix lands on the refactor (the failure mode).
            classical = tools.blame_deleted_lines(repo, fix, ["utils/validation.py"])
            self.assertEqual(classical[0].sha, refactor)

            # Refactor-aware chase must surface the true introducer from signing.py's
            # pre-refactor history.
            chased = tools.rename_chase_candidates(
                repo, refactor, fix, ["utils/validation.py"], ["TYPE_REGEX", "validate"]
            )
            self.assertIn(introducer, {cc.sha for cc in chased})
            # Strategies tag is set correctly on chased candidates.
            self.assertTrue(any("rename_chase" in cc.strategies for cc in chased if cc.sha == introducer))

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
