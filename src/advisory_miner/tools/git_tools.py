from __future__ import annotations

import os
import re
import subprocess
import threading
from collections import Counter, defaultdict
from pathlib import Path

from advisory_miner.models import CandidateCommit


HUNK_RE = re.compile(r"@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@")
BLAME_RE = re.compile(r"^\^?(?P<sha>[0-9a-f]{40})\s+\d+\s+\d+(?:\s+(?P<count>\d+))?")
REFACTOR_SUBJECT_RE = re.compile(
    r"^(?:move|rename|refactor|reorganize|reorganise|split|extract|relocate|migrate|restructure)\b",
    re.IGNORECASE,
)


class GitTools:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self._locks: dict[str, threading.Lock] = defaultdict(threading.Lock)

    def ensure_repo(self, owner: str, repo: str) -> Path:
        key = f"{owner}__{repo}".replace("/", "__")
        path = self.cache_dir / key
        with self._locks[key]:
            if (path / ".git").exists():
                return path
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._git(["clone", "--filter=blob:none", "--no-checkout", f"https://github.com/{owner}/{repo}.git", str(path)], None, 600)
            return path

    def ensure_commit(self, repo_path: Path, sha: str) -> None:
        if self._git_success(repo_path, ["cat-file", "-e", f"{sha}^{{commit}}"]):
            return
        self._git(["fetch", "--filter=blob:none", "origin", sha], repo_path, 300)
        self._git(["cat-file", "-e", f"{sha}^{{commit}}"], repo_path, 60)

    def first_parent(self, repo_path: Path, sha: str) -> str | None:
        try:
            return self._git(["rev-parse", f"{sha}^1"], repo_path, 60).strip()
        except RuntimeError:
            return None

    def commit_subject(self, repo_path: Path, sha: str) -> str | None:
        try:
            return self._git(["show", "-s", "--format=%s", sha], repo_path, 60).strip()
        except RuntimeError:
            return None

    def commit_message(self, repo_path: Path, sha: str) -> str:
        return self._git(["show", "-s", "--format=%B", sha], repo_path, 60)

    def commit_diff(self, repo_path: Path, sha: str, unified: int = 20, max_chars: int = 80000) -> str:
        output = self._git(["show", f"--unified={unified}", "--find-renames", "--no-ext-diff", "--no-color", "--format=medium", sha], repo_path, 180)
        return output[:max_chars]

    def commit_diff_for_files(self, repo_path: Path, sha: str, files: list[str], unified: int = 6, max_chars: int = 40000) -> str:
        if not files:
            return ""
        output = self._git(
            ["show", f"--unified={unified}", "--find-renames", "--no-ext-diff", "--no-color", "--format=medium", sha, "--", *files],
            repo_path,
            180,
        )
        return output[:max_chars]

    def commit_diff_around_patterns(
        self,
        repo_path: Path,
        sha: str,
        patterns: list[str],
        files: list[str] | None = None,
        context_lines: int = 80,
        max_chars: int = 50000,
    ) -> str:
        """Return commit diff sections around advisory-relevant patterns.

        This is intentionally evidence-heavy: large commits are common in real
        advisories, so agents need the source hunks that mention vulnerable
        functions/endpoints instead of the first N bytes of the whole commit.
        """
        diff = self.commit_diff_for_files(repo_path, sha, files or self.touched_files(repo_path, sha), unified=20, max_chars=250000)
        if not patterns:
            return diff[:max_chars]
        lowered_patterns = [pattern.lower() for pattern in patterns if pattern]
        lines = diff.splitlines()
        selected: set[int] = set()
        for index, line in enumerate(lines):
            lowered = line.lower()
            if any(pattern in lowered for pattern in lowered_patterns):
                start = max(0, index - context_lines)
                end = min(len(lines), index + context_lines + 1)
                selected.update(range(start, end))
        if not selected:
            return diff[:max_chars]
        chunks: list[str] = []
        previous = -2
        for index in sorted(selected):
            if index != previous + 1:
                chunks.append("\n--- matched hunk ---")
            chunks.append(lines[index])
            previous = index
        return "\n".join(chunks)[:max_chars]

    def show_file_at_commit(self, repo_path: Path, sha: str, file_path: str, max_chars: int = 80000) -> str:
        output = self._git(["show", f"{sha}:{file_path}"], repo_path, 120)
        return output[:max_chars]

    def compare_file_before_after(self, repo_path: Path, sha: str, file_path: str, max_chars: int = 80000) -> dict[str, str]:
        parent = self.first_parent(repo_path, sha)
        before = ""
        if parent:
            try:
                before = self.show_file_at_commit(repo_path, parent, file_path, max_chars=max_chars // 2)
            except RuntimeError:
                before = ""
        try:
            after = self.show_file_at_commit(repo_path, sha, file_path, max_chars=max_chars // 2)
        except RuntimeError:
            after = ""
        return {"sha": sha, "file": file_path, "before": before, "after": after}

    def pickaxe_search_many(
        self,
        repo_path: Path,
        rev: str,
        patterns: list[str],
        files: list[str] | None = None,
        limit_per_pattern: int = 40,
    ) -> dict[str, list[dict[str, str | int | list[str]]]]:
        return {
            pattern: [candidate.to_dict() for candidate in self.pickaxe_search(repo_path, rev, pattern, files or [], limit=limit_per_pattern)]
            for pattern in patterns
            if pattern
        }

    def touched_files(self, repo_path: Path, sha: str) -> list[str]:
        output = self._git(["diff-tree", "--no-commit-id", "--name-only", "-r", sha], repo_path, 120)
        return [line for line in output.splitlines() if line and not self._skip_path(line)]

    def file_history(self, repo_path: Path, rev: str, files: list[str], limit: int = 500) -> list[CandidateCommit]:
        commits: dict[str, CandidateCommit] = {}
        for file_path in files:
            try:
                output = self._git(["log", f"--max-count={limit}", "--format=%H%x09%s", rev, "--", file_path], repo_path, 180)
            except RuntimeError:
                continue
            for line in output.splitlines():
                sha, _, subject = line.partition("\t")
                if not sha:
                    continue
                candidate = commits.setdefault(
                    sha,
                    CandidateCommit(sha=sha, subject=subject, strategies=["file_history"]),
                )
                if file_path not in candidate.files:
                    candidate.files.append(file_path)
        return list(commits.values())

    def pickaxe_search(self, repo_path: Path, rev: str, pattern: str, files: list[str], regex: bool = False, limit: int = 80) -> list[CandidateCommit]:
        flag = "-G" if regex else "-S"
        args = ["log", f"--max-count={limit}", "--format=%H%x09%s", flag, pattern, rev]
        if files:
            args.extend(["--", *files])
        try:
            output = self._git(args, repo_path, 180)
        except RuntimeError:
            return []
        results = []
        for line in output.splitlines():
            sha, _, subject = line.partition("\t")
            if sha:
                results.append(
                    CandidateCommit(
                        sha=sha,
                        subject=subject,
                        matched_patterns=[pattern],
                        strategies=["pickaxe"],
                    )
                )
        return results

    def blame_deleted_lines(self, repo_path: Path, fix_sha: str, files: list[str], max_ranges: int = 80) -> list[CandidateCommit]:
        parent = self.first_parent(repo_path, fix_sha)
        if not parent:
            return []
        ranges = self._deleted_ranges(repo_path, parent, fix_sha, files)[:max_ranges]
        counts: Counter[str] = Counter()
        touched: dict[str, set[str]] = defaultdict(set)
        for path, start, end in ranges:
            try:
                output = self._git(["blame", "--porcelain", "-L", f"{start},{end}", parent, "--", path], repo_path, 120)
            except RuntimeError:
                continue
            for line in output.splitlines():
                match = BLAME_RE.match(line)
                if not match:
                    continue
                sha = match.group("sha")
                count = int(match.group("count") or "1")
                counts[sha] += count
                touched[sha].add(path)
        candidates = []
        for sha, count in counts.most_common(20):
            candidates.append(
                CandidateCommit(
                    sha=sha,
                    score=count * 6,
                    subject=self.commit_subject(repo_path, sha),
                    reasons=[f"git blame attributed {count} removed/modified line(s) from the fix parent to this commit"],
                    files=sorted(touched[sha]),
                    strategies=["classical_blame"],
                )
            )
        return candidates

    def is_refactor_commit(self, repo_path: Path, sha: str) -> bool:
        """Heuristic check: is this commit primarily a rename/move/refactor?

        Two signals — either is sufficient:
        - Subject starts with a refactor-keyword (move/rename/refactor/...)
        - Rename ratio in name-status >= 60% of all touched paths
        """
        subject = (self.commit_subject(repo_path, sha) or "").strip()
        if REFACTOR_SUBJECT_RE.match(subject):
            return True
        try:
            output = self._git(
                ["diff", "--name-status", "--find-renames=70", f"{sha}^", sha],
                repo_path,
                60,
            )
        except RuntimeError:
            return False
        entries = [line for line in output.splitlines() if line.strip()]
        if len(entries) < 3:
            return False
        renamed = sum(1 for line in entries if line.startswith("R"))
        return (renamed / len(entries)) >= 0.6

    def find_rename_old_path(self, repo_path: Path, sha: str, new_path: str) -> str | None:
        """Look at sha's name-status; if `new_path` was the target of a rename, return the old path."""
        try:
            output = self._git(
                ["diff", "--name-status", "--find-renames=70", f"{sha}^", sha],
                repo_path,
                60,
            )
        except RuntimeError:
            return None
        for line in output.splitlines():
            if not line or not line.startswith("R"):
                continue
            parts = line.split("\t")
            if len(parts) >= 3 and parts[2] == new_path:
                return parts[1]
        return None

    def rename_chase_candidates(
        self,
        repo_path: Path,
        refactor_sha: str,
        fix_sha: str,
        fix_files: list[str],
        patterns: list[str],
        limit: int = 100,
    ) -> list[CandidateCommit]:
        """Find candidate introducers in the pre-refactor history.

        When classical SZZ lands on a rename/move/refactor commit, two things
        may have happened:
          1. An R-style rename: the new file existed under another path before
             the refactor. Walk that old path's history.
          2. The "moved" code was actually extracted out of a sibling file
             that the refactor *modified* (M status) without git recording a
             rename. Walk those modified files' histories.

        Pickaxe with fix-derived patterns highlights commits in those histories
        that touched the same code constructs as the fix.
        """
        parent = self.first_parent(repo_path, refactor_sha)
        if not parent:
            return []
        try:
            output = self._git(
                ["diff", "--name-status", "--find-renames=70", f"{refactor_sha}^", refactor_sha],
                repo_path,
                60,
            )
        except RuntimeError:
            return []

        fix_files_set = set(fix_files)
        source_files: list[tuple[str, str]] = []
        for line in output.splitlines():
            if not line.strip():
                continue
            if line.startswith("R"):
                parts = line.split("\t")
                if len(parts) >= 3:
                    source_files.append((parts[1], f"renamed_to_{parts[2]}"))
            elif line.startswith("M\t"):
                parts = line.split("\t", 1)
                if len(parts) < 2:
                    continue
                path = parts[1]
                if path in fix_files_set or self._skip_path(path):
                    continue
                source_files.append((path, "modified_in_refactor"))

        if not source_files:
            return []

        candidates: list[CandidateCommit] = []
        for src_path, role in source_files:
            for pattern in patterns[:16]:
                for cc in self.pickaxe_search(repo_path, parent, pattern, [src_path], limit=30):
                    cc.score += 10
                    cc.reasons.append(
                        f"Rename-chased pattern '{pattern}' on {src_path} ({role}) before refactor {refactor_sha[:12]}"
                    )
                    if pattern not in cc.matched_patterns:
                        cc.matched_patterns.append(pattern)
                    if "rename_chase" not in cc.strategies:
                        cc.strategies.append("rename_chase")
                    if src_path not in cc.files:
                        cc.files.append(src_path)
                    candidates.append(cc)
        return candidates

    def previous_release_tag(self, repo_path: Path, version: str) -> tuple[str, str] | None:
        """Map `version` (advisory's first_patched_version) to (prev_tag, current_tag).

        Tries the version verbatim and with common prefixes (v/V). Returns None when
        the version is not a known tag, or there is no chronologically prior tag.
        """
        tags = self._tags(repo_path, "--sort=-creatordate")
        if not tags:
            tags = self._tags(repo_path, "--sort=-v:refname")
        if not tags:
            return None
        current_tag = None
        for variant in (version, f"v{version}", f"V{version}"):
            if variant in tags:
                current_tag = variant
                break
        if current_tag is None:
            return None
        idx = tags.index(current_tag)
        if idx + 1 < len(tags):
            return tags[idx + 1], current_tag

        version_tags = self._tags(repo_path, "--sort=-v:refname")
        if current_tag in version_tags:
            idx = version_tags.index(current_tag)
            if idx + 1 < len(version_tags):
                return version_tags[idx + 1], current_tag
        return None

    def _tags(self, repo_path: Path, sort_arg: str) -> list[str]:
        try:
            output = self._git(["tag", sort_arg], repo_path, 60)
        except RuntimeError:
            return []
        return [t.strip() for t in output.splitlines() if t.strip()]

    def range_file_history(
        self,
        repo_path: Path,
        rev_range: str,
        files: list[str],
        limit: int = 200,
    ) -> list[CandidateCommit]:
        """Return commits that touched any of `files` within `rev_range` (e.g. `prev_tag..fix^`)."""
        commits: dict[str, CandidateCommit] = {}
        for file_path in files:
            try:
                output = self._git(
                    ["log", f"--max-count={limit}", "--format=%H%x09%s", rev_range, "--", file_path],
                    repo_path,
                    180,
                )
            except RuntimeError:
                continue
            for line in output.splitlines():
                sha, _, subject = line.partition("\t")
                if not sha:
                    continue
                candidate = commits.setdefault(
                    sha,
                    CandidateCommit(
                        sha=sha,
                        subject=subject,
                        strategies=["tag_bracket"],
                    ),
                )
                if file_path not in candidate.files:
                    candidate.files.append(file_path)
                if not candidate.reasons:
                    candidate.reasons.append(f"Touched within fix range {rev_range}")
        return list(commits.values())

    def commits_in_range(self, repo_path: Path, rev_range: str, limit: int = 200) -> list[CandidateCommit]:
        try:
            output = self._git(
                ["log", f"--max-count={limit}", "--format=%H%x09%s", rev_range],
                repo_path,
                180,
            )
        except RuntimeError:
            return []
        commits: list[CandidateCommit] = []
        for line in output.splitlines():
            sha, _, subject = line.partition("\t")
            if sha:
                commits.append(CandidateCommit(sha=sha, subject=subject, strategies=["release_tag_range"]))
        return commits

    def is_ancestor(self, repo_path: Path, ancestor: str, descendant: str) -> bool:
        return self._git_success(repo_path, ["merge-base", "--is-ancestor", ancestor, descendant])

    def parent_count(self, repo_path: Path, sha: str) -> int:
        try:
            output = self._git(["rev-list", "--parents", "-n", "1", sha], repo_path, 60).strip()
        except RuntimeError:
            return 0
        return max(0, len(output.split()) - 1)

    def _deleted_ranges(self, repo_path: Path, parent: str, fix_sha: str, files: list[str]) -> list[tuple[str, int, int]]:
        ranges: list[tuple[str, int, int]] = []
        diff = self._git(["diff", "--unified=0", "--find-renames", parent, fix_sha, "--", *files], repo_path, 180)
        old_path: str | None = None
        for line in diff.splitlines():
            if line.startswith("--- "):
                old_path = self._diff_path(line[4:])
                continue
            match = HUNK_RE.search(line)
            if not match or not old_path or old_path == "/dev/null":
                continue
            old_count = int(match.group("old_count") or "1")
            if old_count <= 0:
                continue
            start = int(match.group("old_start"))
            ranges.append((old_path, start, start + old_count - 1))
        return ranges

    def _diff_path(self, raw: str) -> str:
        value = raw.strip().strip('"')
        return value[2:] if value.startswith(("a/", "b/")) else value

    def _skip_path(self, path: str) -> bool:
        lowered = path.lower()
        return (
            any(part in lowered for part in ("/test/", "/tests/", "test/", "tests/", "/docs/", "docs/"))
            or lowered.endswith((".md", ".rst", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".lock"))
        )

    def _git_success(self, repo_path: Path, args: list[str]) -> bool:
        try:
            self._git(args, repo_path, 60)
            return True
        except RuntimeError:
            return False

    def _git(self, args: list[str], cwd: Path | None, timeout: int) -> str:
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        try:
            process = subprocess.run(
                ["git", *args],
                cwd=str(cwd) if cwd else None,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            # Normalize to RuntimeError so the pickaxe / blame / file_history
            # call sites' `except RuntimeError: return []` paths catch this and
            # the analyzer keeps going instead of failing the whole advisory.
            raise RuntimeError(f"git {' '.join(args[:3])} timed out after {timeout}s") from exc
        if process.returncode != 0:
            raise RuntimeError(process.stderr.strip() or f"git {' '.join(args)} failed")
        return process.stdout
