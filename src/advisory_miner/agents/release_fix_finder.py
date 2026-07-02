from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from advisory_miner.agents.fix_finder import SECURITY_TERMS, advisory_terms
from advisory_miner.models import AnalysisResult, Evidence, Finding, FixCandidate
from advisory_miner.tools.git_tools import GitTools
from advisory_miner.tools.github_tools import GitHubTools


class ReleaseFixFinder:
    def __init__(self, git: GitTools, github: GitHubTools, max_commits: int = 120):
        self.git = git
        self.github = github
        self.max_commits = max_commits

    def find(self, advisory: dict[str, Any], result: AnalysisResult, skip_git: bool = False) -> None:
        if skip_git or result.fix_commit.value or not result.repository.value:
            return
        versions = fixed_versions(advisory)
        if not versions:
            return
        owner, repo = result.repository.value.split("/", 1)
        try:
            repo_path = self.git.ensure_repo(owner, repo)
        except Exception as exc:
            result.errors.append(f"ReleaseFixFinder failed to clone repo: {exc}")
            return

        parsed = result.parsed_advisory or {}
        patterns = release_search_patterns(advisory, parsed)
        candidates: list[FixCandidate] = []
        for version in versions:
            tag_range = self.git.previous_release_tag(repo_path, version)
            if not tag_range:
                continue
            prev_tag, fixed_tag = tag_range
            for commit in self.git.commits_in_range(repo_path, f"{prev_tag}..{fixed_tag}", limit=self.max_commits):
                score, reasons = self._score_commit(repo_path, commit.sha, commit.subject or "", patterns)
                if score <= 0:
                    continue
                reasons.append(f"Candidate is in fixed-version range {prev_tag}..{fixed_tag}")
                candidates.append(
                    FixCandidate(
                        sha=commit.sha,
                        url=f"https://github.com/{owner}/{repo}/commit/{commit.sha}",
                        score=score,
                        reasons=reasons,
                        message=commit.subject,
                    )
                )

        if not candidates:
            return
        candidates.sort(key=lambda item: item.score, reverse=True)
        result.fix_candidates.extend(candidates[:5])
        best = candidates[0]
        result.fix_commit = Finding(
            value=best.sha,
            url=best.url,
            confidence="medium",
            evidence=[Evidence("release_fix_finder", "; ".join(best.reasons[:5]))],
        )
        pulls = self.github.commit_pulls(owner, repo, best.sha)
        if pulls:
            number = pulls[0].get("number")
            if number:
                result.fix_pr = Finding(
                    value=f"{owner}/{repo}#{number}",
                    url=pulls[0].get("html_url") or f"https://github.com/{owner}/{repo}/pull/{number}",
                    confidence="medium",
                    evidence=[Evidence("github_api", f"GitHub commit-to-pulls links release-range fix candidate to PR #{number}.")],
                )

    def _score_commit(self, repo_path: Path, sha: str, subject: str, patterns: list[str]) -> tuple[int, list[str]]:
        lowered = subject.lower()
        score = 0
        reasons: list[str] = []
        if lowered.startswith("merge ") or "merge branch" in lowered:
            score -= 20
            reasons.append("merge-like commit")
        if lowered.startswith(("docs", "doc", "chore", "ci", "release")):
            score -= 8
        if lowered.startswith("fix") or " fix" in lowered:
            score += 12
            reasons.append("commit message indicates a fix")
        matched_security = sorted(term for term in SECURITY_TERMS if term in lowered)
        if matched_security:
            score += min(15, 3 * len(matched_security))
            reasons.append(f"security terms in subject: {', '.join(matched_security[:5])}")
        matched_patterns = [p for p in patterns if p.lower() in lowered]
        if matched_patterns:
            score += min(20, 5 * len(matched_patterns))
            reasons.append(f"parsed advisory patterns in subject: {', '.join(matched_patterns[:5])}")
        semantic_files = [path for path in self.git.touched_files(repo_path, sha) if _is_semantic_source(path)]
        if semantic_files:
            try:
                semantic_diff = self.git.commit_diff_for_files(repo_path, sha, semantic_files, unified=6, max_chars=20000)
            except Exception:
                semantic_diff = ""
            semantic_matches = [p for p in patterns if p.lower() in semantic_diff.lower()]
            if semantic_matches:
                score += min(80, 16 * len(semantic_matches))
                reasons.append(f"parsed advisory patterns in source diff: {', '.join(semantic_matches[:6])}")
            score += 12
            reasons.append(f"touches semantic source files: {', '.join(semantic_files[:4])}")
        else:
            try:
                diff = self.git.commit_diff(repo_path, sha, unified=6, max_chars=12000)
            except Exception:
                diff = ""
            diff_matches = [p for p in patterns if p.lower() in diff.lower()]
            if diff_matches:
                score += min(15, 3 * len(diff_matches))
                reasons.append(f"parsed advisory patterns in non-source diff: {', '.join(diff_matches[:5])}")
            if lowered.startswith(("release", "docs", "doc", "chore")):
                score -= 12
        if re.search(r"\b(test|spec|regression)\b", lowered) and score < 30:
            score -= 6
        return score, reasons


def fixed_versions(advisory: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for vuln in advisory.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        patched = vuln.get("first_patched_version")
        if isinstance(patched, dict):
            patched = patched.get("identifier")
        if isinstance(patched, str) and patched and patched not in values:
            values.append(patched)
    enriched = advisory.get("enriched_refs") or {}
    for package in enriched.get("osv_affected_packages") or []:
        for range_item in package.get("ranges") or []:
            fixed = range_item.get("fixed")
            if isinstance(fixed, str) and fixed and fixed not in values:
                values.append(fixed)
    return values


def release_search_patterns(advisory: dict[str, Any], parsed: dict[str, Any]) -> list[str]:
    patterns: list[str] = []
    for key in ("high_signal_search_patterns", "vulnerable_functions", "vulnerable_parameters", "affected_endpoints"):
        for item in parsed.get(key) or []:
            if isinstance(item, str) and item and item not in patterns:
                patterns.append(item)
    if patterns:
        return patterns[:30]
    for term in sorted(advisory_terms(advisory)):
        if len(term) >= 6 and term not in patterns:
            patterns.append(term)
    return patterns[:30]


def _is_semantic_source(path: str) -> bool:
    lowered = path.lower()
    if lowered.endswith(("_test.go", ".test.js", ".spec.js", ".test.ts", ".spec.ts")):
        return False
    return lowered.endswith((
        ".go",
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".rb",
        ".php",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".rs",
    ))
