from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from advisory_miner.agents.patterns import derive_patterns
from advisory_miner.models import AnalysisResult, CandidateCommit, Evidence, Finding
from advisory_miner.tools.git_tools import GitTools
from advisory_miner.tools.github_tools import GitHubTools


class IntroducerFinder:
    def __init__(self, git: GitTools, github: GitHubTools, max_fix_candidates: int = 2):
        self.git = git
        self.github = github
        self.max_fix_candidates = max_fix_candidates

    def find(self, advisory: dict[str, Any], result: AnalysisResult, skip_git: bool = False) -> None:
        if skip_git:
            result.limitations.append("Introducer analysis skipped because --skip-git was used.")
            return
        if not result.repository.value or not result.fix_candidates:
            result.limitations.append("Introducer analysis requires a verified repository and at least one fixing commit candidate.")
            return

        owner, repo = result.repository.value.split("/", 1)
        try:
            repo_path = self.git.ensure_repo(owner, repo)
        except Exception as exc:
            result.errors.append(f"Failed to clone repository {owner}/{repo}: {exc}")
            return

        lower_bound_ranges = self._affected_lower_bound_tag_ranges(advisory, repo_path)
        aggregate: dict[str, CandidateCommit] = {}
        for fix in result.fix_candidates[: self.max_fix_candidates]:
            try:
                self._analyze_fix_candidate(
                    advisory,
                    result,
                    repo_path,
                    owner,
                    repo,
                    fix.sha,
                    aggregate,
                    lower_bound_ranges,
                )
            except Exception as exc:
                result.errors.append(f"Introducer analysis failed for fix candidate {fix.sha}: {exc}")

        # The aggregate can contain SHAs that are themselves fix candidates
        # (e.g. the selected fix commit appearing in the blame of a sibling
        # merge commit in the same PR). Those are not real introducers — drop
        # any candidate that matches a known fix-side SHA.
        fix_side_shas: set[str] = set()
        if result.fix_commit.value:
            fix_side_shas.add(result.fix_commit.value)
        fix_side_shas.update(c.sha for c in result.fix_candidates if c.sha)

        candidates = [
            item for item in sorted(aggregate.values(), key=lambda i: i.score, reverse=True)
            if item.sha not in fix_side_shas
        ]

        # Phase 4 multi-pattern AND-bonus: when a candidate matches >=2
        # distinct high-signal patterns from the parsed advisory, its score is
        # boosted because two independent terms agreeing is much stronger
        # evidence than one. The bonus is bounded so noise-prone candidates
        # don't dominate.
        parsed = advisory.get("parsed_advisory") if isinstance(advisory.get("parsed_advisory"), dict) else None
        if not parsed and isinstance(result.parsed_advisory, dict):
            parsed = result.parsed_advisory
        if parsed:
            high_signal = {p.lower() for p in (parsed.get("high_signal_search_patterns") or [])}
            high_signal |= {p.lower() for p in (parsed.get("vulnerable_functions") or [])}
            high_signal |= {p.lower() for p in (parsed.get("vulnerable_parameters") or [])}
            for cand in candidates:
                matched_high = {p.lower() for p in cand.matched_patterns if p.lower() in high_signal}
                if len(matched_high) >= 2:
                    bonus = min(140, 25 * len(matched_high))
                    cand.score += bonus
                    cand.reasons.append(
                        f"AND-bonus: matched {len(matched_high)} high-signal patterns: {sorted(matched_high)[:4]}"
                    )

        self._apply_lower_bound_scoring(candidates, lower_bound_ranges, repo_path)
        candidates.sort(key=lambda item: item.score, reverse=True)
        result.introducer_candidates = candidates[:10]
        if not candidates:
            result.limitations.append("No introducer candidates were found from blame or pattern search.")
            return

        best = candidates[0]
        confidence = "medium" if best.score >= 18 else "low"
        result.introduced_commit = Finding(
            value=best.sha,
            url=f"https://github.com/{owner}/{repo}/commit/{best.sha}",
            confidence=confidence,
            evidence=[Evidence("introducer_finder", reason) for reason in best.reasons[:6]],
        )
        pulls = self.github.commit_pulls(owner, repo, best.sha)
        if pulls:
            number = pulls[0].get("number")
            if number:
                result.introduced_pr = Finding(
                    value=f"{owner}/{repo}#{number}",
                    url=pulls[0].get("html_url") or f"https://github.com/{owner}/{repo}/pull/{number}",
                    confidence="medium",
                    evidence=[Evidence("github_api", f"Commit {best.sha} is linked to PR #{number} by GitHub commit-to-pulls API.")],
                )

    def _analyze_fix_candidate(
        self,
        advisory: dict[str, Any],
        result: AnalysisResult,
        repo_path: Path,
        owner: str,
        repo: str,
        fix_sha: str,
        aggregate: dict[str, CandidateCommit],
        lower_bound_ranges: list[tuple[str, str, str]],
    ) -> None:
        self.git.ensure_commit(repo_path, fix_sha)
        parent = self.git.first_parent(repo_path, fix_sha)
        if not parent:
            return
        message = self.git.commit_message(repo_path, fix_sha)
        diff = self.git.commit_diff(repo_path, fix_sha)
        files = self.git.touched_files(repo_path, fix_sha)
        if not files:
            return

        patterns = derive_patterns(message, diff, files, parsed=result.parsed_advisory)
        lower_bound_patterns = _lower_bound_semantic_patterns(result.parsed_advisory, patterns)

        # Stream 1: classical blame on deleted/modified lines.
        # When a candidate is itself a refactor/rename commit, demote it (zero
        # its score), chase the pre-rename history for the real introducer, and
        # record its SHA so later streams don't quietly re-score it from the
        # post-refactor file.
        classical = self.git.blame_deleted_lines(repo_path, fix_sha, files)
        demoted_refactors: set[str] = set()
        for candidate in classical:
            if self.git.is_refactor_commit(repo_path, candidate.sha):
                demoted_refactors.add(candidate.sha)
                candidate.score = 0
                candidate.reasons.append(
                    "Detected as refactor/rename commit; chasing pre-rename history instead"
                )
                if "classical_blame_refactor_demoted" not in candidate.strategies:
                    candidate.strategies.append("classical_blame_refactor_demoted")
                for chased in self.git.rename_chase_candidates(
                    repo_path, candidate.sha, fix_sha, files, patterns
                ):
                    self._merge_candidate(aggregate, chased, repo_path, fix_sha, source_bonus=0)
            self._merge_candidate(aggregate, candidate, repo_path, fix_sha, source_bonus=0)

        # Stream 2: pattern search on touched files before fix. Skip demoted
        # refactor SHAs so pickaxe-on-newly-added-file doesn't resurrect them.
        for pattern in patterns:
            for candidate in self.git.pickaxe_search(repo_path, parent, pattern, files):
                if candidate.sha in demoted_refactors:
                    continue
                candidate.score += 8
                candidate.reasons.append(
                    f"Pattern search matched '{pattern}' in touched-file history before fix {fix_sha[:12]}"
                )
                if pattern not in candidate.matched_patterns:
                    candidate.matched_patterns.append(pattern)
                self._merge_candidate(aggregate, candidate, repo_path, fix_sha, source_bonus=0)

        # Stream 3: file-touch history before fix; bonus when subject matches a fix pattern.
        for candidate in self.git.file_history(repo_path, parent, files, limit=300):
            if candidate.sha in demoted_refactors:
                continue
            subject = (candidate.subject or "").lower()
            for pattern in patterns[:10]:
                if pattern.lower() in subject:
                    candidate.score += 4
                    candidate.reasons.append(f"Commit subject matches fix-derived pattern '{pattern}'")
                    candidate.matched_patterns.append(pattern)
            if candidate.score:
                self._merge_candidate(aggregate, candidate, repo_path, fix_sha, source_bonus=0)

        # Stream 4: tag-bracket file history when the advisory carries a fixed_version
        # whose tag is known; bound search to `prev_tag..fix^`.
        for prev_tag, fix_tag in self._fix_version_tag_range(advisory, repo_path):
            for candidate in self.git.range_file_history(repo_path, f"{prev_tag}..{fix_sha}^", files, limit=200):
                lowered = (candidate.subject or "").lower()
                pattern_bonus = sum(2 for pattern in patterns[:12] if pattern.lower() in lowered)
                if pattern_bonus:
                    candidate.score += min(8, pattern_bonus)
                    candidate.reasons.append(
                        f"Tag-bracket commit subject overlaps fix patterns ({fix_tag} fixed, prev {prev_tag})"
                    )
                else:
                    candidate.score += 2
                    candidate.reasons.append(
                        f"Commit lies in {prev_tag}..{fix_sha[:12]}^ and touches fix files"
                    )
                self._merge_candidate(aggregate, candidate, repo_path, fix_sha, source_bonus=0)

        # Stream 5: first-affected-version window. If the advisory says the
        # affected range starts at a concrete release (e.g. >= 7.5.0), the real
        # introducer should normally land between the previous release and that
        # lower-bound release. This prevents older, related prerequisite commits
        # from winning just because they contain shared terminology.
        for prev_tag, lower_tag, lower_version in lower_bound_ranges:
            for candidate in self.git.range_file_history(repo_path, f"{prev_tag}..{lower_tag}", files, limit=300):
                lowered = (candidate.subject or "").lower()
                subject_matches = [pattern for pattern in lower_bound_patterns if pattern.lower() in lowered]
                try:
                    candidate_diff = self.git.commit_diff_for_files(repo_path, candidate.sha, files, unified=6, max_chars=12000)
                except Exception:
                    candidate_diff = ""
                diff_matches = [pattern for pattern in lower_bound_patterns if pattern.lower() in candidate_diff.lower()]
                matched = sorted(set(subject_matches + diff_matches))
                candidate.reasons.append(
                    f"Candidate lies in first-affected release window {prev_tag}..{lower_tag} from lower bound {lower_version}"
                )
                if matched:
                    candidate.score += 90 + min(60, 15 * len(matched))
                    candidate.reasons.append(
                        f"First-affected-window semantic overlap: {matched[:6]}"
                    )
                    if "affected_lower_bound_semantic" not in candidate.strategies:
                        candidate.strategies.append("affected_lower_bound_semantic")
                    for pattern in matched:
                        if pattern not in candidate.matched_patterns:
                            candidate.matched_patterns.append(pattern)
                else:
                    candidate.score += 5
                    candidate.reasons.append(
                        "First-affected-window file touch only; no semantic overlap with vulnerable construct"
                    )
                self._merge_candidate(aggregate, candidate, repo_path, fix_sha, source_bonus=0)

        strong_identifiers = _strong_fix_identifiers(diff)
        parsed_for_filter = result.parsed_advisory if isinstance(result.parsed_advisory, dict) else None
        if parsed_for_filter:
            parsed_signals = {p.lower() for p in (parsed_for_filter.get("high_signal_search_patterns") or [])}
            parsed_signals |= {p.lower() for p in (parsed_for_filter.get("vulnerable_functions") or [])}
            parsed_signals |= {p.lower() for p in (parsed_for_filter.get("vulnerable_parameters") or [])}
            strong_identifiers = {item for item in strong_identifiers if item.lower() in parsed_signals}
        for candidate in aggregate.values():
            matched = sorted({p for p in candidate.matched_patterns if p in strong_identifiers})
            if not matched:
                continue
            reason = f"Strong fix-diff identifier match: {matched[:4]}"
            if reason not in candidate.reasons:
                candidate.score += 80 + min(20, 10 * (len(matched) - 1))
                candidate.reasons.append(reason)

    def _fix_version_tag_range(
        self, advisory: dict[str, Any], repo_path: Path
    ) -> list[tuple[str, str]]:
        ranges: list[tuple[str, str]] = []
        seen: set[str] = set()
        for vuln in advisory.get("vulnerabilities") or []:
            patched = vuln.get("first_patched_version") if isinstance(vuln, dict) else None
            if isinstance(patched, dict):
                patched = patched.get("identifier")
            if not patched or patched in seen:
                continue
            seen.add(patched)
            mapping = self.git.previous_release_tag(repo_path, patched)
            if mapping:
                ranges.append(mapping)
        return ranges

    def _affected_lower_bound_tag_ranges(
        self, advisory: dict[str, Any], repo_path: Path
    ) -> list[tuple[str, str, str]]:
        ranges: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        for version in affected_lower_bound_versions(advisory):
            if version in seen:
                continue
            seen.add(version)
            mapping = self.git.previous_release_tag(repo_path, version)
            if mapping:
                prev_tag, lower_tag = mapping
                ranges.append((prev_tag, lower_tag, version))
        return ranges

    def _apply_lower_bound_scoring(
        self,
        candidates: list[CandidateCommit],
        lower_bound_ranges: list[tuple[str, str, str]],
        repo_path: Path,
    ) -> None:
        if not lower_bound_ranges:
            return
        for candidate in candidates:
            in_first_affected_window = False
            predates_all_lower_bounds = True
            after_any_lower_bound = False
            for prev_tag, lower_tag, lower_version in lower_bound_ranges:
                in_window = self.git.is_ancestor(repo_path, candidate.sha, lower_tag) and not self.git.is_ancestor(
                    repo_path, candidate.sha, prev_tag
                )
                if in_window:
                    in_first_affected_window = True
                    if "affected_lower_bound_semantic" in candidate.strategies:
                        candidate.score += 100
                    else:
                        candidate.score += 10
                    candidate.reasons.append(
                        f"Aligned with first affected version: present in {lower_tag} ({lower_version}) but not {prev_tag}"
                    )
                if not self.git.is_ancestor(repo_path, candidate.sha, prev_tag):
                    predates_all_lower_bounds = False
                if not self.git.is_ancestor(repo_path, candidate.sha, lower_tag):
                    after_any_lower_bound = True

            if in_first_affected_window:
                continue
            if predates_all_lower_bounds:
                candidate.score -= 1000
                candidate.reasons.append(
                    "Demoted: candidate predates all first-affected lower-bound tags, so it is likely a related prerequisite rather than the specific vulnerability introduction"
                )
            elif after_any_lower_bound:
                candidate.score -= 100
                candidate.reasons.append(
                    "Demoted: candidate appears after at least one first-affected lower-bound tag, which conflicts with the affected version range"
                )

    def _merge_candidate(self, aggregate: dict[str, CandidateCommit], candidate: CandidateCommit, repo_path: Path, fix_sha: str, source_bonus: int) -> None:
        if candidate.sha == fix_sha or not self.git.is_ancestor(repo_path, candidate.sha, fix_sha):
            return
        existing = aggregate.setdefault(candidate.sha, CandidateCommit(sha=candidate.sha, subject=candidate.subject))
        existing.score += candidate.score + source_bonus
        if not existing.subject:
            existing.subject = candidate.subject
        for reason in candidate.reasons:
            if reason not in existing.reasons:
                existing.reasons.append(reason)
        for pattern in candidate.matched_patterns:
            if pattern not in existing.matched_patterns:
                existing.matched_patterns.append(pattern)
        for file_path in candidate.files:
            if file_path not in existing.files:
                existing.files.append(file_path)
        for strategy in candidate.strategies:
            if strategy not in existing.strategies:
                existing.strategies.append(strategy)


def _strong_fix_identifiers(diff: str) -> set[str]:
    identifiers: set[str] = set()
    current_file = ""
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current_file = line.rsplit(" b/", 1)[-1] if " b/" in line else ""
            continue
        if _skip_identifier_file(current_file):
            continue
        if not line.startswith(("+", "-")) or line.startswith(("+++", "---")):
            continue
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{4,}", line):
            if _is_strong_identifier(token):
                identifiers.add(token)
    return identifiers


def _lower_bound_semantic_patterns(parsed: dict[str, Any] | None, fallback: list[str]) -> list[str]:
    patterns: list[str] = []
    if isinstance(parsed, dict):
        for key in ("high_signal_search_patterns", "vulnerable_functions", "vulnerable_parameters", "affected_endpoints"):
            for value in parsed.get(key) or []:
                if isinstance(value, str) and _is_lower_bound_signal(value) and value not in patterns:
                    patterns.append(value)
    if patterns:
        return patterns[:24]
    for value in fallback:
        if _is_lower_bound_signal(value) and value not in patterns:
            patterns.append(value)
    return patterns[:24]


def _is_lower_bound_signal(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    if len(stripped) < 4:
        return False
    if lowered in {"oauth", "oauth2", "auth", "proxy", "route", "request", "header", "config", "option", "http"}:
        return False
    return True


def affected_lower_bound_versions(advisory: dict[str, Any]) -> list[str]:
    versions: list[str] = []
    for vuln in advisory.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        for version in _lower_bounds_from_range(vuln.get("vulnerable_version_range")):
            if version not in versions:
                versions.append(version)

    enriched = advisory.get("enriched_refs") or {}
    if isinstance(enriched, dict):
        for package in enriched.get("osv_affected_packages") or []:
            if not isinstance(package, dict):
                continue
            for range_item in package.get("ranges") or []:
                if not isinstance(range_item, dict):
                    continue
                range_type = str(range_item.get("type") or "").upper()
                introduced = range_item.get("introduced")
                if range_type in {"SEMVER", "ECOSYSTEM"} and _looks_like_version(introduced):
                    if introduced != "0" and introduced not in versions:
                        versions.append(introduced)
    return versions


def _lower_bounds_from_range(value: Any) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return []
    lowered = value.strip()
    bounds: list[str] = []
    for match in re.finditer(r"(?:^|[\s,;])(?:>=|>|=)\s*v?([0-9]+(?:\.[0-9]+){0,3}(?:[-+][A-Za-z0-9_.-]+)?)", lowered):
        version = match.group(1)
        if version not in bounds:
            bounds.append(version)
    bracket = re.match(r"^[\[\(]\s*v?([0-9]+(?:\.[0-9]+){0,3}(?:[-+][A-Za-z0-9_.-]+)?)\s*,", lowered)
    if bracket and bracket.group(1) not in bounds:
        bounds.append(bracket.group(1))
    return bounds


def _looks_like_version(value: Any) -> bool:
    return isinstance(value, str) and re.match(r"^v?[0-9]+(?:\.[0-9]+){0,3}(?:[-+][A-Za-z0-9_.-]+)?$", value) is not None


def _skip_identifier_file(path: str) -> bool:
    lowered = path.lower()
    return any(part in lowered for part in ("/test/", "/tests/", "test/", "tests/", "spec/", "/spec/"))


def _is_strong_identifier(token: str) -> bool:
    if "_" in token and token.upper() == token:
        return True
    if "_" in token and len(token) >= 8:
        return True
    return any(ch.isupper() for ch in token[1:]) and len(token) >= 8
