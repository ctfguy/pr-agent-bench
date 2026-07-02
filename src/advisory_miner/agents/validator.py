from __future__ import annotations

from advisory_miner.models import AnalysisResult, CandidateCommit, Evidence, Finding
from advisory_miner.tools.git_tools import GitTools


class Validator:
    def __init__(self, git: GitTools | None = None):
        self.git = git

    def validate(self, result: AnalysisResult, skip_git: bool = False) -> AnalysisResult:
        if not result.repository.value:
            self._unknown_fix(result, "No verified GitHub repository is available.")
            self._unknown_introducer(result, "No verified GitHub repository is available.")
            return result

        if not result.fix_commit.value:
            self._unknown_introducer(result, "No fixing commit is available, so introducer analysis cannot be supported.")
            return result

        if result.introduced_commit.value and not skip_git and self.git:
            owner, repo = result.repository.value.split("/", 1)
            try:
                repo_path = self.git.ensure_repo(owner, repo)
                self.git.ensure_commit(repo_path, result.fix_commit.value)
                self.git.ensure_commit(repo_path, result.introduced_commit.value)
                if not self.git.is_ancestor(repo_path, result.introduced_commit.value, result.fix_commit.value):
                    recovered = self._recover_ancestor_introducer(result, repo_path)
                    if recovered:
                        result.limitations.append(
                            "Selected introducer candidate was not an ancestor of the fix; recovered a lower-ranked source-backed ancestor candidate."
                        )
                    else:
                        result.limitations.append("Top introducer candidate is not an ancestor of the selected fix commit; downgraded to unknown.")
                        self._unknown_introducer(result, "Candidate failed ancestor validation.")
                else:
                    result.introduced_commit.evidence.append(
                        Evidence("validator", "Introducer candidate is an ancestor of the selected fixing commit.")
                    )
            except Exception as exc:
                result.limitations.append(f"Introducer ancestor validation could not be completed: {exc}")

        return result

    def _unknown_fix(self, result: AnalysisResult, reason: str) -> None:
        if result.fix_commit.confidence == "unknown":
            result.limitations.append(reason)

    def _unknown_introducer(self, result: AnalysisResult, reason: str) -> None:
        result.introduced_commit.value = None
        result.introduced_commit.url = None
        result.introduced_commit.confidence = "unknown"
        result.introduced_commit.evidence = [Evidence("validator", reason)]

    def _recover_ancestor_introducer(self, result: AnalysisResult, repo_path) -> bool:
        if not self.git or not result.fix_commit.value or not result.repository.value:
            return False
        owner, repo = result.repository.value.split("/", 1)
        patterns = _semantic_patterns(result.parsed_advisory)
        if not patterns or not result.introducer_candidates:
            return False
        bad_value = result.introduced_commit.value
        best: tuple[float, CandidateCommit, list[str], str] | None = None
        for candidate in result.introducer_candidates[:10]:
            if candidate.sha == bad_value:
                continue
            try:
                self.git.ensure_commit(repo_path, candidate.sha)
                if not self.git.is_ancestor(repo_path, candidate.sha, result.fix_commit.value):
                    continue
                diff = self.git.commit_diff_around_patterns(
                    repo_path,
                    candidate.sha,
                    patterns,
                    files=candidate.files[:6],
                    context_lines=40,
                    max_chars=30000,
                )
            except Exception:
                continue
            score, matched = _candidate_recovery_score(candidate, patterns, diff)
            if score <= 0:
                continue
            if best is None or score > best[0]:
                best = (score, candidate, matched, diff)
        if best is None:
            return False
        score, candidate, matched, diff = best
        confidence = "high" if score >= 220 else "medium"
        result.introduced_commit = Finding(
            value=candidate.sha,
            url=f"https://github.com/{owner}/{repo}/commit/{candidate.sha}",
            confidence=confidence,
            evidence=[
                Evidence(
                    "validator_recovery",
                    (
                        "Recovered source-backed ancestor after invalid finalist. "
                        f"matched_patterns={matched[:8]}; candidate_score={candidate.score}; "
                        f"subject={candidate.subject}; diff_excerpt={_excerpt(diff, matched)[:420]}"
                    ),
                ),
                Evidence("validator", "Recovered introducer candidate is an ancestor of the selected fixing commit."),
            ],
        )
        result.introduced_pr = Finding(
            confidence="unknown",
            evidence=[Evidence("validator_recovery", "Introducer PR left unknown; recovered commit needs commit-to-pulls lookup in a later resolver pass.")],
        )
        return True


def _semantic_patterns(parsed: dict | None) -> list[str]:
    if not isinstance(parsed, dict):
        return []
    raw: list[str] = []
    for key in ("high_signal_search_patterns", "vulnerable_functions", "vulnerable_parameters"):
        raw.extend(str(item) for item in parsed.get(key) or [] if item)
    seen: set[str] = set()
    patterns: list[str] = []
    for item in raw:
        lowered = item.lower()
        if lowered not in seen and len(lowered) >= 3:
            seen.add(lowered)
            patterns.append(item)
    return patterns


def _candidate_recovery_score(candidate: CandidateCommit, patterns: list[str], diff: str) -> tuple[float, list[str]]:
    pattern_lowers = {pattern.lower(): pattern for pattern in patterns}
    matched = []
    for pattern in candidate.matched_patterns:
        lowered = pattern.lower()
        if lowered in pattern_lowers:
            matched.append(pattern_lowers[lowered])
    diff_lower = diff.lower()
    for lowered, original in pattern_lowers.items():
        if lowered in diff_lower and original not in matched:
            matched.append(original)
    exact_score = 55 * len(matched)
    dangerous_combo = sum(
        token in diff_lower
        for token in (
            "strings.hasprefix",
            "strings.trimprefix",
            "path.join",
            "r.noroute",
            "servefile",
            "localfilepath",
            "strippath",
        )
    )
    combo_score = 35 * dangerous_combo
    score = exact_score + combo_score + min(candidate.score, 200) * 0.2
    subject = (candidate.subject or "").lower()
    if subject.startswith(("revert", "test", "docs", "chore")):
        score -= 80
    if len(matched) < 2 and dangerous_combo < 2:
        return 0, matched
    return score, matched


def _excerpt(diff: str, matched: list[str]) -> str:
    if not diff:
        return ""
    lowered = diff.lower()
    for pattern in matched:
        index = lowered.find(pattern.lower())
        if index >= 0:
            start = max(0, index - 180)
            end = min(len(diff), index + 500)
            return diff[start:end].replace("\n", " ")
    return diff[:700].replace("\n", " ")
