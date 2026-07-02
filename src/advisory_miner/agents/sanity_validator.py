from __future__ import annotations

import re

from advisory_miner.confidence import calibrated_confidence
from advisory_miner.models import AnalysisResult, Evidence, Finding
from advisory_miner.tools.git_tools import GitTools


BAD_SUBJECT_RE = re.compile(
    r"^(?:merge|revert|bump|release|version|changelog|docs?|format|lint|test)(?:\b|:)",
    re.IGNORECASE,
)


class SanityValidator:
    def __init__(self, git: GitTools | None = None):
        self.git = git

    def validate(self, result: AnalysisResult, skip_git: bool = False) -> AnalysisResult:
        if _has_unrelated_fix_verdict(result.fix_commit):
            result.limitations.append("Fix candidate rejected because semantic verifier marked it unrelated.")
            result.fix_commit = Finding(
                confidence="unknown",
                evidence=[Evidence("sanity_validator", "fix_verifier verdict=unrelated")],
            )
            result.fix_pr = Finding(
                confidence="unknown",
                evidence=[Evidence("sanity_validator", "fix PR cleared because selected fix commit was rejected")],
            )
            result.introduced_commit = Finding(
                confidence="unknown",
                evidence=[Evidence("sanity_validator", "introducer cleared because fix commit was rejected")],
            )
            result.introduced_pr = Finding(
                confidence="unknown",
                evidence=[Evidence("sanity_validator", "introduced PR cleared because fix commit was rejected")],
            )

        if result.repository.value and not skip_git and self.git:
            owner, repo = result.repository.value.split("/", 1)
            try:
                repo_path = self.git.ensure_repo(owner, repo)
            except Exception:
                repo_path = None
            if repo_path is not None:
                self._reject_bad_commit(result.fix_commit, repo_path, "fix")
                self._reject_bad_commit(result.introduced_commit, repo_path, "introduced")
                if result.fix_commit.value and result.introduced_commit.value:
                    if not self.git.is_ancestor(repo_path, result.introduced_commit.value, result.fix_commit.value):
                        result.limitations.append("Introducer candidate is not an ancestor of fix commit; rejected by sanity validator.")
                        result.introduced_commit = Finding(
                            confidence="unknown",
                            evidence=[Evidence("sanity_validator", "introduced commit failed ancestor check")],
                        )
                        result.introduced_pr = Finding(
                            confidence="unknown",
                            evidence=[Evidence("sanity_validator", "introduced PR cleared because commit failed sanity checks")],
                        )

        signal_groups = dict(result.signal_groups)
        for name, finding in (
            ("fix_commit", result.fix_commit),
            ("fix_pr", result.fix_pr),
            ("introduced_commit", result.introduced_commit),
            ("introduced_pr", result.introduced_pr),
        ):
            confidence, groups = calibrated_confidence(finding, preserve_direct_high=name.startswith("fix"))
            finding.confidence = confidence
            signal_groups[name] = groups.to_dict()
        result.signal_groups = signal_groups
        return result

    def _reject_bad_commit(self, finding: Finding, repo_path, target_name: str) -> None:
        if not finding.value:
            return
        subject = self.git.commit_subject(repo_path, finding.value) if self.git else None
        if subject and BAD_SUBJECT_RE.search(subject.strip()):
            if target_name == "fix" and self.git and self.git.parent_count(repo_path, finding.value) <= 1:
                if _has_strong_source_diff_evidence(finding):
                    finding.evidence.append(
                        Evidence("sanity_validator", f"Subject looks non-semantic but commit is single-parent with source-diff evidence: {subject}")
                    )
                    return
            finding.confidence = "unknown"
            finding.evidence.append(
                Evidence("sanity_validator", f"Rejected {target_name} commit because subject looks non-semantic: {subject}")
            )
            finding.value = None
            finding.url = None


def _has_unrelated_fix_verdict(finding: Finding) -> bool:
    return any(
        evidence.source == "fix_verifier" and "verdict=unrelated" in evidence.detail.lower()
        for evidence in finding.evidence
    )


def _has_strong_source_diff_evidence(finding: Finding) -> bool:
    return any(
        evidence.source in {"release_fix_finder", "fix_verifier"}
        and ("source diff" in evidence.detail.lower() or "verdict=fixes" in evidence.detail.lower())
        for evidence in finding.evidence
    )
