from __future__ import annotations

from dataclasses import asdict, dataclass, field

from advisory_miner.models import Evidence, Finding


ADVISORY_SOURCES = {"collector", "github_api", "github_pr", "github_search", "osv", "nvd", "investigator"}
CODE_SOURCES = {"fix_verifier", "introducer_classifier", "fix_ranker"}
HISTORY_SOURCES = {"validator", "introducer_finder", "git"}


@dataclass(slots=True)
class SignalGroups:
    advisory_source: list[str] = field(default_factory=list)
    code_content: list[str] = field(default_factory=list)
    history_topology: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def active_count(self) -> int:
        return sum(bool(group) for group in (self.advisory_source, self.code_content, self.history_topology))


def collect_signal_groups(finding: Finding) -> SignalGroups:
    groups = SignalGroups()
    for evidence in finding.evidence:
        source = evidence.source.lower()
        detail = evidence.detail.lower()
        if source in ADVISORY_SOURCES:
            groups.advisory_source.append(evidence.detail)
        if source in CODE_SOURCES or "pattern search" in detail or "diff" in detail:
            groups.code_content.append(evidence.detail)
        if source in HISTORY_SOURCES or "ancestor" in detail or "blame" in detail or "tag-bracket" in detail:
            groups.history_topology.append(evidence.detail)
    return groups


def calibrated_confidence(finding: Finding, preserve_direct_high: bool = True) -> tuple[str, SignalGroups]:
    if not finding.value:
        return "unknown", SignalGroups()
    groups = collect_signal_groups(finding)
    if preserve_direct_high and finding.confidence == "high" and groups.advisory_source:
        return "high", groups
    if groups.active_count() >= 2 and groups.code_content:
        return "high", groups
    if groups.active_count() >= 2:
        return "medium", groups
    if groups.code_content or groups.history_topology or groups.advisory_source:
        return "low", groups
    return "unknown", groups
