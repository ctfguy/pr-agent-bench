from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class PackageVulnerability:
    ecosystem: str | None = None
    name: str | None = None
    vulnerable_version_range: str | None = None
    first_patched_version: str | None = None
    vulnerable_functions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class GitHubRef:
    owner: str
    repo: str
    kind: str
    value: str
    url: str

    @property
    def repository(self) -> str:
        return f"{self.owner}/{self.repo}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExtractedGitHubRefs:
    repositories: list[str] = field(default_factory=list)
    pull_requests: list[GitHubRef] = field(default_factory=list)
    commits: list[GitHubRef] = field(default_factory=list)
    issues: list[GitHubRef] = field(default_factory=list)
    compare_urls: list[GitHubRef] = field(default_factory=list)
    release_urls: list[GitHubRef] = field(default_factory=list)
    other_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repositories": self.repositories,
            "pull_requests": [ref.to_dict() for ref in self.pull_requests],
            "commits": [ref.to_dict() for ref in self.commits],
            "issues": [ref.to_dict() for ref in self.issues],
            "compare_urls": [ref.to_dict() for ref in self.compare_urls],
            "release_urls": [ref.to_dict() for ref in self.release_urls],
            "other_urls": self.other_urls,
        }


@dataclass(slots=True)
class CollectedAdvisory:
    ghsa_id: str
    cve_ids: list[str]
    url: str | None
    html_url: str | None
    summary: str | None
    description: str | None
    type: str | None
    severity: str | None
    repository_advisory_url: str | None
    source_code_location: str | None
    identifiers: list[dict[str, Any]]
    references: list[str]
    published_at: str | None
    updated_at: str | None
    github_reviewed_at: str | None
    nvd_published_at: str | None
    withdrawn_at: str | None
    vulnerabilities: list[PackageVulnerability]
    cwes: list[dict[str, Any]]
    cvss: dict[str, Any]
    cvss_severities: dict[str, Any]
    credits: list[dict[str, Any]]
    extracted_github: ExtractedGitHubRefs
    enriched_refs: dict[str, Any] | None = None
    raw: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["extracted_github"] = self.extracted_github.to_dict()
        return payload


@dataclass(slots=True)
class Evidence:
    source: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    value: str | None = None
    url: str | None = None
    confidence: str = "unknown"
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "url": self.url,
            "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(slots=True)
class FixCandidate:
    sha: str
    url: str | None = None
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CandidateCommit:
    sha: str
    score: int = 0
    subject: str | None = None
    reasons: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    strategies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AnalysisMetrics:
    github_calls: int = 0
    github_cache_hits: int = 0
    openai_input_tokens: int = 0
    openai_output_tokens: int = 0
    openai_calls: int = 0
    estimated_openai_cost_usd: float = 0.0
    tool_calls_used: int = 0
    wall_clock_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AnalysisResult:
    ghsa_id: str
    repository: Finding = field(default_factory=Finding)
    fix_commit: Finding = field(default_factory=Finding)
    fix_pr: Finding = field(default_factory=Finding)
    introduced_commit: Finding = field(default_factory=Finding)
    introduced_pr: Finding = field(default_factory=Finding)
    fix_candidates: list[FixCandidate] = field(default_factory=list)
    introducer_candidates: list[CandidateCommit] = field(default_factory=list)
    parsed_advisory: dict[str, Any] | None = None
    model_review: dict[str, Any] | None = None
    metrics: AnalysisMetrics = field(default_factory=AnalysisMetrics)
    dockerization: dict[str, Any] | None = None
    signal_groups: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ghsa_id": self.ghsa_id,
            "repository": self.repository.to_dict(),
            "fix_commit": self.fix_commit.to_dict(),
            "fix_pr": self.fix_pr.to_dict(),
            "introduced_commit": self.introduced_commit.to_dict(),
            "introduced_pr": self.introduced_pr.to_dict(),
            "fix_candidates": [item.to_dict() for item in self.fix_candidates],
            "introducer_candidates": [item.to_dict() for item in self.introducer_candidates],
            "parsed_advisory": self.parsed_advisory,
            "model_review": self.model_review,
            "metrics": self.metrics.to_dict(),
            "dockerization": self.dockerization,
            "signal_groups": self.signal_groups,
            "limitations": self.limitations,
            "errors": self.errors,
        }
