from __future__ import annotations

from typing import Any

from advisory_miner.models import AnalysisResult
from advisory_miner.openai_client import OpenAIClient, OpenAIClientError


SYSTEM_PROMPT = """You are an evidence-constrained security advisory validation agent.
Use only the advisory JSON and deterministic tool output provided by the user.
Do not invent repositories, commits, PRs, versions, or facts.
If a finding is unsupported, mark it unknown or downgrade confidence.
Return only JSON with these keys:
status, fix_commit_review, fix_pr_review, introduced_commit_review, introduced_pr_review, validation_notes, reasoning_trace.
reasoning_trace must be a short evidence summary, not hidden chain-of-thought.
Each *_review object must contain value, confidence, and rationale.
Confidence must be one of high, medium, low, unknown.
"""


class ModelReviewer:
    def __init__(self, client: OpenAIClient):
        self.client = client

    def review(self, advisory: dict[str, Any], result: AnalysisResult) -> AnalysisResult:
        payload = {
            "advisory": _compact_advisory(advisory),
            "deterministic_result": _compact_result(result),
            "rules": [
                "Use only candidate commits and evidence already present in deterministic_result.",
                "Do not add new commit or PR identifiers.",
                "Downgrade generic pattern-search matches when they do not prove introduction.",
                "Prefer unknown over unsupported certainty.",
            ],
        }
        try:
            review = self.client.json_response(SYSTEM_PROMPT, payload)
        except OpenAIClientError as exc:
            # Reviewer failures (parse errors, transient network) don't invalidate
            # the deterministic findings — record the skip on model_review and
            # keep going. Don't pollute errors[] with reviewer noise.
            result.model_review = {"status": "skipped", "reason": str(exc)[:300]}
            return result
        result.model_review = review
        _apply_confidence_review(result, review)
        return result


def _compact_advisory(advisory: dict[str, Any]) -> dict[str, Any]:
    return {
        "ghsa_id": advisory.get("ghsa_id"),
        "cve_ids": advisory.get("cve_ids"),
        "summary": advisory.get("summary"),
        "description": advisory.get("description"),
        "references": advisory.get("references"),
        "extracted_github": advisory.get("extracted_github"),
        "vulnerabilities": advisory.get("vulnerabilities"),
    }


def _compact_result(result: AnalysisResult) -> dict[str, Any]:
    data = result.to_dict()
    data["fix_candidates"] = [_compact_candidate(item) for item in data.get("fix_candidates", [])[:5]]
    data["introducer_candidates"] = [_compact_candidate(item) for item in data.get("introducer_candidates", [])[:8]]
    signal_groups = data.get("signal_groups") or {}
    data["signal_groups"] = {
        key: value
        for key, value in signal_groups.items()
        if key in {"fix_commit", "fix_pr", "introduced_commit", "introduced_pr", "critic_review", "agentic_mode"}
    }
    return data


def _compact_candidate(item: dict[str, Any]) -> dict[str, Any]:
    compact = dict(item)
    compact["reasons"] = [str(reason)[:220] for reason in compact.get("reasons") or []][:5]
    compact["matched_patterns"] = [str(pattern)[:160] for pattern in compact.get("matched_patterns") or []][:10]
    return compact


def _apply_confidence_review(result: AnalysisResult, review: dict[str, Any]) -> None:
    """Apply the reviewer's confidence adjustments without erasing identifiers.

    The reviewer's role is to *calibrate confidence*, not to delete what the
    deterministic tools found. If the reviewer is uncertain about a value the
    deterministic path produced (often due to GitHub URL redirects or repo
    renames that the reviewer reads as inconsistency), we downgrade confidence
    instead of nulling the value.
    """
    for key, finding in (
        ("fix_commit_review", result.fix_commit),
        ("fix_pr_review", result.fix_pr),
        ("introduced_commit_review", result.introduced_commit),
        ("introduced_pr_review", result.introduced_pr),
    ):
        item = review.get(key)
        if not isinstance(item, dict):
            continue
        confidence = item.get("confidence")
        if confidence not in {"high", "medium", "low", "unknown"}:
            continue
        # If the reviewer wants to mark this unknown but the deterministic
        # tools produced a value, demote to "low" rather than discarding the
        # value — the deterministic finding stays auditable.
        if confidence == "unknown" and finding.value:
            finding.confidence = "low"
        else:
            finding.confidence = confidence
