from __future__ import annotations

import json
from typing import Any

from advisory_miner.models import AnalysisResult, Evidence
from advisory_miner.openai_client import OpenAIClient, OpenAIClientError


SYSTEM_PROMPT = """You are an evidence critic for a security advisory analysis.

Review the final findings against the provided evidence ledger. Return JSON:
{
  "verdict": "pass" | "needs_more_evidence" | "reject",
  "issues": ["short issue strings"],
  "rationale": "brief evidence-grounded explanation"
}

Reject malformed PRs, hallucinated identifiers, commit findings without git or
GitHub evidence, and introducer claims that were not backed by source-level git
inspection. If a PR was genuinely absent and the ledger shows commit-to-pulls
returned empty, treat unknown as acceptable.
"""


class EvidenceCritic:
    def __init__(self, client: OpenAIClient | None):
        self.client = client

    def review(self, advisory: dict[str, Any], result: AnalysisResult) -> AnalysisResult:
        if self.client is None:
            return result
        ledger = result.signal_groups.get("evidence_ledger")
        if not ledger:
            result.errors.append("EvidenceCritic skipped: no evidence ledger was attached")
            return result
        payload = {
            "advisory": {
                "ghsa_id": advisory.get("ghsa_id"),
                "summary": advisory.get("summary"),
                "description": (advisory.get("description") or "")[:4000],
                "references": advisory.get("references") or [],
                "vulnerabilities": advisory.get("vulnerabilities") or [],
            },
            "findings": {
                "repository": result.repository.to_dict(),
                "fix_commit": result.fix_commit.to_dict(),
                "fix_pr": result.fix_pr.to_dict(),
                "introduced_commit": result.introduced_commit.to_dict(),
                "introduced_pr": result.introduced_pr.to_dict(),
            },
            "evidence_ledger": _compact_ledger(ledger),
        }
        try:
            review = self.client.json_response(SYSTEM_PROMPT, json.dumps(payload, separators=(",", ":")), max_output_tokens=1200)
        except OpenAIClientError as exc:
            result.errors.append(f"EvidenceCritic failed: {exc}")
            return result
        verdict = str(review.get("verdict") or "needs_more_evidence").lower()
        issues = [str(item)[:200] for item in review.get("issues") or []]
        rationale = str(review.get("rationale") or "")[:600]
        result.signal_groups["critic_review"] = {
            "verdict": verdict,
            "issues": issues,
            "rationale": rationale,
        }
        if verdict in {"reject", "needs_more_evidence"}:
            result.limitations.append(f"critic_{verdict}: {rationale}")
        for finding in (result.fix_commit, result.fix_pr, result.introduced_commit, result.introduced_pr):
            if finding.value:
                finding.evidence.append(Evidence(source="evidence_critic", detail=f"verdict={verdict}; {rationale[:250]}"))
        return result


def _compact_ledger(ledger: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": ledger.get("repository"),
        "tools_called": ledger.get("tools_called") or [],
        "items": [
            {
                "id": item.get("id"),
                "tool_name": item.get("tool_name"),
                "values": item.get("values") or [],
                "input": item.get("input"),
                "output_excerpt": str(item.get("output"))[:1200],
            }
            for item in (ledger.get("items") or [])[:20]
        ],
    }
