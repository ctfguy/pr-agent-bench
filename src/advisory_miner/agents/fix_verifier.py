"""LLM verifier that decides whether a candidate commit actually fixes
the vulnerability described in the advisory.

Replaces blind trust in keyword-overlap scoring with semantic check of the
candidate's diff against the parsed advisory's vulnerability semantics.

Cost is gated — verification is skipped when signals already agree, and run
only when:
  - the candidate came from a search rather than a direct advisory reference
  - multiple candidates have closely-scored alternatives
  - the candidate's pre-verification confidence is borderline
  - the parsed advisory is high quality (otherwise we have nothing to check)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from advisory_miner.models import AnalysisResult, Evidence, Finding, FixCandidate
from advisory_miner.openai_client import OpenAIClient, OpenAIClientError
from advisory_miner.tools.github_tools import GitHubTools


logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are an evidence-constrained security fix verifier.

Given a parsed advisory and a candidate commit's diff, decide whether the diff
actually fixes the vulnerability described.

Return ONE JSON object:

{
  "verdict": "fixes" | "partial" | "unrelated" | "uncertain",
  "rationale": one-paragraph evidence summary citing specific diff lines,
  "covered_constructs": [advisory constructs the diff addresses],
  "missing_coverage": [advisory constructs the diff does NOT address]
}

Rules:
- "fixes" means: the diff modifies the vulnerable construct in a way that
  matches the advisory's `expected_fix_behavior`.
- "partial" means: the diff addresses part of the vulnerability surface but
  leaves another part untouched (e.g. one endpoint patched, sibling endpoint
  with the same issue not patched).
- "unrelated" means: the diff modifies code that does not match the
  vulnerability description at all.
- "uncertain" means: the diff is too small / too large / too obfuscated to
  judge with the information given.
- Cite specific code from the diff in the rationale. Do not speculate beyond
  what you can see.
"""


@dataclass
class FixVerdict:
    candidate_sha: str
    verdict: str
    rationale: str
    covered_constructs: list[str]
    missing_coverage: list[str]
    skipped_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_sha": self.candidate_sha,
            "verdict": self.verdict,
            "rationale": self.rationale,
            "covered_constructs": self.covered_constructs,
            "missing_coverage": self.missing_coverage,
            "skipped_reason": self.skipped_reason,
        }


class FixVerifier:
    """Per-fix-candidate semantic check.

    `verify_top_candidate` runs the gating policy and either:
      - returns None (verification skipped — pre-existing confidence stands)
      - returns a FixVerdict with the LLM's judgment

    When the verdict is `unrelated` or `partial`, the candidate's
    confidence on `result.fix_commit` is demoted accordingly.
    """

    def __init__(self, client: OpenAIClient | None, github: GitHubTools):
        self.client = client
        self.github = github

    def verify_top_candidate(
        self, advisory: dict[str, Any], result: AnalysisResult
    ) -> FixVerdict | None:
        if self.client is None:
            return None
        if not result.fix_commit.value or not result.fix_candidates:
            return None
        if not result.repository.value:
            return None
        parsed = result.parsed_advisory or {}
        if not _parsed_has_signal(parsed):
            # Without a structured advisory we can't ask a meaningful question.
            return None

        if not _should_verify(result, result.fix_candidates[0]):
            return None
        candidates = result.fix_candidates[:5]
        best_verdict: FixVerdict | None = None
        for top in candidates:
            verdict = self._verify_candidate(advisory, result, top, parsed)
            if verdict is None:
                continue
            if verdict.verdict == "fixes":
                self._select_candidate(result, top, verdict)
                return verdict
            if best_verdict is None:
                best_verdict = verdict
            if verdict.verdict == "partial" and best_verdict.verdict != "partial":
                best_verdict = verdict

        if best_verdict is not None:
            self._apply_verdict(result, best_verdict)
        return best_verdict

    def _verify_candidate(
        self,
        advisory: dict[str, Any],
        result: AnalysisResult,
        candidate: FixCandidate,
        parsed: dict[str, Any],
    ) -> FixVerdict | None:
        top = candidate

        owner, repo = result.repository.value.split("/", 1)
        diff = self._fetch_diff(owner, repo, top.sha)
        if not diff:
            return None

        payload = {
            "parsed_advisory": parsed,
            "candidate": {
                "sha": top.sha,
                "message": top.message,
                "score": top.score,
                "ranker_reasons": top.reasons[:6],
            },
            "diff": diff,
        }
        try:
            raw = self.client.json_response(SYSTEM_PROMPT, payload, max_output_tokens=1500)
        except OpenAIClientError as exc:
            logger.warning("FixVerifier: OpenAI call failed for %s: %s", advisory.get("ghsa_id"), exc)
            return FixVerdict(
                candidate_sha=top.sha,
                verdict="uncertain",
                rationale=f"verifier failed: {exc}"[:300],
                covered_constructs=[],
                missing_coverage=[],
                skipped_reason="openai_error",
            )
        verdict = FixVerdict(
            candidate_sha=top.sha,
            verdict=str(raw.get("verdict") or "uncertain").lower(),
            rationale=str(raw.get("rationale") or "")[:600],
            covered_constructs=_str_list(raw.get("covered_constructs")),
            missing_coverage=_str_list(raw.get("missing_coverage")),
        )
        return verdict

    def _select_candidate(self, result: AnalysisResult, candidate: FixCandidate, verdict: FixVerdict) -> None:
        if result.repository.value:
            owner, repo = result.repository.value.split("/", 1)
            url = candidate.url or f"https://github.com/{owner}/{repo}/commit/{candidate.sha}"
        else:
            url = candidate.url
        result.fix_commit = Finding(
            value=candidate.sha,
            url=url,
            confidence="high" if result.fix_commit.confidence == "high" else "medium",
            evidence=[
                Evidence("fix_verifier", f"verdict=fixes; {verdict.rationale[:400]}"),
                Evidence("fix_finder", f"selected from candidate list: {'; '.join(candidate.reasons[:4])}"),
            ],
        )

    def _fetch_diff(self, owner: str, repo: str, sha: str) -> str | None:
        commit = self.github.get_commit(owner, repo, sha)
        if not commit:
            return None
        files = commit.get("files") or []
        pieces: list[str] = []
        message = (commit.get("commit") or {}).get("message", "")
        if message:
            pieces.append(f"commit: {message[:500]}")
        budget = 8000
        for f in files[:20]:
            patch = f.get("patch") or ""
            filename = f.get("filename") or ""
            if not patch:
                continue
            header = f"\n--- {filename}\n"
            if len(header) + len(patch) > budget:
                patch = patch[: max(0, budget - len(header))]
            pieces.append(header + patch)
            budget -= len(header) + len(patch)
            if budget <= 0:
                break
        return "\n".join(pieces) if pieces else None

    def _apply_verdict(self, result: AnalysisResult, verdict: FixVerdict) -> None:
        """Apply verifier verdict to the fix_commit confidence + evidence trail.

        Important: the verifier can DOWNGRADE confidence or add evidence. It
        must NOT overwrite the value or boost a low-evidence finding to high.
        """
        target = result.fix_commit
        if not target.value:
            return
        target.evidence.append(
            Evidence(
                source="fix_verifier",
                detail=(
                    f"verdict={verdict.verdict}; covered={verdict.covered_constructs[:4]}; "
                    f"missing={verdict.missing_coverage[:4]}; {verdict.rationale[:300]}"
                ),
            )
        )
        if verdict.verdict == "unrelated":
            # Strong signal: demote to low. Keep the value so a human can audit.
            target.confidence = "low"
        elif verdict.verdict == "partial":
            # Downgrade one level: high->medium, medium->low, low->low.
            target.confidence = {"high": "medium", "medium": "low"}.get(target.confidence, target.confidence)
        elif verdict.verdict == "uncertain":
            # No confidence change; the evidence trail records the doubt.
            pass


def _should_verify(result: AnalysisResult, top: FixCandidate) -> bool:
    """Cost-gate: only run the LLM when the answer is plausibly wrong."""
    # 1. Verify when the only signal is a search-derived candidate.
    direct_reasons = {"Advisory directly references this commit", "Merge commit for directly referenced PR"}
    is_direct = any(any(token in reason for token in direct_reasons) for reason in top.reasons)
    if not is_direct:
        return True
    # 2. Verify when an alternative candidate is within 20% of the top score.
    if len(result.fix_candidates) > 1:
        second = result.fix_candidates[1]
        if second.score and top.score and second.score >= 0.8 * top.score:
            return True
    # 3. Verify when pre-existing confidence isn't high.
    if result.fix_commit.confidence != "high":
        return True
    return False


def _parsed_has_signal(parsed: dict[str, Any]) -> bool:
    if not isinstance(parsed, dict):
        return False
    if parsed.get("parse_status") in {"failed", "skipped"}:
        return False
    return bool(
        parsed.get("high_signal_search_patterns")
        or parsed.get("vulnerable_functions")
        or parsed.get("vulnerable_construct")
    )


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if isinstance(item, str) and item.strip()]
