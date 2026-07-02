"""LLM classifier that reads each top introducer candidate's diff and
labels it as introduced / refactored / unrelated.

This replaces the assumption that "highest-scoring candidate is the
introducer." Each candidate's diff is shown to the LLM together with the
parsed advisory; the LLM decides whether the diff actually adds the
vulnerable construct in a callable form.

Refactored candidates (move/rename/extract) are not the real introducer —
the introducer lived in the pre-rename file. When all top candidates
classify as `refactored` or `unrelated`, we honestly emit `unknown`
rather than pick the best-of-bad-options.

Cost discipline: K is small (default 4), the diff is truncated, and the
classifier is skipped entirely when the parsed advisory is low-quality.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from advisory_miner.agents.introducer_finder import affected_lower_bound_versions
from advisory_miner.models import AnalysisResult, CandidateCommit, Evidence, Finding
from advisory_miner.openai_client import OpenAIClient, OpenAIClientError
from advisory_miner.tools.git_tools import GitTools
from advisory_miner.tools.github_tools import GitHubTools


logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are an evidence-constrained introducer classifier.

Given a parsed advisory and a candidate commit's diff, decide whether the
diff added the vulnerable construct in an exploitable form.

Return ONE JSON object:

{
  "verdict": "introduced" | "refactored" | "unrelated" | "uncertain",
  "is_vulnerable_callable_after": true | false,
  "rationale": one-paragraph evidence citing specific diff lines
}

Rules:
- "introduced" means: the diff ADDS the vulnerable construct described in the
  advisory (or the function/parameter/endpoint that contains it) in a form
  that an attacker could invoke after this commit.
- Do NOT mark a commit introduced merely because it adds a related helper,
  configuration option, security feature, or prerequisite vocabulary. It must
  add the specific vulnerable behavior described by the advisory.
- If affected_version_lower_bounds are provided, the introducing commit should
  usually align with the first affected release. A candidate that predates the
  lower bound should be treated as unrelated unless the diff itself directly
  introduces the exact vulnerable behavior and the advisory evidence says older
  versions are affected too.
- "refactored" means: the diff moves/renames/extracts code that already had
  the vulnerable construct — the real introducer is in the file's pre-rename
  history, NOT this commit. Heuristics: subject starts with move/rename/
  refactor; high rename-ratio; same code appearing under a new path.
- "unrelated" means: the diff touches files in the advisory's vicinity but
  does not add the vulnerable construct (e.g. it changes a sibling function,
  fixes a typo, bumps a version).
- "uncertain" means: insufficient information in the diff to judge.
- is_vulnerable_callable_after = true only when the diff makes the
  construct reachable from a code path the advisory describes (endpoint,
  function entrypoint, etc.).
"""


@dataclass
class IntroducerClassification:
    candidate_sha: str
    verdict: str
    is_vulnerable_callable_after: bool
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_sha": self.candidate_sha,
            "verdict": self.verdict,
            "is_vulnerable_callable_after": self.is_vulnerable_callable_after,
            "rationale": self.rationale,
        }


class IntroducerClassifier:
    def __init__(
        self,
        client: OpenAIClient | None,
        github: GitHubTools,
        git: GitTools,
        top_k: int = 4,
    ):
        self.client = client
        self.github = github
        self.git = git
        self.top_k = top_k

    def classify_and_select(
        self,
        advisory: dict[str, Any],
        result: AnalysisResult,
        repo_path: Path | None,
    ) -> list[IntroducerClassification]:
        if self.client is None or not result.repository.value:
            return []
        parsed = result.parsed_advisory or {}
        if not _parsed_has_signal(parsed):
            return []
        if not result.introducer_candidates:
            return []

        owner, repo = result.repository.value.split("/", 1)
        classifications: list[IntroducerClassification] = []
        lower_bounds = affected_lower_bound_versions(advisory)

        for candidate in result.introducer_candidates[: self.top_k]:
            diff = self._fetch_diff(owner, repo, candidate.sha, repo_path)
            if not diff:
                continue
            payload = {
                "parsed_advisory": parsed,
                "affected_version_lower_bounds": lower_bounds,
                "candidate": {
                    "sha": candidate.sha,
                    "subject": candidate.subject,
                    "score": candidate.score,
                    "strategies": candidate.strategies,
                    "matched_patterns": candidate.matched_patterns[:8],
                    "ranking_reasons": candidate.reasons[:8],
                },
                "diff": diff,
            }
            try:
                raw = self.client.json_response(
                    SYSTEM_PROMPT,
                    json.dumps(payload, separators=(",", ":")),
                    max_output_tokens=1200,
                )
            except OpenAIClientError as exc:
                logger.warning(
                    "IntroducerClassifier: OpenAI call failed for %s/%s: %s",
                    advisory.get("ghsa_id"),
                    candidate.sha[:12],
                    exc,
                )
                continue
            classification = IntroducerClassification(
                candidate_sha=candidate.sha,
                verdict=str(raw.get("verdict") or "uncertain").lower(),
                is_vulnerable_callable_after=bool(raw.get("is_vulnerable_callable_after")),
                rationale=str(raw.get("rationale") or "")[:600],
            )
            classifications.append(classification)

        self._apply_selection(result, classifications, owner, repo)
        return classifications

    def _fetch_diff(self, owner: str, repo: str, sha: str, repo_path: Path | None) -> str | None:
        # Prefer the local git diff when available (no extra GitHub call).
        if repo_path is not None:
            try:
                local = self.git.commit_diff(repo_path, sha, unified=10, max_chars=6000)
                if local:
                    return local
            except Exception:
                pass
        commit = self.github.get_commit(owner, repo, sha)
        if not commit:
            return None
        files = commit.get("files") or []
        pieces: list[str] = []
        message = (commit.get("commit") or {}).get("message", "")
        if message:
            pieces.append(f"commit: {message[:500]}")
        budget = 6000
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

    def _apply_selection(
        self,
        result: AnalysisResult,
        classifications: list[IntroducerClassification],
        owner: str,
        repo: str,
    ) -> None:
        """Choose the highest-scoring candidate classified as `introduced`.

        If none classify as introduced, emit unknown — better than picking
        the best-scoring refactor commit (the bug we kept hitting before).
        """
        if not classifications:
            return
        cls_by_sha = {c.candidate_sha: c for c in classifications}
        introduced: list[CandidateCommit] = [
            cand
            for cand in result.introducer_candidates
            if cls_by_sha.get(cand.sha) and cls_by_sha[cand.sha].verdict == "introduced"
        ]
        if not introduced:
            # No candidate classified as introduced — emit unknown with reason.
            reasons = []
            for cand in result.introducer_candidates[: self.top_k]:
                cls = cls_by_sha.get(cand.sha)
                if cls:
                    reasons.append(f"{cand.sha[:12]}={cls.verdict}")
            result.introduced_commit = Finding(
                value=None,
                url=None,
                confidence="unknown",
                evidence=[
                    Evidence(
                        source="introducer_classifier",
                        detail=f"no candidate classified as introduced ({', '.join(reasons)})",
                    )
                ],
            )
            result.introduced_pr = Finding(
                value=None,
                url=None,
                confidence="unknown",
                evidence=[Evidence(source="introducer_classifier", detail="no verified introducer commit")],
            )
            return

        best = introduced[0]
        cls = cls_by_sha[best.sha]
        confidence = "medium" if cls.is_vulnerable_callable_after else "low"
        result.introduced_commit = Finding(
            value=best.sha,
            url=f"https://github.com/{owner}/{repo}/commit/{best.sha}",
            confidence=confidence,
            evidence=[
                Evidence(
                    source="introducer_classifier",
                    detail=f"verdict=introduced; callable_after={cls.is_vulnerable_callable_after}; {cls.rationale[:300]}",
                ),
                Evidence(
                    source="introducer_finder",
                    detail=f"top-ranked candidate with strategies={best.strategies}",
                ),
            ],
        )
        try:
            pulls = self.github.commit_pulls(owner, repo, best.sha)
        except Exception:
            pulls = []
        if pulls:
            number = pulls[0].get("number")
            if number:
                result.introduced_pr = Finding(
                    value=f"{owner}/{repo}#{number}",
                    url=pulls[0].get("html_url") or f"https://github.com/{owner}/{repo}/pull/{number}",
                    confidence=confidence,
                    evidence=[
                        Evidence(
                            source="introducer_classifier",
                            detail=f"github commit-to-pulls linked selected introducer {best.sha[:12]} to PR #{number}",
                        )
                    ],
                )
        else:
            result.introduced_pr = Finding(
                confidence="unknown",
                evidence=[Evidence("introducer_classifier", f"no PR found for selected introducer {best.sha[:12]}")],
            )


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
