from __future__ import annotations

import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from advisory_miner.agents.advisory_parser import AdvisoryParser
from advisory_miner.agents.critic import EvidenceCritic
from advisory_miner.agents.fix_finder import FixFinder
from advisory_miner.agents.fix_verifier import FixVerifier
from advisory_miner.agents.introducer_classifier import IntroducerClassifier
from advisory_miner.agents.introducer_finder import IntroducerFinder
from advisory_miner.agents.investigator import Investigator
from advisory_miner.agents.model_reviewer import ModelReviewer
from advisory_miner.agents.release_fix_finder import ReleaseFixFinder
from advisory_miner.agents.sanity_validator import SanityValidator
from advisory_miner.agents.validator import Validator
from advisory_miner.models import AnalysisResult
from advisory_miner.persistence import SQLiteStore
from advisory_miner.runtime import current_metrics, reset_metrics, set_cost_cap
from advisory_miner.tools.git_tools import GitTools
from advisory_miner.tools.github_tools import GitHubTools


class AdvisoryAnalyzer:
    def __init__(
        self,
        github: GitHubTools,
        git: GitTools,
        reviewer: ModelReviewer | None = None,
        critic: EvidenceCritic | None = None,
        investigator: Investigator | None = None,
        parser: AdvisoryParser | None = None,
        fix_verifier: FixVerifier | None = None,
        introducer_classifier: IntroducerClassifier | None = None,
        per_advisory_cost_cap_usd: float | None = None,
        tracer: object | None = None,
        agentic_mode: bool = True,
    ):
        self.fix_finder = FixFinder(github)
        self.release_fix_finder = ReleaseFixFinder(git, github)
        self.introducer_finder = IntroducerFinder(git, github)
        self.validator = Validator(git)
        self.sanity_validator = SanityValidator(git)
        self.reviewer = reviewer
        self.critic = critic
        self.investigator = investigator
        self.parser = parser
        self.fix_verifier = fix_verifier
        self.introducer_classifier = introducer_classifier
        self.git = git
        self.per_advisory_cost_cap_usd = per_advisory_cost_cap_usd
        self.tracer = tracer
        self.agentic_mode = agentic_mode

    def analyze(self, advisory: dict, skip_git: bool = False) -> AnalysisResult:
        span = getattr(self.tracer, "span", None) if self.tracer is not None else None
        if not callable(span):
            return self._analyze(advisory, skip_git=skip_git)
        metadata = _trace_metadata(advisory)
        with span(
            "advisory-analysis",
            input={"ghsa_id": advisory.get("ghsa_id"), "summary": advisory.get("summary")},
            metadata=metadata,
            tags=["advisory-miner", "analysis"],
        ) as root_span:
            try:
                result = self._analyze(advisory, skip_git=skip_git)
            except Exception as exc:
                if root_span is not None:
                    root_span.update(level="ERROR", status_message=str(exc))
                raise
            if root_span is not None:
                root_span.update(
                    output={
                        "repository": result.repository.value,
                        "fix_commit": result.fix_commit.value,
                        "fix_confidence": result.fix_commit.confidence,
                        "introduced_commit": result.introduced_commit.value,
                        "introduced_confidence": result.introduced_commit.confidence,
                    }
                )
            score = getattr(self.tracer, "score", None) if self.tracer is not None else None
            if callable(score):
                ledger = result.signal_groups.get("evidence_ledger") or {}
                tool_count = len(ledger.get("items") or [])
                filled = sum(
                    1
                    for finding in (result.fix_commit, result.fix_pr, result.introduced_commit, result.introduced_pr)
                    if finding.value
                )
                score("tool_coverage", min(1.0, tool_count / 4), metadata={"ghsa_id": result.ghsa_id})
                score("finding_fill_rate", filled / 4, metadata={"ghsa_id": result.ghsa_id})
            return result

    def _analyze(self, advisory: dict, skip_git: bool = False) -> AnalysisResult:
        metrics = reset_metrics()
        set_cost_cap(self.per_advisory_cost_cap_usd)
        started = time.monotonic()
        result = self.fix_finder.find(advisory)
        # Phase 1: LLM advisory parser runs BEFORE introducer analysis so the
        # introducer pattern search can use parsed.high_signal_search_patterns
        # instead of noisy commit-message keyword extraction.
        if self.parser is not None and result.repository.value:
            parsed = self.parser.parse(advisory)
            result.parsed_advisory = parsed.to_dict()
        # Phase 3: semantic fix verifier (cost-gated) — runs only when the top
        # candidate isn't a slam-dunk direct ref. Demotes confidence on
        # `unrelated` or `partial` verdicts; never wipes the value.
        if self.fix_verifier is not None:
            try:
                self.fix_verifier.verify_top_candidate(advisory, result)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"FixVerifier failed: {exc}")
        self.release_fix_finder.find(advisory, result, skip_git=skip_git)
        if self.fix_verifier is not None and result.fix_commit.value:
            try:
                self.fix_verifier.verify_top_candidate(advisory, result)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"FixVerifier failed after release search: {exc}")
        self.introducer_finder.find(advisory, result, skip_git=skip_git)
        # Phase 5 legacy classifier: disabled in agentic mode because it is a
        # one-shot gate over truncated context. The agentic investigator gets
        # the candidate list and must gather source-focused git evidence.
        if (
            not self.agentic_mode
            and
            self.introducer_classifier is not None
            and result.repository.value
            and result.introducer_candidates
        ):
            try:
                classifier_repo_path: Path | None = None
                if not skip_git:
                    owner, repo = result.repository.value.split("/", 1)
                    try:
                        classifier_repo_path = self.git.ensure_repo(owner, repo)
                    except Exception:
                        classifier_repo_path = None
                self.introducer_classifier.classify_and_select(advisory, result, classifier_repo_path)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"IntroducerClassifier failed: {exc}")
        if self.agentic_mode:
            _demote_proposals_for_agentic_review(result)
        if self.investigator and result.repository.value and _looks_like_real_repo(result.repository.value):
            repo_path: Path | None = None
            if not skip_git:
                owner, repo = result.repository.value.split("/", 1)
                try:
                    repo_path = self.git.ensure_repo(owner, repo)
                except Exception as exc:
                    result.errors.append(f"Investigator skipped: failed to ensure repo {owner}/{repo}: {exc}")
            try:
                self.investigator.investigate(advisory, result, repo_path)
            except Exception as exc:
                result.errors.append(f"Investigator failed: {exc}")
        if self.critic:
            result = self.critic.review(advisory, result)
        result = self.validator.validate(result, skip_git=skip_git)
        result = self.sanity_validator.validate(result, skip_git=skip_git)
        if self.reviewer:
            result = self.reviewer.review(advisory, result)
        metrics.wall_clock_ms = int((time.monotonic() - started) * 1000)
        result.metrics = metrics
        return result


_BLOCKED_OWNERS = {"user-attachments", "user-images", "avatars", "raw"}


def _looks_like_real_repo(value: str | None) -> bool:
    if not value or "/" not in value:
        return False
    owner = value.split("/", 1)[0].lower()
    return owner not in _BLOCKED_OWNERS


def _demote_proposals_for_agentic_review(result: AnalysisResult) -> None:
    """Treat deterministic outputs as proposals; the investigator must verify."""
    result.signal_groups["agentic_mode"] = {
        "enabled": True,
        "policy": "deterministic findings are candidate proposals and require tool-backed finalization",
    }
    for finding in (result.fix_commit, result.fix_pr, result.introduced_commit, result.introduced_pr):
        if finding.value and finding.confidence in {"high", "medium"}:
            finding.confidence = "low"


def _trace_metadata(advisory: dict) -> dict[str, str]:
    metadata = {
        "ghsaid": advisory.get("ghsa_id"),
        "severity": advisory.get("severity"),
        "publishedat": advisory.get("published_at"),
    }
    repo = advisory.get("repository")
    if isinstance(repo, dict):
        metadata["repository"] = repo.get("full_name") or repo.get("name")
    elif isinstance(repo, str):
        metadata["repository"] = repo
    return {key: str(value)[:200] for key, value in metadata.items() if value}


def load_collected(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Input must be a JSON list produced by the collector")
    return data


def write_analysis(path: Path, results: list[AnalysisResult]) -> None:
    payload = [result.to_dict() for result in results]
    _atomic_write_json(path, payload)


def _atomic_write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def load_existing_analysis(path: Path) -> tuple[list[dict], set[str]]:
    """Load a prior analysis file (if any) and return its rows + the set of
    GHSA ids already covered. Used for resumable runs."""
    if not path.exists():
        return [], set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], set()
    if not isinstance(data, list):
        return [], set()
    rows = [item for item in data if isinstance(item, dict)]
    seen = {row.get("ghsa_id") for row in rows if row.get("ghsa_id")}
    return rows, {s for s in seen if isinstance(s, str)}


def analyze_parallel(
    advisories: list[dict],
    analyzer: AdvisoryAnalyzer,
    workers: int,
    skip_git: bool = False,
    output_path: Path | None = None,
    resume: bool = True,
    progress: bool = True,
    store: SQLiteStore | None = None,
    run_id: str | None = None,
) -> list[AnalysisResult]:
    """Analyze advisories with a thread pool.

    - When `output_path` is given and `resume` is True, advisories whose
      `ghsa_id` is already present in that file are skipped, and completed
      results are checkpointed back to the file after every advisory.
    - When `progress` is True, a single-line status is written to stderr after
      each advisory completes.
    """
    pre_results: list[dict] = []
    already: set[str] = set()
    if output_path is not None and resume:
        pre_results, already = load_existing_analysis(output_path)

    pending = [adv for adv in advisories if adv.get("ghsa_id") not in already]
    new_results: list[AnalysisResult] = []
    write_lock = threading.Lock()
    completed = 0
    total = len(pending)
    skipped = len(advisories) - total

    if progress and skipped:
        print(f"resume: skipping {skipped} already-analyzed advisories", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {
            executor.submit(analyzer.analyze, advisory, skip_git): advisory for advisory in pending
        }
        for future in as_completed(futures):
            advisory = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = AnalysisResult(ghsa_id=advisory.get("ghsa_id", "UNKNOWN"), errors=[str(exc)])
            with write_lock:
                new_results.append(result)
                if store is not None and run_id is not None:
                    store.record_result(run_id, result)
                completed += 1
                if output_path is not None:
                    merged = pre_results + [r.to_dict() for r in new_results]
                    _atomic_write_json(output_path, merged)
                    _write_trace(output_path, result)
            if progress:
                status = "ok" if not result.errors else "errors"
                msg = (
                    f"[{completed}/{total}] {advisory.get('ghsa_id', 'UNKNOWN')} "
                    f"{status} fix_commit={result.fix_commit.confidence} "
                    f"introducer={result.introduced_commit.confidence} "
                    f"({result.metrics.wall_clock_ms}ms)"
                )
                print(msg, file=sys.stderr)

    # Combine resumed rows with new results, sort, and return as AnalysisResult-shaped data.
    combined_dicts = pre_results + [r.to_dict() for r in new_results]
    combined_dicts.sort(key=lambda item: item.get("ghsa_id", ""))
    if output_path is not None:
        _atomic_write_json(output_path, combined_dicts)
    new_results.sort(key=lambda item: item.ghsa_id)
    return new_results


def _write_trace(output_path: Path, result: AnalysisResult) -> None:
    trace_dir = output_path.parent / result.ghsa_id
    payload = {
        "ghsa_id": result.ghsa_id,
        "repository": result.repository.to_dict(),
        "fix_commit": result.fix_commit.to_dict(),
        "fix_pr": result.fix_pr.to_dict(),
        "introduced_commit": result.introduced_commit.to_dict(),
        "introduced_pr": result.introduced_pr.to_dict(),
        "signal_groups": result.signal_groups,
        "metrics": result.metrics.to_dict(),
        "model_review": result.model_review,
        "limitations": result.limitations,
        "errors": result.errors,
    }
    _atomic_write_json(trace_dir / "trace.json", payload)
