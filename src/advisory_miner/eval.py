"""Compare advisory analysis output against hand-labeled ground truth.

Produces precision@1 per target, confidence-calibration, and run-level metrics.
Designed to grow with the labels file: labels with `null` expected values are
treated as unlabeled for that target (skipped from accuracy stats).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


TARGETS: tuple[str, ...] = ("fix_commit", "fix_pr", "introduced_commit", "introduced_pr")


def shas_match(predicted: str | None, expected: str | None) -> bool:
    if not predicted or not expected:
        return False
    p = predicted.strip().lower()
    e = expected.strip().lower()
    if len(p) < 7 or len(e) < 7:
        return False
    return p.startswith(e) or e.startswith(p)


def prs_match(predicted: str | None, expected: str | None) -> bool:
    if not predicted or not expected:
        return False
    return predicted.strip().lower() == expected.strip().lower()


MATCHERS: dict[str, Callable[[str | None, str | None], bool]] = {
    "fix_commit": shas_match,
    "fix_pr": prs_match,
    "introduced_commit": shas_match,
    "introduced_pr": prs_match,
}


@dataclass
class TargetMetrics:
    target: str
    labeled: int = 0
    predicted: int = 0
    correct: int = 0
    wrong: int = 0
    missing: int = 0
    by_confidence: dict[str, dict[str, int]] = field(
        default_factory=lambda: {
            "high": {"total": 0, "correct": 0},
            "medium": {"total": 0, "correct": 0},
            "low": {"total": 0, "correct": 0},
            "unknown": {"total": 0, "correct": 0},
        }
    )

    @property
    def precision_at_1(self) -> float | None:
        if self.predicted == 0:
            return None
        return self.correct / self.predicted

    @property
    def recall(self) -> float | None:
        if self.labeled == 0:
            return None
        return self.correct / self.labeled

    def calibration(self, confidence: str) -> float | None:
        bucket = self.by_confidence.get(confidence) or {}
        total = bucket.get("total", 0)
        if total == 0:
            return None
        return bucket.get("correct", 0) / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "labeled": self.labeled,
            "predicted": self.predicted,
            "correct": self.correct,
            "wrong": self.wrong,
            "missing": self.missing,
            "precision_at_1": self.precision_at_1,
            "recall": self.recall,
            "calibration": {
                level: {
                    "total": data["total"],
                    "correct": data["correct"],
                    "precision": (data["correct"] / data["total"]) if data["total"] else None,
                }
                for level, data in self.by_confidence.items()
            },
        }


@dataclass
class EvalReport:
    label_count: int
    matched_count: int
    targets: dict[str, TargetMetrics]
    per_advisory: list[dict[str, Any]] = field(default_factory=list)
    summary_metrics: dict[str, Any] = field(default_factory=dict)
    per_stratum: dict[str, dict[str, TargetMetrics]] = field(default_factory=dict)
    signal_attribution: dict[str, dict[str, int]] = field(default_factory=dict)
    failure_patterns: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label_count": self.label_count,
            "matched_count": self.matched_count,
            "targets": {name: tm.to_dict() for name, tm in self.targets.items()},
            "per_advisory": self.per_advisory,
            "summary_metrics": self.summary_metrics,
            "per_stratum": {
                stratum: {name: tm.to_dict() for name, tm in by_target.items()}
                for stratum, by_target in self.per_stratum.items()
            },
            "signal_attribution": self.signal_attribution,
            "failure_patterns": self.failure_patterns,
        }


def evaluate(labels: list[dict[str, Any]], analysis: list[dict[str, Any]]) -> EvalReport:
    analysis_by_id = {entry["ghsa_id"]: entry for entry in analysis if "ghsa_id" in entry}
    targets = {name: TargetMetrics(target=name) for name in TARGETS}
    per_stratum: dict[str, dict[str, TargetMetrics]] = {}
    signal_attribution: dict[str, dict[str, int]] = {name: {} for name in TARGETS}
    failure_patterns: dict[str, list[str]] = {name: [] for name in TARGETS}
    per_advisory: list[dict[str, Any]] = []
    matched_count = 0

    for label in labels:
        ghsa = label.get("ghsa_id")
        if not ghsa:
            continue
        result = analysis_by_id.get(ghsa)
        if not result:
            per_advisory.append({"ghsa_id": ghsa, "status": "missing_from_analysis", "targets": {}})
            continue
        matched_count += 1
        category = label.get("category") or "uncategorized"
        adv_entry: dict[str, Any] = {
            "ghsa_id": ghsa,
            "category": category,
            "status": "evaluated",
            "targets": {},
        }

        stratum_targets = per_stratum.setdefault(
            category, {name: TargetMetrics(target=name) for name in TARGETS}
        )

        for name in TARGETS:
            expected = label.get(f"expected_{name}")
            finding = result.get(name) or {}
            predicted = finding.get("value")
            confidence = (finding.get("confidence") or "unknown").lower()
            metrics = targets[name]
            stratum_metric = stratum_targets[name]

            if expected is None:
                adv_entry["targets"][name] = {
                    "expected": None,
                    "predicted": predicted,
                    "confidence": confidence,
                    "outcome": "unlabeled",
                }
                continue

            metrics.labeled += 1
            stratum_metric.labeled += 1
            matcher = MATCHERS[name]
            if predicted is None:
                metrics.missing += 1
                stratum_metric.missing += 1
                outcome = "missing"
            else:
                metrics.predicted += 1
                stratum_metric.predicted += 1
                if matcher(predicted, expected):
                    metrics.correct += 1
                    stratum_metric.correct += 1
                    outcome = "correct"
                else:
                    metrics.wrong += 1
                    stratum_metric.wrong += 1
                    outcome = "wrong"

            for tm in (metrics, stratum_metric):
                bucket = tm.by_confidence.setdefault(confidence, {"total": 0, "correct": 0})
                bucket["total"] += 1
                if outcome == "correct":
                    bucket["correct"] += 1

            # Signal attribution: when correct, which deterministic strategy or
            # LLM signal produced the win? Read from the candidate list when
            # available; otherwise look at evidence sources on the finding.
            if outcome == "correct":
                signals = _attribute_signals(result, name, predicted)
                for sig in signals:
                    signal_attribution[name][sig] = signal_attribution[name].get(sig, 0) + 1

            # Failure pattern: record a short tag describing what went wrong.
            if outcome in ("wrong", "missing"):
                tag = _classify_failure(name, outcome, predicted, expected, finding)
                failure_patterns[name].append(f"{ghsa}: {tag}")

            adv_entry["targets"][name] = {
                "expected": expected,
                "predicted": predicted,
                "confidence": confidence,
                "outcome": outcome,
            }
        per_advisory.append(adv_entry)

    summary_metrics = _aggregate_run_metrics(analysis)

    return EvalReport(
        label_count=len(labels),
        matched_count=matched_count,
        targets=targets,
        per_advisory=per_advisory,
        summary_metrics=summary_metrics,
        per_stratum=per_stratum,
        signal_attribution=signal_attribution,
        failure_patterns=failure_patterns,
    )


def _attribute_signals(result: dict[str, Any], target: str, predicted: str | None) -> list[str]:
    """Return short labels for which signals produced the correct prediction.

    For commit targets, look at the candidate matching `predicted` for its
    `strategies`. For all targets, look at the finding's evidence list for
    `source` tags. Returns deduplicated short labels.
    """
    signals: list[str] = []
    finding = result.get(target) or {}
    for ev in finding.get("evidence") or []:
        source = ev.get("source") if isinstance(ev, dict) else None
        if source:
            signals.append(source)
    if target.endswith("commit") and predicted:
        cand_key = "fix_candidates" if target == "fix_commit" else "introducer_candidates"
        for cand in (result.get(cand_key) or []):
            cand_sha = (cand.get("sha") or "").lower()
            if cand_sha and (cand_sha == predicted.lower() or cand_sha.startswith(predicted.lower()[:12])):
                for strat in cand.get("strategies") or []:
                    signals.append(f"strategy:{strat}")
                break
    return sorted(set(signals))


def _classify_failure(
    target: str, outcome: str, predicted: str | None, expected: str | None, finding: dict[str, Any]
) -> str:
    if outcome == "missing":
        return "no_prediction"
    confidence = (finding.get("confidence") or "unknown").lower()
    return f"wrong_at_{confidence}_confidence"


def _aggregate_run_metrics(analysis: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {
        "github_calls": 0,
        "github_cache_hits": 0,
        "openai_input_tokens": 0,
        "openai_output_tokens": 0,
        "openai_calls": 0,
        "estimated_openai_cost_usd": 0.0,
        "tool_calls_used": 0,
        "wall_clock_ms": 0,
    }
    for entry in analysis:
        metrics = entry.get("metrics") or {}
        for key in totals:
            if key == "estimated_openai_cost_usd":
                totals[key] += float(metrics.get(key) or 0)
            else:
                totals[key] += int(metrics.get(key) or 0)
    count = max(1, len(analysis))
    complete_findings = 0
    possible_findings = len(analysis) * len(TARGETS)
    tool_backed = 0
    for entry in analysis:
        for target in TARGETS:
            finding = entry.get(target) or {}
            if finding.get("value"):
                complete_findings += 1
                sources = {ev.get("source") for ev in finding.get("evidence") or [] if isinstance(ev, dict)}
                if "investigator" in sources or "evidence_critic" in sources:
                    tool_backed += 1
    return {
        "advisories_evaluated": len(analysis),
        "total_github_calls": totals["github_calls"],
        "total_github_cache_hits": totals["github_cache_hits"],
        "total_openai_input_tokens": totals["openai_input_tokens"],
        "total_openai_output_tokens": totals["openai_output_tokens"],
        "total_openai_calls": totals["openai_calls"],
        "estimated_openai_cost_usd": round(totals["estimated_openai_cost_usd"], 6),
        "total_tool_calls": totals["tool_calls_used"],
        "total_wall_clock_ms": totals["wall_clock_ms"],
        "avg_wall_clock_ms": int(totals["wall_clock_ms"] / count),
        "finding_fill_rate": (complete_findings / possible_findings) if possible_findings else None,
        "tool_backed_finding_rate": (tool_backed / complete_findings) if complete_findings else None,
    }


def render_report(report: EvalReport) -> str:
    lines: list[str] = []
    lines.append(f"Labels: {report.label_count} | Matched in analysis: {report.matched_count}")
    lines.append("")
    lines.append("== Overall ==")
    lines.extend(_render_target_table(report.targets))
    if report.per_stratum:
        for stratum in sorted(report.per_stratum):
            lines.append("")
            lines.append(f"== Stratum: {stratum} ==")
            lines.extend(_render_target_table(report.per_stratum[stratum]))
    if any(report.signal_attribution.values()):
        lines.append("")
        lines.append("== Signal attribution (correct predictions) ==")
        for name in TARGETS:
            attribution = report.signal_attribution.get(name) or {}
            if not attribution:
                continue
            entries = sorted(attribution.items(), key=lambda item: item[1], reverse=True)
            top = ", ".join(f"{k}={v}" for k, v in entries[:6])
            lines.append(f"  {name:22s} {top}")
    if any(report.failure_patterns.values()):
        lines.append("")
        lines.append("== Failure patterns ==")
        for name in TARGETS:
            failures = report.failure_patterns.get(name) or []
            if not failures:
                continue
            lines.append(f"  {name}:")
            for f in failures[:8]:
                lines.append(f"    {f}")
    if report.summary_metrics:
        lines.append("")
        m = report.summary_metrics
        lines.append(
            f"Run metrics: advisories={m.get('advisories_evaluated')} "
            f"github_calls={m.get('total_github_calls')} (cache_hits={m.get('total_github_cache_hits')}) "
            f"openai_calls={m.get('total_openai_calls')} "
            f"openai_tokens={m.get('total_openai_input_tokens')}/{m.get('total_openai_output_tokens')} (in/out) "
            f"tool_calls={m.get('total_tool_calls')} "
            f"wall_clock={m.get('total_wall_clock_ms')}ms "
            f"avg_wall_clock={m.get('avg_wall_clock_ms')}ms "
            f"cost=${m.get('estimated_openai_cost_usd')}"
        )
        lines.append(
            f"Production metrics: finding_fill_rate={_fmt_ratio(m.get('finding_fill_rate'))} "
            f"tool_backed_finding_rate={_fmt_ratio(m.get('tool_backed_finding_rate'))}"
        )
    return "\n".join(lines)


def _render_target_table(targets: dict[str, TargetMetrics]) -> list[str]:
    lines: list[str] = []
    header = f"{'Target':22s} {'P@1':>7s} {'Recall':>7s} {'L':>4s} {'P':>4s} {'C':>4s} {'W':>4s} {'M':>4s}  {'high':>6s} {'med':>6s} {'low':>6s}"
    lines.append(header)
    lines.append("-" * len(header))
    for name in TARGETS:
        tm = targets[name]
        lines.append(
            f"{tm.target:22s} "
            f"{_fmt_ratio(tm.precision_at_1):>7s} "
            f"{_fmt_ratio(tm.recall):>7s} "
            f"{tm.labeled:>4d} {tm.predicted:>4d} {tm.correct:>4d} {tm.wrong:>4d} {tm.missing:>4d}  "
            f"{_fmt_ratio(tm.calibration('high')):>6s} "
            f"{_fmt_ratio(tm.calibration('medium')):>6s} "
            f"{_fmt_ratio(tm.calibration('low')):>6s}"
        )
    return lines


def _fmt_ratio(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}"


def load_json_list(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON list at {path}")
    return data
