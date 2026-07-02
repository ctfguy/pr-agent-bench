from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from advisory_miner.agents.orchestrator import analyze_parallel, load_existing_analysis
from advisory_miner.models import AnalysisResult, Finding


class FakeAnalyzer:
    """Records the advisory it ran on; sleeps briefly so concurrency is observable."""

    def __init__(self, sleep: float = 0.0, fail_on: set[str] | None = None):
        self.sleep = sleep
        self.fail_on = fail_on or set()
        self.calls: list[str] = []

    def analyze(self, advisory: dict, skip_git: bool = False) -> AnalysisResult:
        ghsa = advisory["ghsa_id"]
        self.calls.append(ghsa)
        if ghsa in self.fail_on:
            raise RuntimeError(f"forced failure for {ghsa}")
        if self.sleep:
            time.sleep(self.sleep)
        result = AnalysisResult(ghsa_id=ghsa)
        result.repository = Finding(value="x/y", confidence="high")
        result.fix_commit = Finding(value=f"sha-{ghsa}", confidence="high")
        return result


def make_advisories(ids: list[str]) -> list[dict]:
    return [{"ghsa_id": g} for g in ids]


class AnalyzeParallelTests(unittest.TestCase):
    def test_processes_all_advisories(self):
        analyzer = FakeAnalyzer()
        results = analyze_parallel(
            make_advisories(["A", "B", "C"]),
            analyzer,
            workers=2,
            output_path=None,
            resume=False,
            progress=False,
        )
        self.assertEqual({r.ghsa_id for r in results}, {"A", "B", "C"})

    def test_isolates_per_advisory_errors(self):
        analyzer = FakeAnalyzer(fail_on={"B"})
        results = analyze_parallel(
            make_advisories(["A", "B", "C"]),
            analyzer,
            workers=2,
            output_path=None,
            resume=False,
            progress=False,
        )
        by_id = {r.ghsa_id: r for r in results}
        self.assertEqual(by_id["A"].fix_commit.value, "sha-A")
        self.assertEqual(by_id["B"].errors, ["forced failure for B"])
        self.assertEqual(by_id["C"].fix_commit.value, "sha-C")

    def test_resume_skips_already_analyzed_and_keeps_old_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "analyzed.json"
            # Pre-populate the output with a result for A.
            pre = [
                {
                    "ghsa_id": "A",
                    "fix_commit": {"value": "old-sha-A", "confidence": "high"},
                }
            ]
            output.write_text(json.dumps(pre), encoding="utf-8")

            analyzer = FakeAnalyzer()
            results = analyze_parallel(
                make_advisories(["A", "B"]),
                analyzer,
                workers=1,
                output_path=output,
                resume=True,
                progress=False,
            )

            # Only B was newly analyzed; A skipped.
            self.assertEqual(analyzer.calls, ["B"])
            self.assertEqual([r.ghsa_id for r in results], ["B"])

            # On-disk file contains BOTH the original A row and the new B row.
            payload = json.loads(output.read_text(encoding="utf-8"))
            by_id = {row["ghsa_id"]: row for row in payload}
            self.assertEqual(by_id["A"]["fix_commit"]["value"], "old-sha-A")
            self.assertEqual(by_id["B"]["fix_commit"]["value"], "sha-B")

    def test_partial_writes_after_each_advisory(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "analyzed.json"
            analyzer = FakeAnalyzer(sleep=0.01)
            analyze_parallel(
                make_advisories(["A", "B", "C", "D"]),
                analyzer,
                workers=1,
                output_path=output,
                resume=False,
                progress=False,
            )
            # The file must exist and contain all 4 rows.
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual({row["ghsa_id"] for row in payload}, {"A", "B", "C", "D"})


class ResumeHelperTests(unittest.TestCase):
    def test_load_existing_returns_empty_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows, seen = load_existing_analysis(Path(tmp) / "missing.json")
            self.assertEqual(rows, [])
            self.assertEqual(seen, set())

    def test_load_existing_extracts_ghsa_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "analyzed.json"
            path.write_text(
                json.dumps([{"ghsa_id": "X"}, {"ghsa_id": "Y"}, {"no_id": True}]),
                encoding="utf-8",
            )
            rows, seen = load_existing_analysis(path)
            self.assertEqual(seen, {"X", "Y"})
            self.assertEqual(len(rows), 3)


if __name__ == "__main__":
    unittest.main()
