from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from advisory_miner.eval import (
    EvalReport,
    evaluate,
    prs_match,
    render_report,
    shas_match,
)


SAMPLE_LABELS = [
    {
        "ghsa_id": "GHSA-aaaa-aaaa-aaaa",
        "expected_fix_commit": "abc1234567890def1234567890abcdef12345678",
        "expected_fix_pr": "owner/repo#42",
        "expected_introduced_commit": "fedcba0987654321fedcba0987654321fedcba09",
        "expected_introduced_pr": None,
    },
    {
        "ghsa_id": "GHSA-bbbb-bbbb-bbbb",
        "expected_fix_commit": None,
        "expected_fix_pr": "owner/repo#7",
        "expected_introduced_commit": None,
        "expected_introduced_pr": None,
    },
    {
        "ghsa_id": "GHSA-cccc-cccc-cccc",
        "expected_fix_commit": "1111111111111111111111111111111111111111",
        "expected_fix_pr": None,
        "expected_introduced_commit": None,
        "expected_introduced_pr": None,
    },
]


def finding(value, confidence="high"):
    return {"value": value, "url": None, "confidence": confidence, "evidence": []}


SAMPLE_ANALYSIS = [
    {
        "ghsa_id": "GHSA-aaaa-aaaa-aaaa",
        "fix_commit": finding("abc1234"),
        "fix_pr": finding("OWNER/REPO#42", confidence="medium"),
        "introduced_commit": finding("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", confidence="medium"),
        "introduced_pr": finding(None, confidence="unknown"),
    },
    {
        "ghsa_id": "GHSA-bbbb-bbbb-bbbb",
        "fix_commit": finding(None, confidence="unknown"),
        "fix_pr": finding(None, confidence="unknown"),
        "introduced_commit": finding(None, confidence="unknown"),
        "introduced_pr": finding(None, confidence="unknown"),
    },
    {
        "ghsa_id": "GHSA-cccc-cccc-cccc",
        "fix_commit": finding("2222222222222222222222222222222222222222"),
        "fix_pr": finding(None, confidence="unknown"),
        "introduced_commit": finding(None, confidence="unknown"),
        "introduced_pr": finding(None, confidence="unknown"),
    },
]


class MatcherTests(unittest.TestCase):
    def test_shas_match_accepts_prefix(self):
        self.assertTrue(shas_match("abc1234", "abc1234567890def"))
        self.assertTrue(shas_match("abc1234567890def", "abc1234"))

    def test_shas_match_rejects_short(self):
        self.assertFalse(shas_match("abc12", "abc1234567890def"))

    def test_shas_match_case_insensitive(self):
        self.assertTrue(shas_match("ABC1234", "abc1234"))

    def test_shas_match_rejects_mismatch(self):
        self.assertFalse(shas_match("abc1234", "xyz9876"))

    def test_prs_match_case_insensitive(self):
        self.assertTrue(prs_match("Owner/Repo#42", "owner/repo#42"))

    def test_prs_match_rejects_mismatch(self):
        self.assertFalse(prs_match("owner/repo#42", "owner/repo#43"))


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self.report = evaluate(SAMPLE_LABELS, SAMPLE_ANALYSIS)

    def test_matched_count(self):
        self.assertEqual(self.report.matched_count, 3)
        self.assertEqual(self.report.label_count, 3)

    def test_fix_commit_precision(self):
        tm = self.report.targets["fix_commit"]
        self.assertEqual(tm.labeled, 2)        # GHSA-aaaa and GHSA-cccc are labeled
        self.assertEqual(tm.predicted, 2)      # both produced a non-null prediction
        self.assertEqual(tm.correct, 1)        # GHSA-aaaa matches
        self.assertEqual(tm.wrong, 1)          # GHSA-cccc mispredicts
        self.assertEqual(tm.precision_at_1, 0.5)

    def test_fix_pr_precision(self):
        tm = self.report.targets["fix_pr"]
        self.assertEqual(tm.labeled, 2)        # GHSA-aaaa and GHSA-bbbb labeled
        self.assertEqual(tm.predicted, 1)      # only GHSA-aaaa predicted
        self.assertEqual(tm.correct, 1)
        self.assertEqual(tm.missing, 1)
        self.assertEqual(tm.precision_at_1, 1.0)
        self.assertEqual(tm.recall, 0.5)

    def test_introducer_commit_wrong_when_predicted_mismatch(self):
        tm = self.report.targets["introduced_commit"]
        self.assertEqual(tm.labeled, 1)
        self.assertEqual(tm.predicted, 1)
        self.assertEqual(tm.wrong, 1)
        self.assertEqual(tm.correct, 0)

    def test_calibration_tracks_high_confidence(self):
        tm = self.report.targets["fix_commit"]
        # GHSA-aaaa fix_commit: predicted with high, correct
        # GHSA-cccc fix_commit: predicted with high, wrong
        self.assertEqual(tm.by_confidence["high"]["total"], 2)
        self.assertEqual(tm.by_confidence["high"]["correct"], 1)
        self.assertAlmostEqual(tm.calibration("high"), 0.5)

    def test_per_advisory_includes_outcome(self):
        entries = {e["ghsa_id"]: e for e in self.report.per_advisory}
        self.assertEqual(entries["GHSA-aaaa-aaaa-aaaa"]["targets"]["fix_commit"]["outcome"], "correct")
        self.assertEqual(entries["GHSA-cccc-cccc-cccc"]["targets"]["fix_commit"]["outcome"], "wrong")
        self.assertEqual(entries["GHSA-bbbb-bbbb-bbbb"]["targets"]["fix_pr"]["outcome"], "missing")
        self.assertEqual(entries["GHSA-aaaa-aaaa-aaaa"]["targets"]["introduced_pr"]["outcome"], "unlabeled")

    def test_unmatched_label_recorded(self):
        labels = SAMPLE_LABELS + [{"ghsa_id": "GHSA-zzzz-zzzz-zzzz", "expected_fix_commit": "abc1234567"}]
        report = evaluate(labels, SAMPLE_ANALYSIS)
        self.assertEqual(report.matched_count, 3)
        entries = {e["ghsa_id"]: e for e in report.per_advisory}
        self.assertEqual(entries["GHSA-zzzz-zzzz-zzzz"]["status"], "missing_from_analysis")

    def test_render_report_contains_targets(self):
        text = render_report(self.report)
        self.assertIn("fix_commit", text)
        self.assertIn("fix_pr", text)
        self.assertIn("introduced_commit", text)
        self.assertIn("introduced_pr", text)


class CliEvalTests(unittest.TestCase):
    def test_eval_cli_writes_report(self):
        from advisory_miner.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            labels_path = Path(tmp) / "labels.json"
            analysis_path = Path(tmp) / "analysis.json"
            report_path = Path(tmp) / "report.json"
            labels_path.write_text(json.dumps(SAMPLE_LABELS), encoding="utf-8")
            analysis_path.write_text(json.dumps(SAMPLE_ANALYSIS), encoding="utf-8")
            exit_code = main([
                "eval",
                "--labels", str(labels_path),
                "--analysis", str(analysis_path),
                "--report", str(report_path),
            ])
            self.assertEqual(exit_code, 0)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["matched_count"], 3)
            self.assertEqual(report["targets"]["fix_commit"]["correct"], 1)


if __name__ == "__main__":
    unittest.main()
