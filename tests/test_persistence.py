from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from advisory_miner.models import AnalysisResult, Finding
from advisory_miner.persistence import SQLiteStore, make_run_id


class PersistenceTests(unittest.TestCase):
    def test_records_run_advisory_and_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "runs.sqlite3"
            store = SQLiteStore(db_path)
            run_id = make_run_id("test")
            store.start_run(run_id, "input.json", "output.json", {"workers": 1})
            store.upsert_advisory({"ghsa_id": "GHSA-test-test-test", "summary": "x"})
            result = AnalysisResult(ghsa_id="GHSA-test-test-test")
            result.repository = Finding(value="owner/repo", confidence="high")
            result.fix_commit = Finding(value="a" * 40, confidence="high")
            store.record_result(run_id, result)
            store.complete_run(run_id)
            store.close()

            conn = sqlite3.connect(db_path)
            self.assertEqual(conn.execute("SELECT status FROM analysis_runs WHERE run_id=?", (run_id,)).fetchone()[0], "completed")
            self.assertEqual(conn.execute("SELECT ghsa_id FROM advisories").fetchone()[0], "GHSA-test-test-test")
            row = conn.execute("SELECT repository, fix_commit, status FROM findings").fetchone()
            self.assertEqual(row, ("owner/repo", "a" * 40, "completed"))
            conn.close()


if __name__ == "__main__":
    unittest.main()
