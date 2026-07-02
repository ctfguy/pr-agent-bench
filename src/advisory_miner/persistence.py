from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from advisory_miner.models import AnalysisResult


class SQLiteStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS analysis_runs (
              run_id TEXT PRIMARY KEY,
              input_path TEXT,
              output_path TEXT,
              config_json TEXT NOT NULL,
              started_at REAL NOT NULL,
              completed_at REAL,
              status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS advisories (
              ghsa_id TEXT PRIMARY KEY,
              advisory_json TEXT NOT NULL,
              updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
              run_id TEXT NOT NULL,
              ghsa_id TEXT NOT NULL,
              result_json TEXT NOT NULL,
              repository TEXT,
              fix_commit TEXT,
              fix_pr TEXT,
              introduced_commit TEXT,
              introduced_pr TEXT,
              status TEXT NOT NULL,
              created_at REAL NOT NULL,
              PRIMARY KEY (run_id, ghsa_id),
              FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS tool_calls (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT,
              ghsa_id TEXT,
              step_name TEXT,
              tool_name TEXT,
              input_json TEXT,
              output_json TEXT,
              duration_ms INTEGER,
              error TEXT,
              created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS llm_calls (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT,
              ghsa_id TEXT,
              step_name TEXT,
              model TEXT,
              input_tokens INTEGER,
              output_tokens INTEGER,
              cost_usd REAL,
              response_json TEXT,
              error TEXT,
              created_at REAL NOT NULL
            );
            """
        )
        self.conn.commit()

    def start_run(self, run_id: str, input_path: str, output_path: str, config: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO analysis_runs
              (run_id, input_path, output_path, config_json, started_at, completed_at, status)
            VALUES (?, ?, ?, ?, ?, NULL, 'running')
            """,
            (run_id, input_path, output_path, json.dumps(config, sort_keys=True), time.time()),
        )
        self.conn.commit()

    def complete_run(self, run_id: str, status: str = "completed") -> None:
        self.conn.execute(
            "UPDATE analysis_runs SET completed_at=?, status=? WHERE run_id=?",
            (time.time(), status, run_id),
        )
        self.conn.commit()

    def upsert_advisory(self, advisory: dict[str, Any]) -> None:
        ghsa_id = advisory.get("ghsa_id")
        if not ghsa_id:
            return
        self.conn.execute(
            """
            INSERT OR REPLACE INTO advisories (ghsa_id, advisory_json, updated_at)
            VALUES (?, ?, ?)
            """,
            (ghsa_id, json.dumps(advisory, sort_keys=True, default=str), time.time()),
        )
        self.conn.commit()

    def record_result(self, run_id: str, result: AnalysisResult) -> None:
        payload = result.to_dict()
        status = "error" if result.errors else "completed"
        self.conn.execute(
            """
            INSERT OR REPLACE INTO findings
              (run_id, ghsa_id, result_json, repository, fix_commit, fix_pr,
               introduced_commit, introduced_pr, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                result.ghsa_id,
                json.dumps(payload, sort_keys=True, default=str),
                result.repository.value,
                result.fix_commit.value,
                result.fix_pr.value,
                result.introduced_commit.value,
                result.introduced_pr.value,
                status,
                time.time(),
            ),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


def make_run_id(prefix: str = "run") -> str:
    return f"{prefix}-{int(time.time() * 1000)}"
