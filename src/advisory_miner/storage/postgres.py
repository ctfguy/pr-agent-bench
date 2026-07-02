from __future__ import annotations

import json
import time
from typing import Any

from advisory_miner.models import AnalysisResult


class PostgresStore:
    def __init__(self, database_url: str):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except Exception as exc:  # pragma: no cover - depends on optional runtime install
            raise RuntimeError("psycopg[binary] is required for Postgres persistence") from exc
        self._psycopg = psycopg
        self.conn = psycopg.connect(database_url, autocommit=True, row_factory=dict_row)
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_runs (
              run_id TEXT PRIMARY KEY,
              session_id TEXT,
              input_path TEXT,
              output_path TEXT,
              config_json JSONB NOT NULL,
              started_at DOUBLE PRECISION NOT NULL,
              completed_at DOUBLE PRECISION,
              status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS advisories (
              ghsa_id TEXT PRIMARY KEY,
              advisory_json JSONB NOT NULL,
              updated_at DOUBLE PRECISION NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
              run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
              ghsa_id TEXT NOT NULL,
              result_json JSONB NOT NULL,
              repository TEXT,
              fix_commit TEXT,
              fix_pr TEXT,
              introduced_commit TEXT,
              introduced_pr TEXT,
              status TEXT NOT NULL,
              created_at DOUBLE PRECISION NOT NULL,
              PRIMARY KEY (run_id, ghsa_id)
            );

            CREATE TABLE IF NOT EXISTS evidence_items (
              id TEXT PRIMARY KEY,
              run_id TEXT REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
              ghsa_id TEXT,
              tool_name TEXT NOT NULL,
              values_json JSONB NOT NULL,
              input_json JSONB,
              output_json JSONB,
              created_at DOUBLE PRECISION NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_steps (
              id BIGSERIAL PRIMARY KEY,
              run_id TEXT REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
              ghsa_id TEXT,
              role TEXT NOT NULL,
              step_json JSONB NOT NULL,
              created_at DOUBLE PRECISION NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evaluations (
              id BIGSERIAL PRIMARY KEY,
              run_id TEXT,
              report_json JSONB NOT NULL,
              created_at DOUBLE PRECISION NOT NULL
            );
            """
        )

    def start_run(self, run_id: str, input_path: str, output_path: str, config: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO analysis_runs
              (run_id, session_id, input_path, output_path, config_json, started_at, completed_at, status)
            VALUES (%s, %s, %s, %s, %s, %s, NULL, 'running')
            ON CONFLICT (run_id) DO UPDATE SET
              session_id=EXCLUDED.session_id,
              input_path=EXCLUDED.input_path,
              output_path=EXCLUDED.output_path,
              config_json=EXCLUDED.config_json,
              started_at=EXCLUDED.started_at,
              completed_at=NULL,
              status='running'
            """,
            (
                run_id,
                config.get("langfuse_session_id"),
                input_path,
                output_path,
                json.dumps(config, sort_keys=True, default=str),
                time.time(),
            ),
        )

    def complete_run(self, run_id: str, status: str = "completed") -> None:
        self.conn.execute(
            "UPDATE analysis_runs SET completed_at=%s, status=%s WHERE run_id=%s",
            (time.time(), status, run_id),
        )

    def upsert_advisory(self, advisory: dict[str, Any]) -> None:
        ghsa_id = advisory.get("ghsa_id")
        if not ghsa_id:
            return
        self.conn.execute(
            """
            INSERT INTO advisories (ghsa_id, advisory_json, updated_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (ghsa_id) DO UPDATE SET
              advisory_json=EXCLUDED.advisory_json,
              updated_at=EXCLUDED.updated_at
            """,
            (ghsa_id, json.dumps(advisory, sort_keys=True, default=str), time.time()),
        )

    def record_result(self, run_id: str, result: AnalysisResult) -> None:
        payload = result.to_dict()
        status = "error" if result.errors else "completed"
        self.conn.execute(
            """
            INSERT INTO findings
              (run_id, ghsa_id, result_json, repository, fix_commit, fix_pr,
               introduced_commit, introduced_pr, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (run_id, ghsa_id) DO UPDATE SET
              result_json=EXCLUDED.result_json,
              repository=EXCLUDED.repository,
              fix_commit=EXCLUDED.fix_commit,
              fix_pr=EXCLUDED.fix_pr,
              introduced_commit=EXCLUDED.introduced_commit,
              introduced_pr=EXCLUDED.introduced_pr,
              status=EXCLUDED.status,
              created_at=EXCLUDED.created_at
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
        self.record_evidence_ledger(run_id, result)

    def record_evidence_ledger(self, run_id: str, result: AnalysisResult) -> None:
        ledger = result.signal_groups.get("evidence_ledger") or {}
        for item in ledger.get("items") or []:
            self.conn.execute(
                """
                INSERT INTO evidence_items
                  (id, run_id, ghsa_id, tool_name, values_json, input_json, output_json, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (
                    item.get("id"),
                    run_id,
                    result.ghsa_id,
                    item.get("tool_name"),
                    json.dumps(item.get("values") or [], sort_keys=True, default=str),
                    json.dumps(item.get("input"), sort_keys=True, default=str),
                    json.dumps(item.get("output"), sort_keys=True, default=str),
                    float(item.get("created_at") or time.time()),
                ),
            )

    def record_evaluation(self, run_id: str, report: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO evaluations (run_id, report_json, created_at) VALUES (%s, %s, %s)",
            (run_id, json.dumps(report, sort_keys=True, default=str), time.time()),
        )

    def close(self) -> None:
        self.conn.close()
