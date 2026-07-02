from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Config:
    github_token: str | None
    openai_api_key: str | None
    openai_model: str
    openai_validator_model: str
    agent_workers: int
    repo_cache_dir: Path
    per_advisory_cost_cap_usd: float | None
    db_path: Path | None
    database_url: str | None


def load_config() -> Config:
    return Config(
        github_token=os.environ.get("GITHUB_TOKEN"),
        openai_api_key=os.environ.get("OPENAI_API_KEY"),
        openai_model=os.environ.get("OPENAI_MODEL", "gpt-5-mini"),
        openai_validator_model=os.environ.get("OPENAI_VALIDATOR_MODEL", "gpt-5-mini"),
        agent_workers=int(os.environ.get("AGENT_WORKERS", "5")),
        repo_cache_dir=Path(os.environ.get("REPO_CACHE_DIR", ".cache/repos")),
        per_advisory_cost_cap_usd=_float_env("AGENT_COST_CAP_USD"),
        db_path=Path(os.environ.get("ADVISORY_MINER_DB", ".cache/advisory_miner.sqlite3")),
        database_url=os.environ.get("ADVISORY_MINER_DATABASE_URL"),
    )


def _float_env(name: str) -> float | None:
    value = os.environ.get(name)
    if not value:
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if parsed > 0 else None
