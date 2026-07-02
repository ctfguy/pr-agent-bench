from __future__ import annotations

import json
from pathlib import Path

from .advisories import fetch_advisories, fetch_advisory, normalize_advisory
from .extractors import extract_ghsa_id
from .github_client import GitHubClient
from .models import CollectedAdvisory


def collect_by_advisory_id(
    client: GitHubClient, ghsa_id: str, include_raw: bool = True, enrich: bool = True
) -> CollectedAdvisory:
    raw = fetch_advisory(client, ghsa_id)
    return normalize_advisory(raw, include_raw=include_raw, enrich=enrich)


def collect_by_url(
    client: GitHubClient, url: str, include_raw: bool = True, enrich: bool = True
) -> CollectedAdvisory:
    ghsa_id = extract_ghsa_id(url)
    if not ghsa_id:
        raise ValueError(f"Could not extract GHSA ID from URL: {url}")
    return collect_by_advisory_id(client, ghsa_id, include_raw=include_raw, enrich=enrich)


def collect_latest(
    client: GitHubClient,
    limit: int,
    severity: str | None,
    published: str | None = None,
    updated: str | None = None,
    include_raw: bool = True,
    enrich: bool = True,
) -> list[CollectedAdvisory]:
    raws = fetch_advisories(client, severity=severity, limit=limit, published=published, updated=updated)
    advisories = [normalize_advisory(raw, include_raw=include_raw, enrich=enrich) for raw in raws]
    unique = {advisory.ghsa_id for advisory in advisories}
    if len(unique) != len(advisories):
        raise ValueError(
            f"collector produced duplicate GHSA ids: {len(advisories)} rows, {len(unique)} unique"
        )
    return advisories


def write_collected(path: Path, advisories: list[CollectedAdvisory]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [advisory.to_dict() for advisory in advisories]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def date_range(since: str | None, until: str | None) -> str | None:
    if since and until:
        return f"{since}..{until}"
    if since:
        return f">={since}"
    if until:
        return f"<={until}"
    return None
