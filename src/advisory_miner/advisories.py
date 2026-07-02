from __future__ import annotations

from typing import Any

from .enrichers import enrich_advisory
from .github_client import GitHubClient
from .models import CollectedAdvisory, PackageVulnerability
from .extractors import extract_github_references


def fetch_advisory(client: GitHubClient, ghsa_id: str) -> dict[str, Any]:
    return client.get_json(f"/advisories/{ghsa_id}")


def fetch_advisories(
    client: GitHubClient,
    severity: str | None,
    limit: int,
    published: str | None = None,
    updated: str | None = None,
) -> list[dict[str, Any]]:
    """Walk GitHub's cursor-paginated /advisories endpoint via Link headers.

    The /advisories endpoint ignores ?page= and only honors the Link rel="next"
    cursor it returns in each response, so a naive page loop just re-fetches
    the same first window.
    """
    params: dict[str, Any] = {
        "sort": "updated",
        "direction": "desc",
        "per_page": min(100, max(1, limit)),
        "published": published,
        "updated": updated,
    }
    if severity:
        params["severity"] = severity.lower()

    advisories: list[dict[str, Any]] = []
    seen: set[str] = set()
    path: str = "/advisories"
    next_params: dict[str, Any] | None = params

    while True:
        data, next_url = client.request_with_link("GET", path, params=next_params)
        if not data:
            break
        for item in data:
            ghsa_id = item.get("ghsa_id") or item.get("ghsaId")
            if not ghsa_id or ghsa_id in seen:
                continue
            seen.add(ghsa_id)
            advisories.append(item)
            if len(advisories) >= limit:
                return advisories
        if not next_url:
            break
        path = next_url
        next_params = None
    return advisories


def normalize_advisory(raw: dict[str, Any], include_raw: bool = True, enrich: bool = False) -> CollectedAdvisory:
    identifiers = _identifiers(raw)
    cve_ids = _cve_ids(raw, identifiers)
    ghsa_id = raw.get("ghsa_id") or raw.get("ghsaId") or "UNKNOWN"
    enriched = None
    if enrich:
        try:
            enriched = enrich_advisory(ghsa_id if ghsa_id != "UNKNOWN" else None, cve_ids).to_dict()
        except Exception as exc:  # noqa: BLE001 - enrichment must not break collection
            enriched = {"errors": [f"enrich_advisory failed: {exc}"]}
    return CollectedAdvisory(
        ghsa_id=ghsa_id,
        cve_ids=cve_ids,
        url=raw.get("url"),
        html_url=raw.get("html_url") or raw.get("permalink"),
        summary=raw.get("summary"),
        description=raw.get("description"),
        type=raw.get("type"),
        severity=raw.get("severity"),
        repository_advisory_url=raw.get("repository_advisory_url"),
        source_code_location=raw.get("source_code_location"),
        identifiers=identifiers,
        references=_references(raw),
        published_at=raw.get("published_at"),
        updated_at=raw.get("updated_at"),
        github_reviewed_at=raw.get("github_reviewed_at"),
        nvd_published_at=raw.get("nvd_published_at"),
        withdrawn_at=raw.get("withdrawn_at"),
        vulnerabilities=_vulnerabilities(raw),
        cwes=raw.get("cwes") or [],
        cvss=raw.get("cvss") or {},
        cvss_severities=raw.get("cvss_severities") or {},
        credits=raw.get("credits") or [],
        extracted_github=extract_github_references(raw),
        enriched_refs=enriched,
        raw=raw if include_raw else None,
    )


def _identifiers(raw: dict[str, Any]) -> list[dict[str, Any]]:
    identifiers: list[dict[str, Any]] = []
    for item in raw.get("identifiers") or []:
        if isinstance(item, dict) and item.get("value"):
            identifiers.append({"type": item.get("type"), "value": item.get("value")})
    if raw.get("ghsa_id") and not any(item["value"] == raw["ghsa_id"] for item in identifiers):
        identifiers.insert(0, {"type": "GHSA", "value": raw["ghsa_id"]})
    if raw.get("cve_id") and not any(item["value"] == raw["cve_id"] for item in identifiers):
        identifiers.append({"type": "CVE", "value": raw["cve_id"]})
    return identifiers


def _cve_ids(raw: dict[str, Any], identifiers: list[dict[str, Any]]) -> list[str]:
    values = [item["value"] for item in identifiers if str(item.get("value", "")).upper().startswith("CVE-")]
    if raw.get("cve_id"):
        values.append(raw["cve_id"])
    return list(dict.fromkeys(values))


def _references(raw: dict[str, Any]) -> list[str]:
    references = []
    for item in raw.get("references") or []:
        if isinstance(item, str):
            references.append(item)
        elif isinstance(item, dict) and item.get("url"):
            references.append(item["url"])
    return references


def _vulnerabilities(raw: dict[str, Any]) -> list[PackageVulnerability]:
    vulnerabilities: list[PackageVulnerability] = []
    for item in raw.get("vulnerabilities") or []:
        package = item.get("package") or {}
        first_patched = item.get("first_patched_version")
        if isinstance(first_patched, dict):
            first_patched = first_patched.get("identifier")
        vulnerabilities.append(
            PackageVulnerability(
                ecosystem=package.get("ecosystem"),
                name=package.get("name"),
                vulnerable_version_range=item.get("vulnerable_version_range"),
                first_patched_version=first_patched,
                vulnerable_functions=item.get("vulnerable_functions") or [],
            )
        )
    return vulnerabilities
