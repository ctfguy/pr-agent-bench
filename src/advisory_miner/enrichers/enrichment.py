"""Pull supplementary advisory data from OSV and NVD.

Both APIs are public, no auth required. OSV often provides structured
`affected[].ranges[].events` with explicit `introduced` and `fixed` commit
SHAs that the GitHub Advisory Database doesn't expose at all. NVD provides
extra reference URLs and cleaner CVE descriptions.

Failures from either source are non-fatal — enrichment is additive.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any


logger = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1/vulns/"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HTTP_TIMEOUT = 15


# Matches /<owner>/<repo>/commit/<sha> for any URL form.
GITHUB_COMMIT_RE = re.compile(
    r"https?://(?:api\.)?github\.com/(?:repos/)?([^/\s]+)/([^/\s]+)/commit[s]?/([0-9a-fA-F]{7,40})"
)


@dataclass
class EnrichedRefs:
    osv_id: str | None = None
    osv_aliases: list[str] = field(default_factory=list)
    osv_introduced_commits: list[str] = field(default_factory=list)
    osv_fixed_commits: list[str] = field(default_factory=list)
    osv_affected_packages: list[dict[str, Any]] = field(default_factory=list)
    osv_references: list[str] = field(default_factory=list)
    nvd_references: list[str] = field(default_factory=list)
    extra_github_commit_urls: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def enrich_advisory(ghsa_id: str | None, cve_ids: list[str] | None) -> EnrichedRefs:
    refs = EnrichedRefs()
    if ghsa_id:
        try:
            _merge_osv(refs, _fetch_osv(ghsa_id))
            refs.sources.append(f"osv:{ghsa_id}")
        except _EnricherError as exc:
            refs.errors.append(f"osv[{ghsa_id}]: {exc}")
    for cve in cve_ids or []:
        try:
            _merge_osv(refs, _fetch_osv(cve))
            refs.sources.append(f"osv:{cve}")
        except _EnricherError as exc:
            refs.errors.append(f"osv[{cve}]: {exc}")
        try:
            _merge_nvd(refs, _fetch_nvd(cve))
            refs.sources.append(f"nvd:{cve}")
        except _EnricherError as exc:
            refs.errors.append(f"nvd[{cve}]: {exc}")
    return refs


class _EnricherError(RuntimeError):
    pass


def _fetch_osv(identifier: str) -> dict[str, Any] | None:
    url = OSV_API + urllib.parse.quote(identifier, safe="")
    request = urllib.request.Request(url, headers={"User-Agent": "pr-agent-bench-data"})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise _EnricherError(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise _EnricherError(str(exc)) from exc


def _fetch_nvd(cve: str) -> dict[str, Any] | None:
    url = NVD_API + "?cveId=" + urllib.parse.quote(cve, safe="")
    request = urllib.request.Request(url, headers={"User-Agent": "pr-agent-bench-data"})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise _EnricherError(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise _EnricherError(str(exc)) from exc


def _merge_osv(refs: EnrichedRefs, data: dict[str, Any] | None) -> None:
    if not data:
        return
    if not refs.osv_id:
        refs.osv_id = data.get("id")
    for alias in data.get("aliases") or []:
        if isinstance(alias, str) and alias not in refs.osv_aliases:
            refs.osv_aliases.append(alias)
    for ref in data.get("references") or []:
        url = ref.get("url") if isinstance(ref, dict) else None
        if url and url not in refs.osv_references:
            refs.osv_references.append(url)
        if url:
            for owner, repo, sha in GITHUB_COMMIT_RE.findall(url):
                normalized = f"https://github.com/{owner}/{repo}/commit/{sha}"
                if normalized not in refs.extra_github_commit_urls:
                    refs.extra_github_commit_urls.append(normalized)
    for affected in data.get("affected") or []:
        package = affected.get("package") if isinstance(affected, dict) else None
        package_summary: dict[str, Any] = {}
        if isinstance(package, dict):
            package_summary = {
                "ecosystem": package.get("ecosystem"),
                "name": package.get("name"),
            }
        ranges = affected.get("ranges") or [] if isinstance(affected, dict) else []
        for range_block in ranges:
            if not isinstance(range_block, dict):
                continue
            range_type = (range_block.get("type") or "").upper()
            for event in range_block.get("events") or []:
                if not isinstance(event, dict):
                    continue
                introduced = event.get("introduced")
                fixed = event.get("fixed")
                if range_type == "GIT":
                    if introduced and _looks_like_sha(introduced) and introduced not in refs.osv_introduced_commits:
                        refs.osv_introduced_commits.append(introduced)
                    if fixed and _looks_like_sha(fixed) and fixed not in refs.osv_fixed_commits:
                        refs.osv_fixed_commits.append(fixed)
                if introduced or fixed:
                    package_summary.setdefault("ranges", []).append(
                        {"type": range_type, "introduced": introduced, "fixed": fixed}
                    )
        if package_summary:
            refs.osv_affected_packages.append(package_summary)


def _merge_nvd(refs: EnrichedRefs, data: dict[str, Any] | None) -> None:
    if not data:
        return
    vulnerabilities = data.get("vulnerabilities") or []
    for entry in vulnerabilities:
        cve = entry.get("cve") if isinstance(entry, dict) else None
        if not isinstance(cve, dict):
            continue
        for ref in cve.get("references") or []:
            url = ref.get("url") if isinstance(ref, dict) else None
            if url and url not in refs.nvd_references:
                refs.nvd_references.append(url)
            if url:
                for owner, repo, sha in GITHUB_COMMIT_RE.findall(url):
                    normalized = f"https://github.com/{owner}/{repo}/commit/{sha}"
                    if normalized not in refs.extra_github_commit_urls:
                        refs.extra_github_commit_urls.append(normalized)


def _looks_like_sha(value: str | None) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) < 7 or len(value) > 40:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)
