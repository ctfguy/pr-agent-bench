from __future__ import annotations

import re
from typing import Any

from .models import ExtractedGitHubRefs, GitHubRef


GITHUB_URL_RE = re.compile(r"https?://(?:api\.)?github\.com/[^\s<>)\]\"']+")
ADVISORY_ID_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)
API_REPO_RE = re.compile(r"https?://api\.github\.com/repos/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)(?:/|$)")
API_COMMIT_RE = re.compile(
    r"https?://api\.github\.com/repos/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/commits/(?P<sha>[0-9a-fA-F]{7,40})"
)
API_PR_RE = re.compile(
    r"https?://api\.github\.com/repos/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/pulls/(?P<number>\d+)"
)
API_ISSUE_RE = re.compile(
    r"https?://api\.github\.com/repos/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/issues/(?P<number>\d+)"
)
COMMIT_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/commit/(?P<sha>[0-9a-fA-F]{7,40})"
)
PR_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/(?:pull|pulls)/(?P<number>\d+)"
)
ISSUE_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/issues/(?P<number>\d+)"
)
COMPARE_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/compare/(?P<spec>[^\s<>)\]\"']+)"
)
RELEASE_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/releases(?:/tag/(?P<tag>[^\s<>)\]\"']+))?"
)
# /<owner>/<repo>/security/advisories/GHSA-... — strong signal of the real repo even when
# the advisory body inlines image URLs hosted under user-attachments/assets.
SECURITY_ADVISORY_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/security/advisories/"
)
REPO_RE = re.compile(r"https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s#?]+)")


def extract_ghsa_id(value: str) -> str | None:
    match = ADVISORY_ID_RE.search(value or "")
    return match.group(0).upper() if match else None


def extract_github_references(raw: dict[str, Any]) -> ExtractedGitHubRefs:
    urls = _candidate_urls(raw)
    extracted = ExtractedGitHubRefs()
    repo_seen: set[str] = set()
    other_seen: set[str] = set()

    for url in urls:
        refs = _extract_from_url(url)
        if not refs:
            if "github.com" in url and not _is_advisory_url(url) and url not in other_seen:
                extracted.other_urls.append(url)
                other_seen.add(url)
            continue
        for ref in refs:
            if _looks_like_repo(ref.owner, ref.repo) and ref.repository not in repo_seen:
                extracted.repositories.append(ref.repository)
                repo_seen.add(ref.repository)
            if ref.kind == "pull_request":
                _append_unique(extracted.pull_requests, ref)
            elif ref.kind == "commit":
                _append_unique(extracted.commits, ref)
            elif ref.kind == "issue":
                _append_unique(extracted.issues, ref)
            elif ref.kind == "compare":
                _append_unique(extracted.compare_urls, ref)
            elif ref.kind == "release":
                _append_unique(extracted.release_urls, ref)

    return extracted


def _candidate_urls(raw: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("summary", "description", "source_code_location", "repository_advisory_url", "html_url", "url"):
        value = raw.get(key)
        if isinstance(value, str):
            values.extend(_urls_from_text(value))
    for item in raw.get("references") or []:
        if isinstance(item, str):
            values.extend(_urls_from_text(item))
        elif isinstance(item, dict) and isinstance(item.get("url"), str):
            values.extend(_urls_from_text(item["url"]))
    return list(dict.fromkeys(values))


def _urls_from_text(text: str) -> list[str]:
    urls = [_clean_url(match.group(0)) for match in GITHUB_URL_RE.finditer(text or "")]
    if text.startswith("http://") or text.startswith("https://"):
        urls.append(_clean_url(text))
    return list(dict.fromkeys(urls))


def _extract_from_url(url: str) -> list[GitHubRef]:
    clean_url = _clean_url(url)

    # `/security/advisories/` URLs name the true repo even when the rest of
    # the advisory body inlines `github.com/user-attachments/assets/...`
    # image URLs that the catch-all REPO_RE would otherwise match first.
    security_match = SECURITY_ADVISORY_RE.search(clean_url)
    if security_match:
        repo = _clean_repo(security_match.group("repo"))
        owner = security_match.group("owner")
        if _looks_like_repo(owner, repo):
            return [
                GitHubRef(
                    owner=owner,
                    repo=repo,
                    kind="repo",
                    value=f"{owner}/{repo}",
                    url=clean_url,
                )
            ]

    api_commit_match = API_COMMIT_RE.search(clean_url)
    if api_commit_match:
        repo = _clean_repo(api_commit_match.group("repo"))
        return [
            GitHubRef(
                owner=api_commit_match.group("owner"),
                repo=repo,
                kind="commit",
                value=api_commit_match.group("sha"),
                url=clean_url,
            )
        ]

    api_pr_match = API_PR_RE.search(clean_url)
    if api_pr_match:
        repo = _clean_repo(api_pr_match.group("repo"))
        return [
            GitHubRef(
                owner=api_pr_match.group("owner"),
                repo=repo,
                kind="pull_request",
                value=api_pr_match.group("number"),
                url=clean_url,
            )
        ]

    api_issue_match = API_ISSUE_RE.search(clean_url)
    if api_issue_match:
        repo = _clean_repo(api_issue_match.group("repo"))
        return [
            GitHubRef(
                owner=api_issue_match.group("owner"),
                repo=repo,
                kind="issue",
                value=api_issue_match.group("number"),
                url=clean_url,
            )
        ]

    api_repo_match = API_REPO_RE.search(clean_url)
    if api_repo_match:
        repo = _clean_repo(api_repo_match.group("repo"))
        return [
            GitHubRef(
                owner=api_repo_match.group("owner"),
                repo=repo,
                kind="repo",
                value=f"{api_repo_match.group('owner')}/{repo}",
                url=clean_url,
            )
        ]

    commit_match = COMMIT_RE.search(clean_url)
    if commit_match:
        repo = _clean_repo(commit_match.group("repo"))
        return [
            GitHubRef(
                owner=commit_match.group("owner"),
                repo=repo,
                kind="commit",
                value=commit_match.group("sha"),
                url=clean_url,
            )
        ]

    pr_match = PR_RE.search(clean_url)
    if pr_match:
        repo = _clean_repo(pr_match.group("repo"))
        return [
            GitHubRef(
                owner=pr_match.group("owner"),
                repo=repo,
                kind="pull_request",
                value=pr_match.group("number"),
                url=clean_url,
            )
        ]

    issue_match = ISSUE_RE.search(clean_url)
    if issue_match:
        repo = _clean_repo(issue_match.group("repo"))
        return [
            GitHubRef(
                owner=issue_match.group("owner"),
                repo=repo,
                kind="issue",
                value=issue_match.group("number"),
                url=clean_url,
            )
        ]

    compare_match = COMPARE_RE.search(clean_url)
    if compare_match:
        repo = _clean_repo(compare_match.group("repo"))
        return [
            GitHubRef(
                owner=compare_match.group("owner"),
                repo=repo,
                kind="compare",
                value=compare_match.group("spec"),
                url=clean_url,
            )
        ]

    release_match = RELEASE_RE.search(clean_url)
    if release_match:
        repo = _clean_repo(release_match.group("repo"))
        return [
            GitHubRef(
                owner=release_match.group("owner"),
                repo=repo,
                kind="release",
                value=release_match.group("tag") or "releases",
                url=clean_url,
            )
        ]

    repo_match = REPO_RE.search(clean_url)
    if repo_match:
        repo = _clean_repo(repo_match.group("repo"))
        if _looks_like_repo(repo_match.group("owner"), repo):
            return [
                GitHubRef(
                    owner=repo_match.group("owner"),
                    repo=repo,
                    kind="repo",
                    value=f"{repo_match.group('owner')}/{repo}",
                    url=clean_url,
                )
            ]
    return []


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:)]}")


def _clean_repo(repo: str) -> str:
    repo = repo.rstrip(".,;:)]}")
    if repo.endswith(".git"):
        repo = repo[:-4]
    return repo


def _looks_like_repo(owner: str, repo: str) -> bool:
    blocked = {"advisories", "security", "topics", "marketplace", "features", "explore"}
    # GitHub-hosted attachments and avatars look like /owner/path URLs but are not repos.
    blocked_owners = {"user-attachments", "user-images", "avatars", "raw"}
    if owner.lower() == "github" and repo.lower() == "advisories":
        return False
    if owner.lower() in blocked_owners:
        return False
    if owner.lower() in blocked or repo.lower() in blocked:
        return False
    return bool(owner and repo)


def _is_advisory_url(url: str) -> bool:
    return bool(re.search(r"https?://(?:api\.)?github\.com/(?:advisories/|advisories$)", url))


def _append_unique(refs: list[GitHubRef], ref: GitHubRef) -> None:
    key = (ref.owner.lower(), ref.repo.lower(), ref.kind, ref.value.lower())
    if key not in {(item.owner.lower(), item.repo.lower(), item.kind, item.value.lower()) for item in refs}:
        refs.append(ref)
