from __future__ import annotations

import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

from .runtime import RateBudget, ResponseCache, current_metrics


LINK_RE = re.compile(r'<([^>]+)>\s*;\s*rel="([^"]+)"')


def parse_link_next(link_header: str | None) -> str | None:
    """Return the URL marked rel="next" in a GitHub Link header, if any."""
    if not link_header:
        return None
    for url, rel in LINK_RE.findall(link_header):
        if rel == "next":
            return url
    return None


class GitHubApiError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status = status
        self.body = body


class GitHubClient:
    """Small stdlib GitHub REST client with retry and rate-limit handling."""

    def __init__(
        self,
        token: str | None,
        max_retries: int = 3,
        timeout: int = 30,
        cache: ResponseCache | None = None,
        budget: RateBudget | None = None,
    ):
        self.token = token
        self.max_retries = max_retries
        self.timeout = timeout
        self.api_root = "https://api.github.com"
        self.cache = cache
        self.budget = budget

    def get_json(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        accept: str = "application/vnd.github+json",
    ) -> Any:
        return self.request_json("GET", path, params=params, accept=accept)

    def request_json(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        accept: str = "application/vnd.github+json",
    ) -> Any:
        data, _ = self._do_request(method, path, params, payload, accept)
        return data

    def request_with_link(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        accept: str = "application/vnd.github+json",
    ) -> tuple[Any, str | None]:
        """Like request_json but also returns the Link rel="next" URL when present."""
        data, headers = self._do_request(method, path, params, payload, accept)
        return data, parse_link_next(headers.get("Link"))

    def _do_request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None,
        payload: dict[str, Any] | None,
        accept: str,
    ) -> tuple[Any, Mapping[str, str]]:
        url = self._build_url(path, params)

        cache_key = self._cache_key(method, url) if self._cache_eligible(method, url) else None
        if cache_key and self.cache is not None:
            cached = self.cache.get(cache_key)
            if cached is not None:
                current_metrics().github_cache_hits += 1
                return cached.get("data"), cached.get("headers") or {}

        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": accept,
            "Content-Type": "application/json",
            "User-Agent": "pr-agent-bench-data",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        for attempt in range(self.max_retries + 1):
            if self.budget is not None:
                self.budget.acquire()
            request = urllib.request.Request(url, data=body, method=method, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8")
                    response_headers = dict(response.headers.items())
                    data = json.loads(raw) if raw else None
                    current_metrics().github_calls += 1
                    if self.budget is not None:
                        self.budget.update_from_headers(response_headers)
                    if cache_key and self.cache is not None:
                        self.cache.set(cache_key, {"data": data, "headers": response_headers})
                    return data, response_headers
            except urllib.error.HTTPError as exc:
                raw_body = exc.read().decode("utf-8", errors="replace")
                error_headers = dict(exc.headers.items()) if exc.headers else {}
                if self.budget is not None:
                    self.budget.update_from_headers(error_headers)
                    if exc.code in {403, 429}:
                        retry_after = error_headers.get("Retry-After")
                        if retry_after and retry_after.isdigit():
                            self.budget.secondary_backoff(float(retry_after))
                if not self._should_retry(exc.code, exc.headers, attempt):
                    raise GitHubApiError(
                        f"GitHub API request failed: {method} {url} -> {exc.code}",
                        status=exc.code,
                        body=raw_body,
                    ) from exc
                self._sleep_before_retry(exc.code, exc.headers, attempt)
            except urllib.error.URLError as exc:
                if attempt >= self.max_retries:
                    raise GitHubApiError(f"GitHub API request failed: {method} {url}: {exc}") from exc
                self._sleep_before_retry(None, {}, attempt)

        raise GitHubApiError(f"GitHub API request failed after retries: {method} {url}")

    def _cache_eligible(self, method: str, url: str) -> bool:
        if method != "GET":
            return False
        # Search endpoints can mutate as upstream data changes; cache only within a single run.
        # We keep them eligible here for simplicity — a fresh cache dir per run is the practical TTL.
        return True

    def _cache_key(self, method: str, url: str) -> str:
        return ResponseCache.key("github", method, url)

    def get_pull(self, owner: str, repo: str, number: int) -> dict[str, Any] | None:
        try:
            return self.get_json(f"/repos/{owner}/{repo}/pulls/{number}")
        except GitHubApiError:
            return None

    def get_pull_commits(self, owner: str, repo: str, number: int) -> list[dict[str, Any]]:
        try:
            return self.get_json(
                f"/repos/{owner}/{repo}/pulls/{number}/commits",
                params={"per_page": 100},
            ) or []
        except GitHubApiError:
            return []

    def get_pull_files(self, owner: str, repo: str, number: int) -> list[dict[str, Any]]:
        try:
            return self.get_json(
                f"/repos/{owner}/{repo}/pulls/{number}/files",
                params={"per_page": 100},
            ) or []
        except GitHubApiError:
            return []

    def get_commit(self, owner: str, repo: str, sha: str) -> dict[str, Any] | None:
        try:
            return self.get_json(f"/repos/{owner}/{repo}/commits/{sha}")
        except GitHubApiError:
            return None

    def get_commit_pulls(self, owner: str, repo: str, sha: str) -> list[dict[str, Any]]:
        try:
            return self.get_json(f"/repos/{owner}/{repo}/commits/{sha}/pulls") or []
        except GitHubApiError:
            return []

    def search_commits(self, owner: str, repo: str, term: str, limit: int = 5) -> list[dict[str, Any]]:
        query = f"repo:{owner}/{repo} {term}"
        try:
            response = self.get_json(
                "/search/commits",
                params={"q": query, "sort": "committer-date", "order": "desc", "per_page": limit},
            )
            return (response or {}).get("items", [])
        except GitHubApiError:
            return []

    def search_pull_requests(self, owner: str, repo: str, term: str, limit: int = 5) -> list[dict[str, Any]]:
        query = f"repo:{owner}/{repo} {term} is:pr"
        try:
            response = self.get_json(
                "/search/issues",
                params={"q": query, "sort": "updated", "order": "desc", "per_page": limit},
            )
            return (response or {}).get("items", [])
        except GitHubApiError:
            return []

    def _build_url(self, path: str, params: dict[str, Any] | None) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = f"{self.api_root}{path}"
        if not params:
            return url
        clean_params = {key: value for key, value in params.items() if value is not None}
        return f"{url}?{urllib.parse.urlencode(clean_params)}"

    def _should_retry(self, status: int, headers: Any, attempt: int) -> bool:
        if attempt >= self.max_retries:
            return False
        if status in {429, 500, 502, 503, 504}:
            return True
        if status == 403 and headers.get("x-ratelimit-remaining") == "0":
            return True
        return False

    def _sleep_before_retry(self, status: int | None, headers: Any, attempt: int) -> None:
        delay = min(2 ** attempt + random.random(), 15)
        if status in {403, 429} and headers:
            reset = headers.get("x-ratelimit-reset")
            if reset:
                try:
                    delay = max(delay, min(int(reset) - int(time.time()) + 1, 60))
                except ValueError:
                    pass
        time.sleep(max(delay, 0.5))
