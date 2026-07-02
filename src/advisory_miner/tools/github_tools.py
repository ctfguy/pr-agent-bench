from __future__ import annotations

from typing import Any

from advisory_miner.github_client import GitHubClient


class GitHubTools:
    def __init__(self, client: GitHubClient):
        self.client = client

    def get_pr_bundle(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        return {
            "pull_request": self.client.get_pull(owner, repo, number),
            "commits": self.client.get_pull_commits(owner, repo, number),
            "files": self.client.get_pull_files(owner, repo, number),
        }

    def get_commit(self, owner: str, repo: str, sha: str) -> dict[str, Any] | None:
        return self.client.get_commit(owner, repo, sha)

    def commit_pulls(self, owner: str, repo: str, sha: str) -> list[dict[str, Any]]:
        return self.client.get_commit_pulls(owner, repo, sha)

    def search_prs(self, owner: str, repo: str, terms: list[str], limit: int = 5) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen: set[int] = set()
        for term in terms:
            for item in self.client.search_pull_requests(owner, repo, term, limit=limit):
                number = item.get("number")
                if number and number not in seen:
                    seen.add(number)
                    results.append(item)
        return results

    def search_commits(self, owner: str, repo: str, terms: list[str], limit: int = 5) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for term in terms:
            for item in self.client.search_commits(owner, repo, term, limit=limit):
                sha = item.get("sha")
                if sha and sha not in seen:
                    seen.add(sha)
                    results.append(item)
        return results
