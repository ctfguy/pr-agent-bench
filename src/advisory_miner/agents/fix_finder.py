from __future__ import annotations

import re
from typing import Any

from advisory_miner.models import AnalysisResult, Evidence, Finding, FixCandidate
from advisory_miner.tools.github_tools import GitHubTools


SECURITY_TERMS = {
    "fix",
    "security",
    "vulnerability",
    "vulnerable",
    "sanitize",
    "validate",
    "validation",
    "auth",
    "authenticate",
    "authenticated",
    "authorization",
    "permission",
    "access",
    "sql",
    "injection",
    "xss",
    "csrf",
    "ssrf",
    "overflow",
    "parameterize",
    "parameterized",
    "escape",
    "unsafe",
    "bypass",
}

STOPWORDS = {
    "this",
    "that",
    "with",
    "from",
    "have",
    "will",
    "into",
    "allows",
    "before",
    "after",
    "version",
    "versions",
    "using",
    "used",
    "fixed",
    "issue",
    "github",
    "advisory",
}


class FixFinder:
    def __init__(self, github: GitHubTools):
        self.github = github

    def find(self, advisory: dict[str, Any]) -> AnalysisResult:
        result = AnalysisResult(ghsa_id=advisory["ghsa_id"])
        extracted = advisory.get("extracted_github") or {}
        repos = list(extracted.get("repositories") or [])
        direct_prs = list(extracted.get("pull_requests") or [])
        direct_commits = list(extracted.get("commits") or [])
        # Phase 2 hook: OSV/NVD enrichment commit URLs become additional direct
        # evidence. They have the same shape as `extracted.commits` so the
        # downstream `_from_direct_commits` path picks them up unchanged.
        direct_commits.extend(_commits_from_enriched(advisory))

        if not repos:
            repos.extend(_repos_from_refs(direct_prs + direct_commits))
        if repos:
            result.repository = Finding(
                value=repos[0],
                url=f"https://github.com/{repos[0]}",
                confidence="high",
                evidence=[Evidence("collector", f"Direct GitHub repository evidence: {repos[0]}")],
            )
        else:
            result.limitations.append("No GitHub repository was directly available in collector evidence.")
            return result

        owner, repo = result.repository.value.split("/", 1)
        terms = advisory_terms(advisory)

        # Direct commit refs in the advisory are the strongest signal for
        # fix_commit — they're exactly what the advisory author pointed at.
        # Run that path first so a later PR-rank can't pick a noisier sibling
        # commit (e.g. the merge commit) over it.
        if direct_commits:
            self._from_direct_commits(result, owner, repo, direct_commits)
        if direct_prs:
            self._from_direct_prs(result, advisory, owner, repo, direct_prs, terms)
        if not result.fix_candidates:
            self._from_search(result, advisory, owner, repo)

        if result.fix_candidates and not result.fix_commit.value:
            best = result.fix_candidates[0]
            result.fix_commit = Finding(
                value=best.sha,
                url=best.url or f"https://github.com/{owner}/{repo}/commit/{best.sha}",
                confidence="medium",
                evidence=[Evidence("fix_finder", f"Top ranked fixing commit candidate: {best.sha} ({'; '.join(best.reasons[:4])})")],
            )
        if not result.fix_commit.value:
            result.limitations.append("No fixing commit could be identified from direct advisory evidence or GitHub search.")
        return result

    def _from_direct_prs(self, result: AnalysisResult, advisory: dict[str, Any], owner: str, repo: str, prs: list[dict[str, Any]], terms: set[str]) -> None:
        for pr_ref in prs:
            number = int(pr_ref["value"])
            bundle = self.github.get_pr_bundle(owner, repo, number)
            pr = bundle.get("pull_request") or {}
            commits = bundle.get("commits") or []
            files = bundle.get("files") or []
            result.fix_pr = Finding(
                value=f"{owner}/{repo}#{number}",
                url=pr_ref.get("url") or f"https://github.com/{owner}/{repo}/pull/{number}",
                confidence="high",
                evidence=[Evidence("collector", f"Advisory directly references PR {owner}/{repo}#{number}.")],
            )

            file_names = [item.get("filename", "") for item in files]
            ranked = [self._score_pr_commit(owner, repo, item, terms, file_names) for item in commits]
            ranked = [item for item in ranked if item.score > -10]
            ranked.sort(key=lambda item: item.score, reverse=True)
            result.fix_candidates.extend(ranked[:5])

            merge_sha = pr.get("merge_commit_sha")
            if merge_sha:
                result.fix_candidates.append(
                    FixCandidate(
                        sha=merge_sha,
                        url=f"https://github.com/{owner}/{repo}/commit/{merge_sha}",
                        score=20,
                        reasons=[f"Merge commit for directly referenced PR #{number}"],
                        message=pr.get("title"),
                    )
                )
            if ranked and (not result.fix_commit.value or result.fix_commit.confidence != "high"):
                best = ranked[0]
                confidence = "high" if best.score >= 20 else "medium"
                result.fix_commit = Finding(
                    value=best.sha,
                    url=best.url,
                    confidence=confidence,
                    evidence=[
                        Evidence("github_pr", f"PR #{number} contains commit {best.sha}: {best.message or ''}"),
                        Evidence("fix_ranker", "; ".join(best.reasons[:5])),
                    ],
                )
            return

    def _from_direct_commits(self, result: AnalysisResult, owner: str, repo: str, commits: list[dict[str, Any]]) -> None:
        for item in commits:
            sha = item["value"]
            result.fix_candidates.append(
                FixCandidate(
                    sha=sha,
                    url=item.get("url") or f"https://github.com/{owner}/{repo}/commit/{sha}",
                    score=100,
                    reasons=["Advisory directly references this commit"],
                )
            )
        best = result.fix_candidates[0]
        result.fix_commit = Finding(
            value=best.sha,
            url=best.url,
            confidence="high",
            evidence=[Evidence("collector", f"Advisory directly references commit {best.sha}.")],
        )
        pulls = self.github.commit_pulls(owner, repo, best.sha)
        if pulls:
            number = pulls[0].get("number")
            if number:
                result.fix_pr = Finding(
                    value=f"{owner}/{repo}#{number}",
                    url=pulls[0].get("html_url") or f"https://github.com/{owner}/{repo}/pull/{number}",
                    confidence="high",
                    evidence=[Evidence("github_api", f"GitHub commit-to-pulls API links commit {best.sha} to PR #{number}.")],
                )

    def _from_search(self, result: AnalysisResult, advisory: dict[str, Any], owner: str, repo: str) -> None:
        terms = [advisory["ghsa_id"], *(advisory.get("cve_ids") or [])]
        prs = self.github.search_prs(owner, repo, terms, limit=3)
        if prs:
            number = int(prs[0]["number"])
            self._from_direct_prs(result, advisory, owner, repo, [{"value": str(number), "url": prs[0].get("html_url")}], advisory_terms(advisory))
            if result.fix_pr.evidence:
                result.fix_pr.evidence.append(Evidence("github_search", f"PR #{number} matched advisory identifier search."))
            return
        commits = self.github.search_commits(owner, repo, terms, limit=3)
        for item in commits:
            sha = item.get("sha")
            if sha:
                result.fix_candidates.append(
                    FixCandidate(
                        sha=sha,
                        url=item.get("html_url") or f"https://github.com/{owner}/{repo}/commit/{sha}",
                        score=50,
                        reasons=["GitHub commit search matched advisory identifier"],
                        message=(item.get("commit") or {}).get("message"),
                    )
                )

    def _score_pr_commit(self, owner: str, repo: str, item: dict[str, Any], terms: set[str], files: list[str]) -> FixCandidate:
        sha = item.get("sha")
        message = ((item.get("commit") or {}).get("message") or "").strip()
        subject = message.split("\n", 1)[0]
        lowered = message.lower()
        score = 0
        reasons: list[str] = []

        if lowered.startswith("merge ") or "merge branch" in lowered:
            score -= 25
            reasons.append("merge commit")
        if lowered.startswith("test") or " test" in lowered:
            score -= 8
            reasons.append("test-focused commit")
        if lowered.startswith("fix") or " fix" in lowered:
            score += 10
            reasons.append("commit message indicates a fix")
        matched_security = sorted(term for term in SECURITY_TERMS if term in lowered)
        if matched_security:
            score += min(16, len(matched_security) * 3)
            reasons.append(f"security-relevant terms: {', '.join(matched_security[:6])}")
        overlap = sorted(term for term in terms if term in lowered)
        if overlap:
            score += min(20, len(overlap) * 2)
            reasons.append(f"overlaps advisory terms: {', '.join(overlap[:8])}")
        relevant_files = [path for path in files if any(term in path.lower() for term in terms)]
        if relevant_files:
            score += min(10, len(relevant_files) * 2)
            reasons.append("PR touches files whose paths overlap advisory terms")
        if not reasons:
            reasons.append("commit is part of directly referenced PR")
        return FixCandidate(
            sha=sha,
            url=f"https://github.com/{owner}/{repo}/commit/{sha}" if sha else None,
            score=score,
            reasons=reasons,
            message=subject,
        )


def advisory_terms(advisory: dict[str, Any]) -> set[str]:
    text = " ".join(str(advisory.get(key) or "") for key in ("summary", "description", "ghsa_id"))
    text += " " + " ".join(advisory.get("cve_ids") or [])
    terms = {token.lower() for token in re.findall(r"[A-Za-z][A-Za-z0-9_\-]{3,}", text)}
    terms |= {token.lower() for token in re.findall(r"`([^`]{3,80})`", text)}
    return {term.strip("-_") for term in terms if term.lower() not in STOPWORDS and len(term.strip("-_")) >= 4}


def _repos_from_refs(refs: list[dict[str, Any]]) -> list[str]:
    repos = []
    for ref in refs:
        owner = ref.get("owner")
        repo = ref.get("repo")
        if owner and repo:
            value = f"{owner}/{repo}"
            if value not in repos:
                repos.append(value)
    return repos


COMMIT_URL_RE = re.compile(
    r"https?://github\.com/([^/\s]+)/([^/\s]+)/commit[s]?/([0-9a-fA-F]{7,40})"
)


def _commits_from_enriched(advisory: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert OSV/NVD enrichment commit URLs into the same shape as
    `extracted_github.commits` so the existing direct-evidence path
    consumes them unchanged."""
    enriched = advisory.get("enriched_refs") or {}
    urls = list(enriched.get("extra_github_commit_urls") or [])
    # Also surface OSV git-range "fixed" SHAs as commits without owner/repo
    # context. We only emit those when we can pair them with a repo we already
    # extracted, otherwise they would mislead downstream code.
    extracted = advisory.get("extracted_github") or {}
    repos = list(extracted.get("repositories") or [])
    if repos:
        owner_repo = repos[0].split("/", 1)
        if len(owner_repo) == 2:
            owner, repo = owner_repo
            for sha in enriched.get("osv_fixed_commits") or []:
                urls.append(f"https://github.com/{owner}/{repo}/commit/{sha}")
    refs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in urls:
        match = COMMIT_URL_RE.search(url)
        if not match:
            continue
        owner, repo, sha = match.groups()
        key = (owner.lower(), repo.lower(), sha.lower())
        if key in seen:
            continue
        seen.add(key)
        refs.append(
            {
                "owner": owner,
                "repo": repo,
                "kind": "commit",
                "value": sha,
                "url": url,
            }
        )
    return refs
