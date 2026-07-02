"""LLM-driven fallback investigator.

Runs only when deterministic tiers (FixFinder + IntroducerFinder) leave a
target unresolved or low-confidence. Drives an OpenAI tool-calling loop over
GitHub and (optionally) local-git tools to discover or adjudicate fix and
introducer commits/PRs.

The investigator is intentionally evidence-constrained: it can only finalize
findings that the deterministic tools could in principle have produced, since
all SHAs/PR numbers must come from the GitHub/git tool results. It cannot
invent identifiers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from advisory_miner.agents.evidence import EvidenceLedger, validate_finalized_value
from advisory_miner.models import AnalysisResult, Evidence, Finding
from advisory_miner.openai_client import OpenAIClient, OpenAIClientError
from advisory_miner.runtime import current_metrics
from advisory_miner.tools.git_tools import GitTools
from advisory_miner.tools.github_tools import GitHubTools


SYSTEM_PROMPT = """You are an evidence-constrained security advisory investigation agent.

Goal: for a given advisory, identify the fixing commit, the fixing pull request
(if any), the introducing commit, and the introducing PR (if any). For each
finding, you must back it with concrete evidence pulled from the tools.

Rules:
- Never invent commit SHAs, PR numbers, or repository names. Every identifier
  you return must have been produced by a tool result you observed.
- Tool use is mandatory. Do not finalize from memory, candidate lists, or prior
  model reasoning alone.
- Prefer direct advisory references (PRs / commits already in the deterministic
  result) over speculative search hits.
- When multiple candidates are plausible, fetch and read their diffs before
  choosing — pick the one that actually addresses the described vulnerability.
- For introducer analysis, prefer commits that originally added the vulnerable
  code path. Beware of move/rename commits — they are usually NOT the real
  introducer.
- For introducer commits, inspect source-focused git evidence: a focused diff,
  before/after file content, pickaxe, blame, or file history.
- For PR targets, call commit-to-pulls or fetch/search a real PR. If the API
  returns no PRs, leave the target unknown.
- If a target genuinely cannot be resolved with the available evidence, do not
  call finalize_finding for it. It is correct to leave a target unknown.

Termination: when you have done your best, stop calling tools. Call
finalize_finding(target, value, url, confidence, rationale) once per resolved
target. Use confidence levels: "high" (direct evidence or unanimous tool
agreement), "medium" (strong indirect evidence), "low" (weak inference).
"""


class Investigator:
    def __init__(
        self,
        client: OpenAIClient,
        github_tools: GitHubTools,
        git_tools: GitTools | None = None,
        max_turns: int = 10,
        max_output_tokens: int = 4000,
    ) -> None:
        self.client = client
        self.github = github_tools
        self.git = git_tools
        self.max_turns = max_turns
        self.max_output_tokens = max_output_tokens

    def investigate(
        self,
        advisory: dict[str, Any],
        result: AnalysisResult,
        repo_path: Path | None,
    ) -> AnalysisResult:
        if not result.repository.value:
            return result

        owner, repo = result.repository.value.split("/", 1)

        # Cheap deterministic exhaustion check before launching the LLM loop:
        # for PR targets, if the linked commit has no associated PR per
        # /commits/<sha>/pulls, there's nothing for the LLM to discover. Mark
        # them as definitively unknown with a reason and skip those targets.
        self._exhaust_pr_targets_deterministically(result, owner, repo)

        residual_targets = self._residual_targets(result)
        if not residual_targets:
            return result
        ledger = EvidenceLedger(owner, repo)
        tools = self._tool_schemas(repo_path is not None)
        handlers = self._build_handlers(owner, repo, repo_path, ledger)
        user_payload = self._compact_payload(advisory, result, residual_targets)

        try:
            output = self.client.tool_loop(
                SYSTEM_PROMPT,
                user_payload,
                tools,
                handlers,
                max_turns=self.max_turns,
                max_output_tokens=self.max_output_tokens,
            )
        except OpenAIClientError as exc:
            result.errors.append(f"Investigator failed: {exc}")
            return result

        current_metrics().tool_calls_used += len(output.get("tool_calls") or [])
        self._backfill_required_evidence(
            result,
            output.get("finalized") or {},
            owner,
            repo,
            repo_path,
            ledger,
        )
        self._apply_finalized(
            result,
            output.get("finalized") or {},
            owner,
            repo,
            ledger=ledger,
            require_evidence=True,
        )
        self._exhaust_pr_targets_deterministically(result, owner, repo)
        result.signal_groups["evidence_ledger"] = ledger.to_dict()
        return result

    def _backfill_required_evidence(
        self,
        result: AnalysisResult,
        finalized: dict[str, dict[str, Any]],
        owner: str,
        repo: str,
        repo_path: Path | None,
        ledger: EvidenceLedger,
    ) -> None:
        if self.git is None or repo_path is None:
            return
        requested: dict[str, str] = {}
        for target, finding in (
            ("fix_commit", result.fix_commit),
            ("introduced_commit", result.introduced_commit),
        ):
            if finding.value:
                requested[target] = finding.value
        for target, payload in finalized.items():
            value = payload.get("value")
            if isinstance(value, str) and target in {"fix_commit", "introduced_commit"}:
                requested[target] = value
        patterns = list(_high_signal_set(result.parsed_advisory))
        for target, sha in requested.items():
            if ledger.has_value(sha):
                continue
            try:
                self.git.ensure_commit(repo_path, sha)
                files = _candidate_files(result, target, sha)
                if target == "fix_commit":
                    if not files:
                        files = self.git.touched_files(repo_path, sha)[:8]
                    diff = self.git.commit_diff_for_files(repo_path, sha, files, unified=12, max_chars=50000)
                    ledger.record_tool(
                        "git_show_diff_for_files",
                        {"owner": owner, "repo": repo, "sha": sha, "files": files, "backfill": True},
                        {"sha": sha, "files": files, "diff": diff},
                    )
                else:
                    diff = self.git.commit_diff_around_patterns(
                        repo_path,
                        sha,
                        patterns,
                        files=files,
                        context_lines=50,
                        max_chars=50000,
                    )
                    ledger.record_tool(
                        "git_show_diff_around_patterns",
                        {"owner": owner, "repo": repo, "sha": sha, "patterns": patterns[:12], "files": files, "backfill": True},
                        {"sha": sha, "patterns": patterns[:12], "files": files, "diff": diff},
                    )
            except Exception as exc:  # noqa: BLE001
                result.limitations.append(f"Evidence backfill failed for {target} {sha[:12]}: {exc}")
        for target, commit_target in (("fix_pr", "fix_commit"), ("introduced_pr", "introduced_commit")):
            sha = requested.get(commit_target)
            if not sha:
                continue
            try:
                pulls = self.github.commit_pulls(owner, repo, sha)
            except Exception:
                continue
            ledger.record_tool(
                "github_get_commit_pulls",
                {"owner": owner, "repo": repo, "sha": sha, "target": target, "backfill": True},
                [
                    {
                        "number": p.get("number"),
                        "title": p.get("title"),
                        "html_url": p.get("html_url"),
                        "state": p.get("state"),
                    }
                    for p in pulls[:10]
                ],
            )

    def _residual_targets(self, result: AnalysisResult) -> list[str]:
        residual: list[str] = []
        for name, finding in (
            ("fix_commit", result.fix_commit),
            ("fix_pr", result.fix_pr),
            ("introduced_commit", result.introduced_commit),
            ("introduced_pr", result.introduced_pr),
        ):
            # An "exhausted" finding has been explicitly determined unsolvable
            # by an earlier cheap deterministic check — don't spend LLM turns
            # on it.
            if any(ev.source == "investigator_exhausted" for ev in finding.evidence):
                continue
            if not finding.value or finding.confidence not in {"high", "medium"}:
                residual.append(name)
        return residual

    def _exhaust_pr_targets_deterministically(
        self, result: AnalysisResult, owner: str, repo: str
    ) -> None:
        """For each unknown PR target whose paired commit is known, ask
        GitHub's commit-to-pulls API once. If it returns nothing, the
        deterministic answer is "no PR" — record it as exhausted so the
        LLM loop doesn't try to invent one."""
        pairs = (
            ("fix_pr", result.fix_pr, result.fix_commit),
            ("introduced_pr", result.introduced_pr, result.introduced_commit),
        )
        for name, pr_finding, commit_finding in pairs:
            if pr_finding.value:
                continue
            if not commit_finding.value:
                continue
            try:
                pulls = self.github.commit_pulls(owner, repo, commit_finding.value)
            except Exception:
                continue
            if pulls:
                number = pulls[0].get("number")
                if number:
                    pr_finding.value = f"{owner}/{repo}#{number}"
                    pr_finding.url = pulls[0].get("html_url") or f"https://github.com/{owner}/{repo}/pull/{number}"
                    pr_finding.confidence = "medium"
                    pr_finding.evidence.append(
                        Evidence(
                            source="investigator_prefetch",
                            detail=f"github commit-to-pulls API linked {commit_finding.value[:12]} to PR #{number}",
                        )
                    )
            else:
                pr_finding.confidence = "unknown"
                pr_finding.evidence.append(
                    Evidence(
                        source="investigator_exhausted",
                        detail=f"github commit-to-pulls returned no PRs for {commit_finding.value[:12]}; no PR to discover",
                    )
                )

    def _compact_payload(
        self, advisory: dict[str, Any], result: AnalysisResult, residual: list[str]
    ) -> dict[str, Any]:
        return {
            "advisory": {
                "ghsa_id": advisory.get("ghsa_id"),
                "cve_ids": advisory.get("cve_ids"),
                "summary": advisory.get("summary"),
                "description": (advisory.get("description") or "")[:4000],
                "references": advisory.get("references") or [],
                "vulnerabilities": advisory.get("vulnerabilities") or [],
                "cwes": advisory.get("cwes") or [],
                "extracted_github": advisory.get("extracted_github"),
            },
            "current_findings": {
                "repository": result.repository.to_dict(),
                "fix_commit": result.fix_commit.to_dict(),
                "fix_pr": result.fix_pr.to_dict(),
                "introduced_commit": result.introduced_commit.to_dict(),
                "introduced_pr": result.introduced_pr.to_dict(),
            },
            "candidates": {
                "fix": [_compact_candidate(c.to_dict(), set()) for c in result.fix_candidates[:6]],
                "introducer": [
                    _compact_candidate(c.to_dict(), _high_signal_set(result.parsed_advisory))
                    for c in result.introducer_candidates[:10]
                ],
            },
            "residual_targets": residual,
            "mandatory_tool_policy": {
                "fix_commit": "Inspect a concrete commit or diff tool result before finalizing.",
                "introduced_commit": "Use git evidence such as focused diff, pickaxe, file history, blame, or before/after source.",
                "fix_pr": "Use commit-to-pulls, get_pr, or PR search. Never synthesize #null.",
                "introduced_pr": "Use commit-to-pulls, get_pr, or PR search. Empty commit-to-pulls means leave unknown.",
                "candidate_priority": "For introducers, prioritize candidates with many high_signal_matches over generic blame hits. If a finalist is not an ancestor, inspect the next high-signal ancestor candidate.",
            },
        }

    def _tool_schemas(self, has_git: bool) -> list[dict[str, Any]]:
        schemas: list[dict[str, Any]] = [
            _fn(
                "github_get_pr",
                "Fetch metadata for a single GitHub pull request.",
                {"owner": _str(), "repo": _str(), "number": _int()},
                ["owner", "repo", "number"],
            ),
            _fn(
                "github_get_pr_commits",
                "List commits in a pull request (latest first, capped to 100).",
                {"owner": _str(), "repo": _str(), "number": _int()},
                ["owner", "repo", "number"],
            ),
            _fn(
                "github_get_pr_files",
                "List files changed in a pull request (capped to 100).",
                {"owner": _str(), "repo": _str(), "number": _int()},
                ["owner", "repo", "number"],
            ),
            _fn(
                "github_get_commit",
                "Fetch a single commit's metadata, parents, and aggregated stats.",
                {"owner": _str(), "repo": _str(), "sha": _str()},
                ["owner", "repo", "sha"],
            ),
            _fn(
                "github_get_commit_pulls",
                "List PRs that contain the given commit SHA.",
                {"owner": _str(), "repo": _str(), "sha": _str()},
                ["owner", "repo", "sha"],
            ),
            _fn(
                "github_search_prs",
                "Search PRs in a repo. Provide a query string e.g. CVE-2026-xxxx or vulnerability keywords.",
                {"owner": _str(), "repo": _str(), "query": _str(), "limit": _int(default=5)},
                ["owner", "repo", "query"],
            ),
            _fn(
                "github_search_commits",
                "Search commits in a repo. Provide a query string e.g. CVE-xxxx or 'fix CWE-89'.",
                {"owner": _str(), "repo": _str(), "query": _str(), "limit": _int(default=5)},
                ["owner", "repo", "query"],
            ),
        ]
        if has_git:
            schemas.extend(
                [
                    _fn(
                        "git_show_diff",
                        "Show a commit's unified diff (truncated to ~8 KB).",
                        {"sha": _str()},
                        ["sha"],
                    ),
                    _fn(
                        "git_show_diff_for_files",
                        "Show a commit's diff restricted to source files selected for advisory relevance.",
                        {"sha": _str(), "files": _array_str(), "max_chars": _int(default=40000)},
                        ["sha", "files"],
                    ),
                    _fn(
                        "git_show_diff_around_patterns",
                        "Show diff hunks around advisory-relevant literal patterns.",
                        {
                            "sha": _str(),
                            "patterns": _array_str(),
                            "files": _array_str(default=[]),
                            "max_chars": _int(default=50000),
                        },
                        ["sha", "patterns"],
                    ),
                    _fn(
                        "git_log_S",
                        "Run git log -S <pattern> over a path; returns commits that added/removed the literal string.",
                        {"pattern": _str(), "file": _str(default=""), "max_count": _int(default=20)},
                        ["pattern"],
                    ),
                    _fn(
                        "git_log_S_many",
                        "Run git log -S for multiple literal patterns and optional paths.",
                        {
                            "patterns": _array_str(),
                            "files": _array_str(default=[]),
                            "max_count": _int(default=20),
                        },
                        ["patterns"],
                    ),
                    _fn(
                        "git_show_file_at_commit",
                        "Show one file's contents at a commit.",
                        {"sha": _str(), "file": _str(), "max_chars": _int(default=80000)},
                        ["sha", "file"],
                    ),
                    _fn(
                        "git_compare_file_before_after",
                        "Show a file before and after a commit to verify newly introduced behavior.",
                        {"sha": _str(), "file": _str(), "max_chars": _int(default=80000)},
                        ["sha", "file"],
                    ),
                    _fn(
                        "git_log_follow",
                        "Walk file history including renames; returns up to max_count recent commits.",
                        {"file": _str(), "max_count": _int(default=30)},
                        ["file"],
                    ),
                    _fn(
                        "git_blame_range",
                        "Run git blame on a file at a commit; returns one entry per line in [start_line,end_line].",
                        {
                            "sha": _str(),
                            "file": _str(),
                            "start_line": _int(),
                            "end_line": _int(),
                        },
                        ["sha", "file", "start_line", "end_line"],
                    ),
                ]
            )
        schemas.append(
            _fn(
                "finalize_finding",
                "Record a final finding for a target. Call once per target you can resolve.",
                {
                    "target": {
                        "type": "string",
                        "enum": ["fix_commit", "fix_pr", "introduced_commit", "introduced_pr"],
                        "description": "Which finding this answers.",
                    },
                    "value": _str(description="The identifier — full SHA for commits, owner/repo#N for PRs."),
                    "url": _str(description="Canonical GitHub URL for the identifier."),
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": "Confidence in the finding.",
                    },
                    "rationale": _str(
                        description="One-paragraph evidence summary citing specific tool returns."
                    ),
                },
                ["target", "value", "confidence", "rationale"],
            )
        )
        return schemas

    def _build_handlers(
        self,
        default_owner: str,
        default_repo: str,
        repo_path: Path | None,
        ledger: EvidenceLedger | None = None,
    ) -> dict[str, Callable[[dict[str, Any]], Any]]:
        github = self.github
        git = self.git

        def record(tool_name: str, args: dict[str, Any], output: Any) -> Any:
            if ledger is not None:
                ledger.record_tool(tool_name, args, output)
            return output

        def gh_pr(args: dict[str, Any]) -> Any:
            bundle = github.get_pr_bundle(
                args.get("owner") or default_owner,
                args.get("repo") or default_repo,
                int(args["number"]),
            )
            pr = bundle.get("pull_request") or {}
            return record("github_get_pr", args, {
                "number": pr.get("number"),
                "title": pr.get("title"),
                "state": pr.get("state"),
                "merged": pr.get("merged"),
                "merge_commit_sha": pr.get("merge_commit_sha"),
                "html_url": pr.get("html_url"),
                "body": (pr.get("body") or "")[:2000],
            })

        def gh_pr_commits(args: dict[str, Any]) -> Any:
            bundle = github.get_pr_bundle(
                args.get("owner") or default_owner,
                args.get("repo") or default_repo,
                int(args["number"]),
            )
            return record("github_get_pr_commits", args, [
                {
                    "sha": c.get("sha"),
                    "message": ((c.get("commit") or {}).get("message") or "")[:400],
                }
                for c in (bundle.get("commits") or [])[:30]
            ])

        def gh_pr_files(args: dict[str, Any]) -> Any:
            bundle = github.get_pr_bundle(
                args.get("owner") or default_owner,
                args.get("repo") or default_repo,
                int(args["number"]),
            )
            return record("github_get_pr_files", args, [
                {
                    "filename": f.get("filename"),
                    "status": f.get("status"),
                    "additions": f.get("additions"),
                    "deletions": f.get("deletions"),
                }
                for f in (bundle.get("files") or [])[:50]
            ])

        def gh_commit(args: dict[str, Any]) -> Any:
            commit = github.get_commit(
                args.get("owner") or default_owner,
                args.get("repo") or default_repo,
                args["sha"],
            )
            if not commit:
                return record("github_get_commit", args, {"error": "commit not found"})
            commit_meta = commit.get("commit") or {}
            return record("github_get_commit", args, {
                "sha": commit.get("sha"),
                "html_url": commit.get("html_url"),
                "message": (commit_meta.get("message") or "")[:800],
                "stats": commit.get("stats"),
                "parents": [p.get("sha") for p in commit.get("parents") or []],
                "file_count": len(commit.get("files") or []),
            })

        def gh_commit_pulls(args: dict[str, Any]) -> Any:
            pulls = github.commit_pulls(
                args.get("owner") or default_owner,
                args.get("repo") or default_repo,
                args["sha"],
            )
            return record("github_get_commit_pulls", args, [
                {
                    "number": p.get("number"),
                    "title": p.get("title"),
                    "html_url": p.get("html_url"),
                    "state": p.get("state"),
                }
                for p in pulls[:10]
            ])

        def gh_search_prs(args: dict[str, Any]) -> Any:
            limit = int(args.get("limit") or 5)
            results = github.search_prs(
                args.get("owner") or default_owner,
                args.get("repo") or default_repo,
                [args["query"]],
                limit=limit,
            )
            return record("github_search_prs", args, [
                {
                    "number": item.get("number"),
                    "title": item.get("title"),
                    "html_url": item.get("html_url"),
                    "state": item.get("state"),
                }
                for item in results[:limit]
            ])

        def gh_search_commits(args: dict[str, Any]) -> Any:
            limit = int(args.get("limit") or 5)
            results = github.search_commits(
                args.get("owner") or default_owner,
                args.get("repo") or default_repo,
                [args["query"]],
                limit=limit,
            )
            return record("github_search_commits", args, [
                {
                    "sha": item.get("sha"),
                    "html_url": item.get("html_url"),
                    "message": ((item.get("commit") or {}).get("message") or "")[:400],
                }
                for item in results[:limit]
            ])

        handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
            "github_get_pr": gh_pr,
            "github_get_pr_commits": gh_pr_commits,
            "github_get_pr_files": gh_pr_files,
            "github_get_commit": gh_commit,
            "github_get_commit_pulls": gh_commit_pulls,
            "github_search_prs": gh_search_prs,
            "github_search_commits": gh_search_commits,
        }

        if git is not None and repo_path is not None:
            def g_diff(args: dict[str, Any]) -> Any:
                diff = git.commit_diff(repo_path, args["sha"], unified=10, max_chars=8000)
                return record("git_show_diff", args, {"sha": args["sha"], "diff": diff})

            def g_diff_for_files(args: dict[str, Any]) -> Any:
                files = [str(item) for item in args.get("files") or [] if item]
                max_chars = int(args.get("max_chars") or 40000)
                diff = git.commit_diff_for_files(repo_path, args["sha"], files, unified=12, max_chars=max_chars)
                return record("git_show_diff_for_files", args, {"sha": args["sha"], "files": files, "diff": diff})

            def g_diff_around_patterns(args: dict[str, Any]) -> Any:
                patterns = [str(item) for item in args.get("patterns") or [] if item]
                files = [str(item) for item in args.get("files") or [] if item]
                max_chars = int(args.get("max_chars") or 50000)
                diff = git.commit_diff_around_patterns(
                    repo_path,
                    args["sha"],
                    patterns,
                    files=files,
                    max_chars=max_chars,
                )
                return record(
                    "git_show_diff_around_patterns",
                    args,
                    {"sha": args["sha"], "patterns": patterns, "files": files, "diff": diff},
                )

            def g_log_s(args: dict[str, Any]) -> Any:
                pattern = args["pattern"]
                file = args.get("file") or ""
                limit = int(args.get("max_count") or 20)
                candidates = git.pickaxe_search(
                    repo_path, "HEAD", pattern, [file] if file else [], limit=limit
                )
                return record("git_log_S", args, [
                    {"sha": c.sha, "subject": c.subject}
                    for c in candidates[:limit]
                ])

            def g_log_s_many(args: dict[str, Any]) -> Any:
                patterns = [str(item) for item in args.get("patterns") or [] if item]
                files = [str(item) for item in args.get("files") or [] if item]
                limit = int(args.get("max_count") or 20)
                output = git.pickaxe_search_many(repo_path, "HEAD", patterns, files, limit_per_pattern=limit)
                return record("git_log_S_many", args, output)

            def g_show_file(args: dict[str, Any]) -> Any:
                max_chars = int(args.get("max_chars") or 80000)
                output = git.show_file_at_commit(repo_path, args["sha"], args["file"], max_chars=max_chars)
                return record("git_show_file_at_commit", args, {"sha": args["sha"], "file": args["file"], "content": output})

            def g_compare_file(args: dict[str, Any]) -> Any:
                max_chars = int(args.get("max_chars") or 80000)
                output = git.compare_file_before_after(repo_path, args["sha"], args["file"], max_chars=max_chars)
                return record("git_compare_file_before_after", args, output)

            def g_log_follow(args: dict[str, Any]) -> Any:
                file = args["file"]
                limit = int(args.get("max_count") or 30)
                history = git.range_file_history(repo_path, "HEAD", [file], limit=limit)
                return record("git_log_follow", args, [
                    {"sha": c.sha, "subject": c.subject}
                    for c in history[:limit]
                ])

            def g_blame(args: dict[str, Any]) -> Any:
                out = git._git(  # noqa: SLF001 - test seam intentional
                    [
                        "blame",
                        "--porcelain",
                        "-L",
                        f"{int(args['start_line'])},{int(args['end_line'])}",
                        args["sha"],
                        "--",
                        args["file"],
                    ],
                    repo_path,
                    60,
                )
                return record("git_blame_range", args, {"sha": args["sha"], "file": args["file"], "blame": out[:8000]})

            handlers.update(
                {
                    "git_show_diff": g_diff,
                    "git_show_diff_for_files": g_diff_for_files,
                    "git_show_diff_around_patterns": g_diff_around_patterns,
                    "git_log_S": g_log_s,
                    "git_log_S_many": g_log_s_many,
                    "git_show_file_at_commit": g_show_file,
                    "git_compare_file_before_after": g_compare_file,
                    "git_log_follow": g_log_follow,
                    "git_blame_range": g_blame,
                }
            )

        return handlers

    def _apply_finalized(
        self,
        result: AnalysisResult,
        finalized: dict[str, dict[str, Any]],
        owner: str,
        repo: str,
        ledger: EvidenceLedger | None = None,
        require_evidence: bool = False,
    ) -> None:
        target_fields = {
            "fix_commit": result.fix_commit,
            "fix_pr": result.fix_pr,
            "introduced_commit": result.introduced_commit,
            "introduced_pr": result.introduced_pr,
        }
        for target, payload in finalized.items():
            finding = target_fields.get(target)
            if not finding:
                continue
            confidence = (payload.get("confidence") or "low").lower()
            if confidence not in {"high", "medium", "low"}:
                confidence = "low"
            if finding.value and finding.confidence == "high" and confidence != "high":
                continue
            value = payload.get("value")
            valid, reason, normalized = validate_finalized_value(
                target=target,
                value=value,
                owner=owner,
                repo=repo,
                ledger=ledger,
                require_evidence=require_evidence,
            )
            if not valid or not normalized:
                if isinstance(value, str) and value.strip().lower() in {"unknown", "none", "n/a", "na", "not found", ""}:
                    continue
                result.errors.append(f"Investigator rejected finalized {target}={value!r}: {reason}")
                continue
            url = payload.get("url")
            if not url:
                if target.endswith("commit"):
                    url = f"https://github.com/{owner}/{repo}/commit/{normalized}"
                elif target.endswith("pr") and "#" in normalized:
                    _, number = normalized.split("#", 1)
                    url = f"https://github.com/{owner}/{repo}/pull/{number}"
            finding.value = normalized
            finding.url = url
            finding.confidence = confidence
            support = ledger.supporting_ids(normalized) if ledger is not None else []
            detail = (payload.get("rationale") or "")[:600]
            if support:
                detail = f"{detail} supporting_evidence={support[:5]}".strip()
            finding.evidence.append(
                Evidence(source="investigator", detail=detail)
            )


def _str(description: str | None = None, default: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string"}
    if description:
        schema["description"] = description
    if default is not None:
        schema["default"] = default
    return schema


def _int(description: str | None = None, default: int | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "integer"}
    if description:
        schema["description"] = description
    if default is not None:
        schema["default"] = default
    return schema


def _array_str(description: str | None = None, default: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "array", "items": {"type": "string"}}
    if description:
        schema["description"] = description
    if default is not None:
        schema["default"] = default
    return schema


def _high_signal_set(parsed: dict[str, Any] | None) -> set[str]:
    if not isinstance(parsed, dict):
        return set()
    signals: set[str] = set()
    for key in ("high_signal_search_patterns", "vulnerable_functions", "vulnerable_parameters"):
        signals.update(str(item).lower() for item in parsed.get(key) or [] if item)
    return signals


def _compact_candidate(candidate: dict[str, Any], high_signal: set[str]) -> dict[str, Any]:
    matched_patterns = [str(item) for item in candidate.get("matched_patterns") or []]
    high_matches = [pattern for pattern in matched_patterns if pattern.lower() in high_signal]
    return {
        **candidate,
        "reasons": [str(reason)[:220] for reason in candidate.get("reasons") or []][:6],
        "matched_patterns": matched_patterns[:12],
        "high_signal_matches": high_matches[:12],
        "high_signal_match_count": len(high_matches),
    }


def _candidate_files(result: AnalysisResult, target: str, sha: str) -> list[str]:
    candidates = result.fix_candidates if target == "fix_commit" else result.introducer_candidates
    for candidate in candidates:
        if getattr(candidate, "sha", None) == sha:
            return [str(item) for item in getattr(candidate, "files", []) if item]
    return []


def _fn(
    name: str,
    description: str,
    properties: dict[str, Any],
    required: list[str],
) -> dict[str, Any]:
    return {
        "type": "function",
        "name": name,
        "description": description,
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    }
