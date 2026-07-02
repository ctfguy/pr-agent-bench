from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any


SHA_RE = re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE)
PR_VALUE_RE = re.compile(r"\b[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*\b")
PR_URL_RE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)/pull/([1-9][0-9]*)")


@dataclass(slots=True)
class EvidenceItem:
    id: str
    source: str
    tool_name: str
    input: Any
    output: Any
    values: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EvidenceLedger:
    """Records tool observations and validates final findings against them."""

    def __init__(self, owner: str, repo: str):
        self.owner = owner
        self.repo = repo
        self.items: list[EvidenceItem] = []
        self._values: set[str] = set()
        self._tools_called: set[str] = set()

    @property
    def tools_called(self) -> set[str]:
        return set(self._tools_called)

    def record_tool(self, tool_name: str, input: Any, output: Any) -> EvidenceItem:
        values = sorted(_extract_values(output, self.owner, self.repo))
        item_id = _evidence_id(tool_name, input, output, len(self.items))
        item = EvidenceItem(
            id=item_id,
            source="tool",
            tool_name=tool_name,
            input=input,
            output=_compact(output),
            values=values,
        )
        self.items.append(item)
        self._tools_called.add(tool_name)
        self._values.update(value.lower() for value in values)
        return item

    def has_value(self, value: str) -> bool:
        normalized = normalize_identifier(value, self.owner, self.repo)
        return bool(normalized and normalized.lower() in self._values)

    def supporting_ids(self, value: str) -> list[str]:
        normalized = normalize_identifier(value, self.owner, self.repo)
        if not normalized:
            return []
        lowered = normalized.lower()
        return [item.id for item in self.items if lowered in {v.lower() for v in item.values}]

    def has_any_tool(self, names: set[str]) -> bool:
        return bool(self._tools_called & names)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": f"{self.owner}/{self.repo}",
            "tools_called": sorted(self._tools_called),
            "items": [item.to_dict() for item in self.items],
        }


def normalize_identifier(value: str | None, owner: str, repo: str) -> str | None:
    if not value:
        return None
    value = str(value).strip()
    if not value or "null" in value.lower():
        return None
    if value.lower() in {"unknown", "none", "n/a", "na", "not found"}:
        return None
    if SHA_RE.fullmatch(value):
        return value.lower()
    if "#" in value:
        repo_part, number = value.split("#", 1)
        if repo_part.lower() != f"{owner}/{repo}".lower():
            return None
        if not number.isdigit() or int(number) <= 0:
            return None
        return f"{owner}/{repo}#{int(number)}"
    return None


def validate_finalized_value(
    *,
    target: str,
    value: str | None,
    owner: str,
    repo: str,
    ledger: EvidenceLedger | None,
    require_evidence: bool,
) -> tuple[bool, str, str | None]:
    normalized = normalize_identifier(value, owner, repo)
    if normalized is None:
        return False, "malformed identifier", None
    if target.endswith("commit") and not SHA_RE.fullmatch(normalized):
        return False, "commit target requires a full 40-character SHA", None
    if target.endswith("pr") and not PR_VALUE_RE.fullmatch(normalized):
        return False, "PR target requires owner/repo#number", None
    if require_evidence:
        if ledger is None:
            return False, "missing evidence ledger", None
        if not ledger.has_value(normalized):
            return False, "identifier was not observed in tool output", None
        if target == "fix_commit" and not ledger.has_any_tool(
            {"git_show_diff", "git_show_diff_for_files", "git_show_diff_around_patterns", "git_compare_file_before_after"}
        ):
            return False, "fix commit was finalized without git diff/source evidence", None
        if target == "introduced_commit" and not ledger.has_any_tool(
            {
                "git_show_diff",
                "git_show_diff_for_files",
                "git_log_S",
                "git_log_S_many",
                "git_log_follow",
                "git_blame_range",
                "git_show_file_at_commit",
                "git_compare_file_before_after",
            }
        ):
            return False, "introducer commit was finalized without git evidence", None
        if target.endswith("pr") and not ledger.has_any_tool({"github_get_commit_pulls", "github_get_pr", "github_search_prs"}):
            return False, "PR was finalized without GitHub PR evidence", None
    return True, "ok", normalized


def _extract_values(payload: Any, owner: str, repo: str) -> set[str]:
    values: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            number = value.get("number")
            html_url = value.get("html_url")
            sha = value.get("sha") or value.get("merge_commit_sha")
            if isinstance(sha, str) and SHA_RE.fullmatch(sha):
                values.add(sha.lower())
            if isinstance(number, int) and number > 0:
                values.add(f"{owner}/{repo}#{number}")
            if isinstance(number, str) and number.isdigit() and int(number) > 0:
                values.add(f"{owner}/{repo}#{int(number)}")
            if isinstance(html_url, str):
                match = PR_URL_RE.search(html_url)
                if match:
                    values.add(f"{match.group(1)}/{match.group(2)}#{match.group(3)}")
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            values.update(match.group(0).lower() for match in SHA_RE.finditer(value))
            values.update(match.group(0) for match in PR_VALUE_RE.finditer(value))
            for match in PR_URL_RE.finditer(value):
                values.add(f"{match.group(1)}/{match.group(2)}#{match.group(3)}")

    walk(payload)
    return values


def _compact(value: Any) -> Any:
    try:
        encoded = json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)[:4000]
    if len(encoded) <= 12000:
        return value
    return json.loads(encoded[:12000] + '"..."') if False else encoded[:12000] + "...(truncated)"


def _evidence_id(tool_name: str, input: Any, output: Any, index: int) -> str:
    raw = json.dumps({"tool": tool_name, "input": input, "output": _compact(output), "index": index}, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
