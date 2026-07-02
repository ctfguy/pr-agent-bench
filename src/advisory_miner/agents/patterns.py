from __future__ import annotations

import re
from collections import Counter


GENERIC = {
    "return",
    "public",
    "private",
    "static",
    "final",
    "class",
    "const",
    "string",
    "object",
    "boolean",
    "import",
    "package",
    "throws",
    "exception",
    "null",
    "true",
    "false",
    "this",
    "that",
    "with",
    "from",
    "fix",
    "test",
}
NOISY_DIFF_TOKENS = {
    "error",
    "result",
    "format",
    "logger",
    "debug",
    "items",
    "unable",
    "throw",
    "valid",
    "match",
    "regex",
    "regular expression",
}


def derive_patterns(
    message: str,
    diff: str,
    files: list[str],
    parsed: dict | None = None,
    limit: int = 24,
) -> list[str]:
    """Return a ranked list of search patterns for pickaxe / file-history scans.

    When the LLM advisory parser produced a `parsed` dict (Phase 1+),
    its `high_signal_search_patterns`, `vulnerable_functions`, and
    `vulnerable_parameters` are preferred over keyword extraction from the
    commit message/diff — they're orders of magnitude less noisy. Items in
    `low_signal_patterns_to_avoid` are excluded.

    When `parsed` is None or produced no high-signal patterns, falls back
    to the original keyword extraction (kept for the no-LLM path).
    """
    if parsed:
        patterns = _derive_from_parsed(parsed, limit)
        if patterns:
            return _merge_with_diff_patterns(patterns, message, diff, files, parsed, limit)
    return _derive_from_keywords(message, diff, files, limit)


def _merge_with_diff_patterns(
    parsed_patterns: list[str],
    message: str,
    diff: str,
    files: list[str],
    parsed: dict,
    limit: int,
) -> list[str]:
    excluded = {(p or "").lower() for p in (parsed.get("low_signal_patterns_to_avoid") or [])}
    excluded |= {token.lower() for token in GENERIC | NOISY_DIFF_TOKENS}
    merged: list[str] = []
    seen: set[str] = set()

    def add(token: str) -> None:
        cleaned = token.strip()
        lowered = cleaned.lower()
        if not cleaned or lowered in seen or lowered in excluded:
            return
        seen.add(lowered)
        merged.append(cleaned)

    for pattern in parsed_patterns:
        add(pattern)
    for pattern in _derive_from_keywords(message, diff, files, limit=30):
        if _is_code_specific(pattern):
            add(pattern)
        if len(merged) >= limit:
            break
    return merged[:limit]


def _derive_from_parsed(parsed: dict, limit: int) -> list[str]:
    excluded = {(p or "").lower() for p in (parsed.get("low_signal_patterns_to_avoid") or [])}
    excluded |= {token.lower() for token in GENERIC}
    seen: set[str] = set()
    patterns: list[str] = []

    def add(token: str | None) -> None:
        if not token:
            return
        cleaned = token.strip()
        if len(cleaned) < 4:
            return
        lowered = cleaned.lower()
        if not _valid_parsed_signal(cleaned):
            return
        if lowered in excluded or lowered in seen:
            return
        seen.add(lowered)
        patterns.append(cleaned)

    for token in parsed.get("high_signal_search_patterns") or []:
        add(token)
    for token in parsed.get("vulnerable_functions") or []:
        add(token)
    for token in parsed.get("vulnerable_parameters") or []:
        add(token)
    return patterns[:limit]


def _derive_from_keywords(message: str, diff: str, files: list[str], limit: int) -> list[str]:
    weighted: Counter[str] = Counter()
    _add_from_text(weighted, message, 4)
    _add_from_diff(weighted, diff)
    for path in files:
        for part in re.split(r"[/._\-]", path):
            if _valid(part):
                weighted[part] += 1
    return [pattern for pattern, _ in weighted.most_common(limit)]


def _add_from_diff(weighted: Counter[str], diff: str) -> None:
    for line in diff.splitlines():
        if not line or line.startswith(("diff ", "index ", "---", "+++")):
            continue
        weight = 1
        if line.startswith("-"):
            weight = 5
        elif line.startswith("+"):
            weight = 3
        _add_from_text(weighted, line[1:] if line[0] in "+- " else line, weight)


def _add_from_text(weighted: Counter[str], text: str, weight: int) -> None:
    for item in re.findall(r"`([^`]{4,80})`", text):
        if _valid_phrase(item):
            weighted[item.strip()] += weight + 2
    for item in re.findall(r"[A-Za-z_][A-Za-z0-9_]{4,}\s*\(", text):
        token = item.strip()[:-1]
        if _valid(token):
            weighted[token] += weight + 2
    for item in re.findall(r"/[A-Za-z0-9_./{}-]{4,}", text):
        if _valid_phrase(item):
            weighted[item.strip()] += weight + 1
    for item in re.findall(r"[A-Za-z_][A-Za-z0-9_]{4,}", text):
        if _valid(item):
            weighted[item] += weight


def _valid(value: str) -> bool:
    lowered = value.lower().strip("_-")
    return len(lowered) >= 5 and lowered not in GENERIC and not lowered.isdigit()


def _valid_phrase(value: str) -> bool:
    stripped = value.strip()
    return 4 <= len(stripped) <= 100 and not stripped.startswith(("http://", "https://"))


def _is_code_specific(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 5:
        return False
    if "_" in stripped or "." in stripped or "/" in stripped:
        return True
    return any(ch.isupper() for ch in stripped[1:]) and any(ch.islower() for ch in stripped)


def _valid_parsed_signal(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    if lowered in NOISY_DIFF_TOKENS or lowered in GENERIC:
        return False
    if _is_code_specific(stripped):
        return True
    if " " in stripped:
        return False
    return len(stripped) >= 8 and not stripped.isalpha()
