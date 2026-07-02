"""LLM-driven advisory parsing into structured vulnerability semantics.

Produces a fixed-shape JSON payload describing *what the vulnerability is*
in terms downstream code can actually use:

  cwe, vulnerability_class, vulnerable_construct, vulnerable_functions,
  vulnerable_parameters, affected_endpoints, expected_fix_behavior,
  high_signal_search_patterns, low_signal_patterns_to_avoid

Pattern derivation, pickaxe scoping, fix verification, and the introducer
classifier all consume this — replacing keyword extraction from commit
messages (which is what the old `patterns.py:derive_patterns` did).
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from advisory_miner.openai_client import OpenAIClient, OpenAIClientError


logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are an evidence-constrained security advisory parser.

Read the advisory text and emit ONE JSON object with this exact shape:

{
  "cwe_id": "CWE-89" | null,
  "vulnerability_class": short_lowercase_label,
  "vulnerable_construct": one-sentence description of the unsafe code construct,
  "vulnerable_functions": [function names mentioned, lowercase + camelCase preserved],
  "vulnerable_parameters": [parameter / input names mentioned],
  "affected_endpoints": [HTTP paths or API names mentioned],
  "expected_fix_behavior": one-sentence description of what a correct fix should do,
  "high_signal_search_patterns": [3-8 specific code-identifier substrings worth grepping for],
  "low_signal_patterns_to_avoid": [generic words to NOT use as search patterns]
}

Rules:
- Only return facts supported by the advisory text.
- Prefer specific code identifiers (function names, parameter names, API paths)
  over generic English words (no "input", "user", "data", "request" alone).
- If the advisory is too vague to determine a field, return an empty list /
  null for that field. Do not invent.
- vulnerability_class examples: "sql_injection", "path_traversal", "xss",
  "command_injection", "insecure_deserialization", "authentication_bypass",
  "insecure_randomness", "buffer_overflow", "ssrf", "open_redirect",
  "prototype_pollution", "race_condition", "code_injection", "csrf".
- high_signal_search_patterns: each must be >= 5 characters and would NOT
  appear thousands of times in a random codebase. Function/method names,
  unusual identifiers, vulnerable API call substrings are good. English
  words are bad.
- Do NOT put CVE IDs, GHSA IDs, commit hashes, PR numbers, or repository URLs
  in high_signal_search_patterns. Those are reference metadata, not code
  search patterns.
- low_signal_patterns_to_avoid: include any single-English-word tokens that
  appear in the advisory but would be noisy pickaxe targets (e.g. "audit",
  "publish", "valid", "match"). Downstream code uses this as an explicit
  exclusion list.
"""


@dataclass
class ParsedAdvisory:
    cwe_id: str | None = None
    vulnerability_class: str | None = None
    vulnerable_construct: str | None = None
    vulnerable_functions: list[str] = field(default_factory=list)
    vulnerable_parameters: list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)
    expected_fix_behavior: str | None = None
    high_signal_search_patterns: list[str] = field(default_factory=list)
    low_signal_patterns_to_avoid: list[str] = field(default_factory=list)
    parse_status: str = "parsed"
    parse_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ParsedAdvisory:
        if not isinstance(data, dict):
            return cls()
        return cls(
            cwe_id=_clean_str(data.get("cwe_id")),
            vulnerability_class=_clean_str(data.get("vulnerability_class")),
            vulnerable_construct=_clean_str(data.get("vulnerable_construct")),
            vulnerable_functions=_clean_list(data.get("vulnerable_functions")),
            vulnerable_parameters=_clean_list(data.get("vulnerable_parameters")),
            affected_endpoints=_clean_list(data.get("affected_endpoints")),
            expected_fix_behavior=_clean_str(data.get("expected_fix_behavior")),
            high_signal_search_patterns=_clean_list(data.get("high_signal_search_patterns")),
            low_signal_patterns_to_avoid=_clean_list(data.get("low_signal_patterns_to_avoid")),
            parse_status=str(data.get("parse_status") or "parsed"),
            parse_error=_clean_str(data.get("parse_error")),
        )


class AdvisoryParser:
    """Single-shot LLM parse, cached by advisory text hash."""

    def __init__(self, client: OpenAIClient | None):
        self.client = client

    def parse(self, advisory: dict[str, Any]) -> ParsedAdvisory:
        if self.client is None:
            return ParsedAdvisory(parse_status="skipped", parse_error="no OpenAI client configured")
        payload = self._build_payload(advisory)
        try:
            raw = self.client.json_response(SYSTEM_PROMPT, payload, max_output_tokens=1200)
        except OpenAIClientError as exc:
            logger.warning("AdvisoryParser: OpenAI call failed for %s: %s", advisory.get("ghsa_id"), exc)
            return ParsedAdvisory(parse_status="failed", parse_error=str(exc)[:300])
        parsed = ParsedAdvisory.from_dict(raw)
        # Sanity: if the parse produced nothing useful, mark it.
        if (
            not parsed.high_signal_search_patterns
            and not parsed.vulnerable_functions
            and not parsed.vulnerable_construct
        ):
            parsed.parse_status = "low_quality"
        return parsed

    def _build_payload(self, advisory: dict[str, Any]) -> dict[str, Any]:
        return {
            "ghsa_id": advisory.get("ghsa_id"),
            "cve_ids": advisory.get("cve_ids"),
            "summary": advisory.get("summary"),
            "description": (advisory.get("description") or "")[:6000],
            "cwes": advisory.get("cwes") or [],
            "vulnerabilities": advisory.get("vulnerabilities") or [],
            "references": (advisory.get("references") or [])[:30],
        }


def _clean_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _clean_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in value:
        if isinstance(item, str):
            stripped = item.strip()
            if stripped and stripped.lower() not in seen:
                cleaned.append(stripped)
                seen.add(stripped.lower())
    return cleaned
