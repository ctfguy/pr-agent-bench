"""Always-on, deterministic advisory enrichers (OSV + NVD).

These run after the GitHub Advisory normalization and contribute extra
direct-evidence signals (introduced/fixed commit ranges, additional
references, cleaner affected-version data) that the GitHub `/advisories`
endpoint sometimes omits. Pure HTTP, no LLM cost.
"""

from .enrichment import EnrichedRefs, enrich_advisory

__all__ = ["EnrichedRefs", "enrich_advisory"]
