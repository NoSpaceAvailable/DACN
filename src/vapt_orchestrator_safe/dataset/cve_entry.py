"""CveEntry — the core data model for the distilled vulnerability corpus.

Each entry represents a single vulnerability class or CVE instance,
distilled to the minimum fields the Dispatcher / KG / RAG need:

- **Identification**: cve_id, cwe_id, title
- **Classification**: vuln_class (IDOR / SSRF / SQLi / XSS / RCE / ...),
  severity (critical / high / medium / low)
- **Technical**: affected_frameworks, sinks, sources, payload_templates,
  oracle_hints
- **Writeup**: description (1-3 sentences), remediation (1-2 sentences)

The model is intentionally flat (no nested objects beyond lists) so it
serialises cleanly to JSON lines and maps 1:1 to KG nodes + edges.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CveEntry:
    cve_id: str
    cwe_id: str
    title: str
    vuln_class: str
    severity: str
    description: str
    affected_frameworks: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    payload_templates: List[str] = field(default_factory=list)
    oracle_hints: List[str] = field(default_factory=list)
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CveEntry":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    def to_kg_text(self) -> str:
        """Compact text representation for KG / RAG indexing (~50-150 tokens)."""
        parts = [f"[{self.cve_id}] {self.title} ({self.vuln_class}/{self.severity})"]
        if self.sinks:
            parts.append(f"Sinks: {', '.join(self.sinks)}")
        if self.payload_templates:
            parts.append(f"Payloads: {'; '.join(self.payload_templates[:3])}")
        if self.oracle_hints:
            parts.append(f"Oracle: {', '.join(self.oracle_hints[:2])}")
        if self.affected_frameworks:
            parts.append(f"Frameworks: {', '.join(self.affected_frameworks)}")
        return " | ".join(parts)

    @property
    def approx_tokens(self) -> int:
        return max(1, len(self.to_kg_text()) // 4)
