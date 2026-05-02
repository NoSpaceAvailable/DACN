"""Distiller — transforms raw CVE / writeup data into CveEntry corpus.

The distiller has two modes:

1. **from_jsonl(path)**: Load a JSONL file where each line is a JSON
   object with CveEntry-compatible fields. Used for bulk NVD ingest.

2. **from_seed()**: Load the built-in seed corpus (Sprint 8 offline).

After loading, the Distiller can:

- **populate_kg(kg)**: Inject all entries as nodes + edges into a KG
  (InMemoryKG or Neo4jKG). Each CveEntry becomes a CVE node, with
  edges to CWE, Framework, Sink, and Payload nodes.

- **to_jsonl(path)**: Export the corpus to a JSONL file for archival
  or transfer.

- **stats()**: Summary dict for logging / CLI output.

The pipeline is intentionally simple (no embeddings, no chunking) —
the KG already provides structured retrieval; the RAG layer handles
unstructured fallback.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from vapt_orchestrator_safe.dataset.cve_entry import CveEntry
from vapt_orchestrator_safe.dataset.seed import load_seed_corpus


class Distiller:
    """Load, filter, and export CveEntry corpora."""

    def __init__(self, entries: Optional[List[CveEntry]] = None) -> None:
        self.entries: List[CveEntry] = entries or []

    @classmethod
    def from_seed(cls) -> "Distiller":
        return cls(load_seed_corpus())

    @classmethod
    def from_jsonl(cls, path: Path) -> "Distiller":
        entries: List[CveEntry] = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                entries.append(CveEntry.from_dict(data))
        return cls(entries)

    def to_jsonl(self, path: Path) -> int:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for entry in self.entries:
                f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        return len(self.entries)

    def filter_by_class(self, vuln_class: str) -> "Distiller":
        filtered = [e for e in self.entries if e.vuln_class.lower() == vuln_class.lower()]
        return Distiller(filtered)

    def filter_by_severity(self, *severities: str) -> "Distiller":
        sev_set = {s.lower() for s in severities}
        filtered = [e for e in self.entries if e.severity.lower() in sev_set]
        return Distiller(filtered)

    def populate_kg(self, kg: Any) -> Dict[str, int]:
        """Inject all entries into the knowledge graph. Returns counts."""
        nodes_added = 0
        edges_added = 0

        for entry in self.entries:
            kg.add_node(
                "CVE", f"CVE:{entry.cve_id}",
                title=entry.title,
                vuln_class=entry.vuln_class,
                severity=entry.severity,
                description=entry.description,
            )
            nodes_added += 1

            if entry.cwe_id:
                kg.add_node("CWE", f"CWE:{entry.cwe_id}")
                kg.add_edge(f"CVE:{entry.cve_id}", "CLASSIFIED_AS", f"CWE:{entry.cwe_id}")
                edges_added += 1

            for fw in entry.affected_frameworks:
                fw_id = f"Framework:{fw.lower()}"
                kg.add_node("Framework", fw_id, language=fw.lower())
                kg.add_edge(f"CVE:{entry.cve_id}", "AFFECTS", fw_id)
                edges_added += 1

            for sink in entry.sinks:
                sink_id = f"Sink:{sink}"
                kg.add_node("Sink", sink_id, kind=sink)
                kg.add_edge(f"CVE:{entry.cve_id}", "EXPLOITS", sink_id)
                edges_added += 1

            for i, payload in enumerate(entry.payload_templates):
                payload_id = f"Payload:{entry.cve_id}_{i}"
                kg.add_node(
                    "Payload", payload_id,
                    vuln_class=entry.vuln_class,
                    template=payload,
                )
                kg.add_edge(payload_id, "TARGETS", f"CVE:{entry.cve_id}")
                edges_added += 1

                for sink in entry.sinks:
                    kg.add_edge(payload_id, "TARGETS", f"Sink:{sink}")
                    edges_added += 1

        return {"nodes_added": nodes_added, "edges_added": edges_added}

    def stats(self) -> Dict[str, Any]:
        by_class: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        total_payloads = 0
        total_tokens = 0

        for e in self.entries:
            by_class[e.vuln_class] = by_class.get(e.vuln_class, 0) + 1
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            total_payloads += len(e.payload_templates)
            total_tokens += e.approx_tokens

        return {
            "total_entries": len(self.entries),
            "by_class": by_class,
            "by_severity": by_severity,
            "total_payloads": total_payloads,
            "approx_total_tokens": total_tokens,
        }

    def merge(self, other: "Distiller") -> "Distiller":
        seen = {e.cve_id for e in self.entries}
        merged = list(self.entries)
        for e in other.entries:
            if e.cve_id not in seen:
                merged.append(e)
                seen.add(e.cve_id)
        return Distiller(merged)
