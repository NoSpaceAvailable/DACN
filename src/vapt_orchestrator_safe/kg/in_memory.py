"""InMemoryKG — dict-of-dict graph satisfying the :class:`KG` protocol.

Zero-dependency, thread-safe, and perfectly fine for:

- Every unit test (no docker / neo4j needed in CI).
- Local dev runs on a laptop without spinning up Neo4j.
- The Sprint 8 eval ablation where we compare "KG off" (keyword RAG
  only) vs "KG on" — the in-memory graph is enough to demonstrate the
  token-savings story even before the full CVE corpus is loaded.

The Neo4j implementation (:class:`Neo4jKG`) only kicks in when the user
explicitly sets ``NEO4J_URI``, which matters once the graph grows past
what fits in memory or when multi-run persistence is desirable.
"""
from __future__ import annotations

from collections import defaultdict
from threading import RLock
from typing import Any, Dict, List, Optional, Tuple

from vapt_orchestrator_safe.kg.knowledge_graph import KGFact


class InMemoryKG:
    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        # Forward edges: src -> [(rel, dst, props)]
        self._forward: Dict[str, List[Tuple[str, str, Dict[str, Any]]]] = defaultdict(list)
        # Backward edges for neighbour queries: dst -> [(rel, src, props)]
        self._backward: Dict[str, List[Tuple[str, str, Dict[str, Any]]]] = defaultdict(list)
        self._lock = RLock()

    # ── write ────────────────────────────────────────────────────────────
    def add_node(self, node_type: str, node_id: str, **props: Any) -> None:
        with self._lock:
            existing = self._nodes.get(node_id)
            if existing is None:
                self._nodes[node_id] = {"_type": node_type, **props}
            else:
                existing.update(props)
                existing.setdefault("_type", node_type)

    def add_edge(self, src: str, rel: str, dst: str, **props: Any) -> None:
        with self._lock:
            self._forward[src].append((rel, dst, dict(props)))
            self._backward[dst].append((rel, src, dict(props)))

    # ── read ─────────────────────────────────────────────────────────────
    def query_by_family(self, attack_family: str, limit: int = 10) -> List[KGFact]:
        """Return payloads + sinks + CWE for a given attack family (IDOR / SSRF / SQLi / …)."""
        facts: List[KGFact] = []
        with self._lock:
            for node_id, props in self._nodes.items():
                if props.get("_type") != "Payload":
                    continue
                if str(props.get("vuln_class", "")).lower() != attack_family.lower():
                    continue
                facts.append(KGFact(
                    subject=node_id, predicate="HAS_ATTRIBUTES", obj=attack_family,
                    props={k: v for k, v in props.items() if not k.startswith("_")},
                ))
                for rel, dst, edge_props in self._forward.get(node_id, []):
                    facts.append(KGFact(subject=node_id, predicate=rel, obj=dst, props=edge_props))
                    if len(facts) >= limit:
                        return facts
        return facts[:limit]

    def query_by_framework(self, framework: str, limit: int = 10) -> List[KGFact]:
        fw_id = f"Framework:{framework.lower()}" if not framework.startswith("Framework:") else framework
        return self.neighbours(fw_id, depth=1, limit=limit)

    def query_triples(
        self,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        obj: Optional[str] = None,
        limit: int = 10,
    ) -> List[KGFact]:
        facts: List[KGFact] = []
        with self._lock:
            iterable = (
                [(subject, rel, dst, props) for rel, dst, props in self._forward.get(subject, [])]
                if subject else
                [(src, rel, dst, props)
                 for src, edges in self._forward.items()
                 for rel, dst, props in edges]
            )
            for src, rel, dst, props in iterable:
                if predicate is not None and rel != predicate:
                    continue
                if obj is not None and dst != obj:
                    continue
                facts.append(KGFact(subject=src, predicate=rel, obj=dst, props=props))
                if len(facts) >= limit:
                    break
        return facts

    def neighbours(self, node_id: str, *, depth: int = 1, limit: int = 20) -> List[KGFact]:
        if depth < 1:
            return []
        out: List[KGFact] = []
        seen_edges: set = set()
        with self._lock:
            frontier = {node_id}
            for _ in range(depth):
                next_frontier: set = set()
                for current in frontier:
                    for rel, dst, props in self._forward.get(current, []):
                        key = (current, rel, dst)
                        if key in seen_edges:
                            continue
                        seen_edges.add(key)
                        out.append(KGFact(subject=current, predicate=rel, obj=dst, props=props))
                        next_frontier.add(dst)
                        if len(out) >= limit:
                            return out
                    for rel, src, props in self._backward.get(current, []):
                        key = (src, rel, current)
                        if key in seen_edges:
                            continue
                        seen_edges.add(key)
                        out.append(KGFact(subject=src, predicate=rel, obj=current, props=props))
                        next_frontier.add(src)
                        if len(out) >= limit:
                            return out
                frontier = next_frontier
        return out

    def size(self) -> Tuple[int, int]:
        with self._lock:
            edge_count = sum(len(v) for v in self._forward.values())
            return len(self._nodes), edge_count

    def close(self) -> None:
        # nothing to do for in-memory
        return None
