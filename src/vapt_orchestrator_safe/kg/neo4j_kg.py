"""Neo4j-backed KG implementation.

Activated when ``NEO4J_URI``, ``NEO4J_USER``, ``NEO4J_PASSWORD`` env vars
are set (or passed explicitly). Otherwise the :class:`InMemoryKG` is
used — same interface, same test surface.

We purposely keep the Cypher simple: parameterised ``MERGE`` for writes
and parameterised ``MATCH`` + ``LIMIT`` for reads. Sprint 8 can wire in
LLM-generated Cypher for richer queries; this module guarantees the
basics work first.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from vapt_orchestrator_safe.kg.knowledge_graph import KGFact


class Neo4jKG:
    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        *,
        driver: Any = None,  # test injection
    ):
        if driver is not None:
            self._driver = driver
        else:
            uri = uri or os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687")
            user = user or os.environ.get("NEO4J_USER", "neo4j")
            password = password or os.environ.get("NEO4J_PASSWORD")
            if not password:
                raise RuntimeError(
                    "Neo4jKG requires NEO4J_PASSWORD (env or argument); "
                    "set it or fall back to InMemoryKG."
                )
            from neo4j import GraphDatabase  # local import so tests without neo4j still run
            self._driver = GraphDatabase.driver(uri, auth=(user, password))

    # ── write ────────────────────────────────────────────────────────────
    def add_node(self, node_type: str, node_id: str, **props: Any) -> None:
        cypher = f"MERGE (n:{_safe_label(node_type)} {{id: $id}}) SET n += $props"
        with self._driver.session() as s:
            s.run(cypher, id=node_id, props=props)

    def add_edge(self, src: str, rel: str, dst: str, **props: Any) -> None:
        cypher = (
            "MATCH (a {id: $src}), (b {id: $dst}) "
            f"MERGE (a)-[r:{_safe_label(rel)}]->(b) SET r += $props"
        )
        with self._driver.session() as s:
            s.run(cypher, src=src, dst=dst, props=props)

    # ── read ─────────────────────────────────────────────────────────────
    def query_by_family(self, attack_family: str, limit: int = 10) -> List[KGFact]:
        cypher = (
            "MATCH (p:Payload {vuln_class: $fam})-[r]->(b) "
            "RETURN p.id AS s, type(r) AS rel, b.id AS o, properties(r) AS props "
            "LIMIT $limit"
        )
        with self._driver.session() as s:
            result = s.run(cypher, fam=attack_family, limit=limit)
            return [_row_to_fact(record) for record in result]

    def query_by_framework(self, framework: str, limit: int = 10) -> List[KGFact]:
        fw_id = framework if framework.startswith("Framework:") else f"Framework:{framework.lower()}"
        cypher = (
            "MATCH (f {id: $fw})<-[r]-(x) "
            "RETURN x.id AS s, type(r) AS rel, f.id AS o, properties(r) AS props "
            "LIMIT $limit"
        )
        with self._driver.session() as s:
            return [_row_to_fact(record) for record in s.run(cypher, fw=fw_id, limit=limit)]

    def query_triples(
        self,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        obj: Optional[str] = None,
        limit: int = 10,
    ) -> List[KGFact]:
        where: List[str] = []
        params: Dict[str, Any] = {"limit": limit}
        if subject is not None:
            where.append("a.id = $subject")
            params["subject"] = subject
        if obj is not None:
            where.append("b.id = $obj")
            params["obj"] = obj
        rel_clause = f":{_safe_label(predicate)}" if predicate else ""
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        cypher = (
            f"MATCH (a)-[r{rel_clause}]->(b){where_sql} "
            "RETURN a.id AS s, type(r) AS rel, b.id AS o, properties(r) AS props "
            "LIMIT $limit"
        )
        with self._driver.session() as s:
            return [_row_to_fact(record) for record in s.run(cypher, **params)]

    def neighbours(self, node_id: str, *, depth: int = 1, limit: int = 20) -> List[KGFact]:
        depth = max(1, int(depth))
        cypher = (
            f"MATCH p = (a {{id: $id}})-[*1..{depth}]-(b) "
            "UNWIND relationships(p) AS r "
            "RETURN startNode(r).id AS s, type(r) AS rel, endNode(r).id AS o, "
            "properties(r) AS props LIMIT $limit"
        )
        with self._driver.session() as s:
            return [_row_to_fact(record) for record in s.run(cypher, id=node_id, limit=limit)]

    def size(self) -> Tuple[int, int]:
        with self._driver.session() as s:
            nodes = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            rels = s.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
            return int(nodes), int(rels)

    def close(self) -> None:
        try:
            self._driver.close()
        except Exception:                                   # pragma: no cover
            pass


def _safe_label(label: str) -> str:
    """Sanity check on label / rel-type used in Cypher templates.

    We never interpolate user strings into Cypher in this module — all
    callers pass literals — but a defensive check avoids footguns if
    someone later plumbs user input through.
    """
    if not label or not label.replace("_", "").isalnum():
        raise ValueError(f"Invalid Cypher label {label!r}")
    return label


def _row_to_fact(record: Any) -> KGFact:
    return KGFact(
        subject=record["s"],
        predicate=record["rel"],
        obj=record["o"],
        props=dict(record["props"] or {}),
    )
