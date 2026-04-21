"""Knowledge graph — InMemoryKG, Neo4jKG (mocked), QueryKGTool / QueryRAGTool."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vapt_orchestrator_safe.kg import InMemoryKG, build_default_kg
from vapt_orchestrator_safe.kg.knowledge_graph import KGFact
from vapt_orchestrator_safe.kg.neo4j_kg import Neo4jKG
from vapt_orchestrator_safe.memory.rag import CompressedRAG
from vapt_orchestrator_safe.tools.kg_tools import QueryKGTool, QueryRAGTool


# ── InMemoryKG ──────────────────────────────────────────────────────────
def test_inmemory_add_node_then_query_triples():
    kg = InMemoryKG()
    kg.add_node("Payload", "Payload:x", vuln_class="IDOR")
    kg.add_node("Sink", "Sink:y")
    kg.add_edge("Payload:x", "TARGETS", "Sink:y", note="demo")

    triples = kg.query_triples(subject="Payload:x")
    assert len(triples) == 1
    assert triples[0].predicate == "TARGETS"
    assert triples[0].obj == "Sink:y"
    assert triples[0].props == {"note": "demo"}


def test_inmemory_query_by_family_returns_payloads_and_edges():
    kg = InMemoryKG()
    build_default_kg(kg)
    facts = kg.query_by_family("SQLi")
    assert any(f.subject == "Payload:sqli_auth_bypass" for f in facts)
    # Should include a TARGETS edge too.
    assert any(f.predicate == "TARGETS" for f in facts)


def test_inmemory_query_by_framework_walks_neighbours():
    kg = InMemoryKG()
    build_default_kg(kg)
    facts = kg.query_by_framework("flask")
    assert facts
    assert all(f.subject.startswith("Sink:") or f.obj == "Framework:flask" for f in facts)


def test_inmemory_neighbours_respects_depth_and_limit():
    kg = InMemoryKG()
    kg.add_node("A", "A:1"); kg.add_node("B", "B:1"); kg.add_node("C", "C:1")
    kg.add_edge("A:1", "E1", "B:1")
    kg.add_edge("B:1", "E2", "C:1")

    depth1 = kg.neighbours("A:1", depth=1)
    assert len(depth1) == 1 and depth1[0].obj == "B:1"

    depth2 = kg.neighbours("A:1", depth=2)
    assert len(depth2) == 2


def test_inmemory_size_counts_nodes_and_edges():
    kg = InMemoryKG()
    build_default_kg(kg)
    nodes, edges = kg.size()
    assert nodes >= 5 and edges >= 5


# ── Neo4jKG (driver mocked) ─────────────────────────────────────────────
class _FakeSession:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.run_calls = []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def run(self, cypher, **params):
        self.run_calls.append((cypher, params))
        return _FakeResult(self.rows)


class _FakeResult:
    def __init__(self, rows):
        self.rows = rows
    def __iter__(self):
        return iter(self.rows)
    def single(self):
        return self.rows[0] if self.rows else None


class _FakeDriver:
    def __init__(self, rows=()):
        self.session_instance = _FakeSession(rows)
    def session(self):
        return self.session_instance
    def close(self): pass


def test_neo4jkg_add_node_parameterises_id_and_props():
    drv = _FakeDriver()
    kg = Neo4jKG(driver=drv)
    kg.add_node("Payload", "Payload:x", vuln_class="IDOR", extra=1)
    cypher, params = drv.session_instance.run_calls[0]
    assert "MERGE (n:Payload" in cypher
    assert params["id"] == "Payload:x"
    assert params["props"]["vuln_class"] == "IDOR"


def test_neo4jkg_add_edge_uses_match_merge():
    drv = _FakeDriver()
    Neo4jKG(driver=drv).add_edge("Payload:x", "TARGETS", "Sink:y", weight=0.9)
    cypher, params = drv.session_instance.run_calls[0]
    assert "MATCH" in cypher and "MERGE" in cypher and ":TARGETS" in cypher
    assert params["src"] == "Payload:x" and params["dst"] == "Sink:y"


def test_neo4jkg_query_by_family_returns_facts():
    rows = [
        {"s": "Payload:x", "rel": "TARGETS", "o": "Sink:y", "props": {"weight": 0.9}},
    ]
    kg = Neo4jKG(driver=_FakeDriver(rows))
    facts = kg.query_by_family("IDOR")
    assert len(facts) == 1 and facts[0].subject == "Payload:x"


def test_neo4jkg_rejects_invalid_labels():
    kg = Neo4jKG(driver=_FakeDriver())
    with pytest.raises(ValueError):
        kg.add_node("Bad Label!", "x")
    with pytest.raises(ValueError):
        kg.add_edge("a", "BAD REL", "b")


def test_neo4jkg_requires_password_when_no_driver(monkeypatch):
    monkeypatch.delenv("NEO4J_PASSWORD", raising=False)
    with pytest.raises(RuntimeError):
        Neo4jKG()


# ── QueryKGTool ─────────────────────────────────────────────────────────
def test_query_kg_tool_returns_compact_triples():
    kg = InMemoryKG()
    build_default_kg(kg)
    out = QueryKGTool(kg).invoke({"attack_family": "IDOR", "limit": 5})
    payload = json.loads(out.split("\n", 1)[1])
    assert payload["count"] >= 1
    assert "approx_tokens" in payload
    # KG payload must be materially smaller than a raw dump of the same info.
    assert payload["approx_tokens"] < 500


def test_query_kg_tool_requires_at_least_one_filter():
    kg = InMemoryKG()
    out = QueryKGTool(kg).invoke({})
    assert "exit=2" in out


def test_query_kg_tool_subject_path():
    kg = InMemoryKG()
    build_default_kg(kg)
    out = QueryKGTool(kg).invoke({"subject": "Payload:sqli_auth_bypass", "limit": 5})
    payload = json.loads(out.split("\n", 1)[1])
    assert payload["count"] >= 1


# ── QueryRAGTool ────────────────────────────────────────────────────────
def test_query_rag_tool_returns_cards():
    project_root = Path(__file__).resolve().parents[1]
    rag = CompressedRAG(project_root / "data" / "kb")
    out = QueryRAGTool(rag).invoke({"query": "idor authorization invoice", "top_k": 3})
    payload = json.loads(out.split("\n", 1)[1])
    assert payload["count"] >= 1
    assert "approx_tokens" in payload


def test_kg_is_cheaper_than_rag_for_same_question():
    """Headline C3 metric: KG tokens < RAG tokens on the same intent."""
    kg = InMemoryKG()
    build_default_kg(kg)
    project_root = Path(__file__).resolve().parents[1]
    rag = CompressedRAG(project_root / "data" / "kb")

    kg_out = QueryKGTool(kg).invoke({"attack_family": "SQLi", "limit": 10})
    rag_out = QueryRAGTool(rag).invoke({"query": "sql injection login bypass", "top_k": 4})

    kg_tokens = json.loads(kg_out.split("\n", 1)[1])["approx_tokens"]
    rag_tokens = json.loads(rag_out.split("\n", 1)[1])["approx_tokens"]
    # KG should be meaningfully cheaper.
    assert kg_tokens < rag_tokens, (kg_tokens, rag_tokens)
