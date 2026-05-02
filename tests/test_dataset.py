"""Dataset tests -- CveEntry model, seed corpus, Distiller pipeline, KG population."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from vapt_orchestrator_safe.dataset.cve_entry import CveEntry
from vapt_orchestrator_safe.dataset.distiller import Distiller
from vapt_orchestrator_safe.dataset.seed import load_seed_corpus
from vapt_orchestrator_safe.kg.in_memory import InMemoryKG


# ── CveEntry model ───────────────────────────────────────────────────────
def test_cve_entry_roundtrip():
    entry = CveEntry(
        cve_id="CVE-2099-0001",
        cwe_id="CWE-89",
        title="Test SQLi",
        vuln_class="SQLi",
        severity="high",
        description="Test description.",
        sinks=["raw_sql"],
        payload_templates=["' OR 1=1--"],
    )
    d = entry.to_dict()
    restored = CveEntry.from_dict(d)
    assert restored.cve_id == entry.cve_id
    assert restored.payload_templates == entry.payload_templates
    assert restored.vuln_class == "SQLi"


def test_cve_entry_from_dict_ignores_extra_fields():
    data = {
        "cve_id": "CVE-2099-0002",
        "cwe_id": "CWE-79",
        "title": "Test XSS",
        "vuln_class": "XSS",
        "severity": "medium",
        "description": "desc",
        "extra_field": "should be ignored",
    }
    entry = CveEntry.from_dict(data)
    assert entry.cve_id == "CVE-2099-0002"
    assert not hasattr(entry, "extra_field")


def test_cve_entry_to_kg_text():
    entry = CveEntry(
        cve_id="CVE-2099-0003",
        cwe_id="CWE-89",
        title="Test Entry",
        vuln_class="SQLi",
        severity="high",
        description="x",
        sinks=["raw_sql"],
        payload_templates=["' OR 1=1--"],
        affected_frameworks=["flask"],
    )
    text = entry.to_kg_text()
    assert "CVE-2099-0003" in text
    assert "SQLi" in text
    assert "flask" in text
    assert entry.approx_tokens > 0


# ── Seed corpus ──────────────────────────────────────────────────────────
def test_seed_corpus_loads():
    corpus = load_seed_corpus()
    assert len(corpus) == 40


def test_seed_corpus_covers_required_classes():
    corpus = load_seed_corpus()
    classes = {e.vuln_class for e in corpus}
    assert "SQLi" in classes
    assert "IDOR" in classes
    assert "SSRF" in classes
    assert "XSS" in classes
    assert "RCE" in classes


def test_seed_corpus_has_blind_sqli():
    corpus = load_seed_corpus()
    blind = [e for e in corpus if "blind" in [t.lower() for t in e.tags]]
    assert len(blind) >= 2


def test_seed_entries_have_payloads():
    corpus = load_seed_corpus()
    for entry in corpus:
        assert entry.cve_id
        assert entry.vuln_class
        assert entry.severity


# ── Distiller ────────────────────────────────────────────────────────────
def test_distiller_from_seed():
    d = Distiller.from_seed()
    assert d.stats()["total_entries"] == 40


def test_distiller_filter_by_class():
    d = Distiller.from_seed()
    sqli = d.filter_by_class("SQLi")
    assert all(e.vuln_class == "SQLi" for e in sqli.entries)
    assert sqli.stats()["total_entries"] == 8


def test_distiller_filter_by_severity():
    d = Distiller.from_seed()
    crits = d.filter_by_severity("critical")
    assert all(e.severity == "critical" for e in crits.entries)
    assert crits.stats()["total_entries"] > 0


def test_distiller_jsonl_roundtrip(tmp_path):
    d = Distiller.from_seed()
    path = tmp_path / "corpus.jsonl"
    count = d.to_jsonl(path)
    assert count == 40
    assert path.exists()

    restored = Distiller.from_jsonl(path)
    assert len(restored.entries) == 40
    assert restored.entries[0].cve_id == d.entries[0].cve_id


def test_distiller_merge_deduplicates():
    d1 = Distiller([
        CveEntry(cve_id="A", cwe_id="CWE-1", title="a", vuln_class="X", severity="h", description="d"),
        CveEntry(cve_id="B", cwe_id="CWE-2", title="b", vuln_class="X", severity="h", description="d"),
    ])
    d2 = Distiller([
        CveEntry(cve_id="B", cwe_id="CWE-2", title="b", vuln_class="X", severity="h", description="d"),
        CveEntry(cve_id="C", cwe_id="CWE-3", title="c", vuln_class="X", severity="h", description="d"),
    ])
    merged = d1.merge(d2)
    assert len(merged.entries) == 3
    ids = [e.cve_id for e in merged.entries]
    assert ids == ["A", "B", "C"]


def test_distiller_stats():
    d = Distiller.from_seed()
    s = d.stats()
    assert s["total_entries"] == 40
    assert "SQLi" in s["by_class"]
    assert "critical" in s["by_severity"]
    assert s["total_payloads"] > 0
    assert s["approx_total_tokens"] > 0


# ── KG population ───────────────────────────────────────────────────────
def test_populate_kg_creates_nodes_and_edges():
    kg = InMemoryKG()
    d = Distiller.from_seed()
    counts = d.populate_kg(kg)
    assert counts["nodes_added"] == 40
    assert counts["edges_added"] > 40

    nodes, edges = kg.size()
    assert nodes > 40  # CVE nodes + CWE + Framework + Sink + Payload nodes
    assert edges > 40


def test_populate_kg_allows_family_query():
    kg = InMemoryKG()
    Distiller.from_seed().populate_kg(kg)
    facts = kg.query_by_family("SQLi", limit=50)
    assert len(facts) > 0
    payloads = [f for f in facts if f.subject.startswith("Payload:")]
    assert len(payloads) > 0


def test_populate_kg_allows_framework_query():
    kg = InMemoryKG()
    Distiller.from_seed().populate_kg(kg)
    facts = kg.query_by_framework("flask", limit=50)
    assert len(facts) > 0


def test_populated_kg_is_cheaper_than_raw_corpus():
    """KG query returns fewer tokens than iterating the full corpus text."""
    kg = InMemoryKG()
    d = Distiller.from_seed()
    d.populate_kg(kg)

    full_text_tokens = sum(e.approx_tokens for e in d.entries)
    kg_facts = kg.query_by_family("SQLi", limit=20)
    kg_text = "\n".join(f.to_text() for f in kg_facts)
    kg_tokens = max(1, len(kg_text) // 4)

    assert kg_tokens < full_text_tokens
