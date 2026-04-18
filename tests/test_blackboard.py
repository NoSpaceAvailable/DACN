"""Blackboard tests — new fields, thread-safety smoke, backward-compat alias."""
from __future__ import annotations

import threading
from pathlib import Path

import pytest

from vapt_orchestrator_safe.memory.evidence import EvidenceItem
from vapt_orchestrator_safe.memory.shared_memory import Blackboard, SharedMemory


def _bb(tmp_path: Path) -> Blackboard:
    return Blackboard(run_id="t", run_dir=tmp_path)


def test_alias_for_backward_compat():
    # Existing callers do `from ...shared_memory import SharedMemory`
    assert SharedMemory is Blackboard


def test_phase_context_get_creates_default(tmp_path):
    bb = _bb(tmp_path)
    ctx = bb.get_phase_context("recon")
    ctx["foo"] = "bar"
    assert bb.get_phase_context("recon") == {"foo": "bar"}


def test_phase_context_set_overrides(tmp_path):
    bb = _bb(tmp_path)
    bb.set_phase_context("recon", {"a": 1})
    bb.set_phase_context("recon", {"b": 2})
    assert bb.get_phase_context("recon") == {"b": 2}


def test_kg_handle_starts_none(tmp_path):
    assert _bb(tmp_path).kg_handle is None


def test_loop_signature_count_increases_on_repeat(tmp_path):
    bb = _bb(tmp_path)
    assert bb.push_loop_signature("nmap:abc") == 1
    assert bb.push_loop_signature("nmap:abc") == 2
    assert bb.push_loop_signature("curl:xyz") == 1
    assert bb.loop_count("nmap:abc") == 2


def test_loop_signature_buffer_is_bounded(tmp_path):
    bb = _bb(tmp_path)
    for i in range(40):  # capacity is 32
        bb.push_loop_signature(f"sig{i}")
    assert len(bb.loop_signatures) == 32
    assert bb.loop_count("sig0") == 0  # evicted
    assert bb.loop_count("sig39") == 1


def test_reset_loop_signatures_clears(tmp_path):
    bb = _bb(tmp_path)
    bb.push_loop_signature("x")
    bb.push_loop_signature("y")
    bb.reset_loop_signatures()
    assert len(bb.loop_signatures) == 0


def test_snapshot_includes_new_fields_but_not_kg_handle(tmp_path):
    bb = _bb(tmp_path)
    bb.set_phase_context("recon", {"hello": "world"})
    bb.push_loop_signature("nmap:abc")
    bb.kg_handle = object()  # simulate live driver
    snap = bb.snapshot()
    assert snap["phase_context"] == {"recon": {"hello": "world"}}
    assert snap["loop_signatures"] == ["nmap:abc"]
    assert "kg_handle" not in snap


def test_snapshot_returns_independent_copies(tmp_path):
    bb = _bb(tmp_path)
    bb.add_task("recon", "pending")
    snap = bb.snapshot()
    snap["task_graph"].append({"name": "evil", "status": "x", "metadata": {}})
    # mutating snapshot does NOT mutate the live blackboard
    assert all(t["name"] != "evil" for t in bb.task_graph)


def test_persist_writes_memory_json(tmp_path):
    bb = _bb(tmp_path)
    bb.add_task("recon", "pending")
    bb.persist()
    assert (tmp_path / "memory.json").exists()


def test_existing_api_unchanged(tmp_path):
    """Sprint 1 callers used add_task/update_task/add_evidence/add_artifact/log_event."""
    bb = _bb(tmp_path)
    bb.add_task("recon", "pending")
    bb.update_task("recon", "running", {"tool": "nmap"})
    bb.add_evidence(EvidenceItem("e1", "recon", "summary", {"k": "v"}, ["tag"]))
    bb.add_artifact("scan", {"hosts": [1, 2]})
    bb.log_event("recon", "started")
    bb.set_budget({"tool_calls": 1})
    snap = bb.snapshot()
    assert snap["task_graph"][0]["status"] == "running"
    assert snap["evidence"][0]["evidence_id"] == "e1"
    assert snap["artifacts"][0]["payload"]["hosts"] == [1, 2]
    assert snap["events"][0]["message"] == "started"
    assert snap["budget"] == {"tool_calls": 1}


# ── thread-safety smoke (does not prove correctness, but catches obvious races) ──
def test_concurrent_writers_dont_lose_records(tmp_path):
    bb = _bb(tmp_path)
    n_threads = 8
    per_thread = 200

    def worker(tid: int):
        for i in range(per_thread):
            bb.add_artifact("worker", {"tid": tid, "i": i})
            bb.log_event("worker", f"{tid}:{i}")
            bb.push_loop_signature(f"sig:{tid}:{i % 4}")

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    expected = n_threads * per_thread
    assert len(bb.artifacts) == expected
    assert len(bb.events) == expected
