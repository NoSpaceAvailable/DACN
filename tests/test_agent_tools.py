"""Agent-invoker tool wrappers — covers the full dispatcher→sub-agent path with fakes."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.tools.agent_tools import (
    InvokeAnalystTool,
    InvokeExploitTool,
    InvokeReconTool,
    InvokeReportTool,
    InvokeSignatureTool,
    PivotTool,
)
from vapt_orchestrator_safe.types import CandidatePoC, Hypothesis, ValidationResult


def _bb(tmp_path: Path) -> Blackboard:
    bb = Blackboard(run_id="t", run_dir=tmp_path)
    bb.set_phase_context("intake", {
        "manifest": {"id": "f1", "title": "Fake", "difficulty": 0.5},
        "transcript": {"routes": [{"method": "GET", "path": "/api/x"}], "observations": []},
        "source_files": [{"path": "x.py", "content": "print(1)"}],
        "ground_truth": {"expected_vulnerability": "IDOR", "oracle": "o1", "severity": "High"},
    })
    return bb


def _bind(tool, bb):
    tool.bind_blackboard(bb)
    return tool


# ── Recon ────────────────────────────────────────────────────────────────
def test_recon_tool_invokes_agent_and_writes_phase_context(tmp_path):
    bb = _bb(tmp_path)
    seen: Dict[str, Any] = {}
    def fake(p):
        seen.update(p)
        return {"route_map": ["GET /api/x"], "parameters": ["id"], "auth_surface": True, "source_indicators": []}
    out = _bind(InvokeReconTool(fake), bb).invoke({"focus": "auth"})
    assert "routes" in out  # summary_for_llm rendering
    ctx = bb.get_phase_context("recon")
    assert ctx["route_map"] == ["GET /api/x"]
    assert seen["focus"] == "auth"


def test_recon_tool_fails_fast_when_intake_missing(tmp_path):
    bb = Blackboard(run_id="t", run_dir=tmp_path)                     # no intake
    tool = _bind(InvokeReconTool(lambda p: {}), bb)
    out = tool.invoke({})
    assert "Intake" in out
    assert "exit=2" in out


# ── Signature ────────────────────────────────────────────────────────────
def test_signature_tool_requires_recon_first(tmp_path):
    bb = _bb(tmp_path)
    out = _bind(InvokeSignatureTool(lambda p: {"cards": []}), bb).invoke({})
    assert "invoke_recon" in out and "exit=2" in out


def test_signature_tool_ok_after_recon(tmp_path):
    bb = _bb(tmp_path)
    bb.set_phase_context("recon", {"route_map": ["GET /x"], "parameters": [], "source_indicators": []})
    tool = _bind(InvokeSignatureTool(lambda p: {
        "query": "q",
        "cards": [{"attack_family": "IDOR", "score": 0.9}],
    }), bb)
    out = tool.invoke({})
    assert "IDOR" in out
    assert bb.get_phase_context("signature")["cards"][0]["attack_family"] == "IDOR"


# ── Analyst ──────────────────────────────────────────────────────────────
def test_analyst_tool_returns_hypothesis_summary(tmp_path):
    bb = _bb(tmp_path)
    bb.set_phase_context("recon", {"route_map": [], "parameters": [], "source_indicators": []})
    bb.set_phase_context("signature", {"cards": []})
    hyps = [
        Hypothesis(attack_family="IDOR", confidence=0.8, rationale="r1"),
        Hypothesis(attack_family="SQLi", confidence=0.5, rationale="r2"),
    ]
    tool = _bind(InvokeAnalystTool(lambda p: hyps), bb)
    out = tool.invoke({})
    assert "IDOR" in out and "SQLi" in out
    assert len(bb.get_phase_context("analysis")["hypotheses"]) == 2


def test_analyst_tool_requires_prereqs(tmp_path):
    bb = _bb(tmp_path)
    # recon + signature missing
    out = _bind(InvokeAnalystTool(lambda p: []), bb).invoke({})
    assert "exit=2" in out


# ── Exploit + Validator ──────────────────────────────────────────────────
def test_exploit_tool_matches_by_family_and_records_validation(tmp_path):
    bb = _bb(tmp_path)
    hyps = [
        Hypothesis(attack_family="IDOR", confidence=0.9, rationale="r"),
        Hypothesis(attack_family="SSRF", confidence=0.7, rationale="r"),
    ]
    bb.set_phase_context("analysis", {"hypotheses": hyps})

    def fake_exploit(p):
        assert p["hypothesis"].attack_family == "IDOR"
        return CandidatePoC(
            attack_family="IDOR", title="poc", steps=[], oracle="o1", confidence=0.9,
        )

    def fake_validator(p):
        return ValidationResult(
            status="verified", attack_family="IDOR", severity="High",
            confidence=0.95, evidence=[], reasoning="ok",
        )

    tool = _bind(InvokeExploitTool(fake_exploit, fake_validator), bb)
    out = tool.invoke({"attack_family": "IDOR"})
    assert "verified" in out
    vals = bb.get_phase_context("exploit")["validations"]
    assert len(vals) == 1 and vals[0].status == "verified"


def test_exploit_tool_unknown_family_returns_error(tmp_path):
    bb = _bb(tmp_path)
    bb.set_phase_context("analysis", {
        "hypotheses": [Hypothesis(attack_family="IDOR", confidence=0.5, rationale="r")]
    })
    tool = _bind(InvokeExploitTool(lambda p: None, lambda p: None), bb)
    out = tool.invoke({"attack_family": "XXE"})
    assert "No hypothesis" in out and "exit=2" in out


def test_exploit_tool_requires_analysis(tmp_path):
    bb = _bb(tmp_path)
    tool = _bind(InvokeExploitTool(lambda p: None, lambda p: None), bb)
    out = tool.invoke({"attack_family": "IDOR"})
    assert "invoke_analyst" in out and "exit=2" in out


# ── Report ───────────────────────────────────────────────────────────────
def test_report_tool_summarises_findings(tmp_path):
    bb = _bb(tmp_path)
    bb.set_phase_context("exploit", {"validations": [
        ValidationResult(
            status="verified", attack_family="IDOR", severity="High",
            confidence=0.9, evidence=[], reasoning="",
        )
    ]})

    def fake_report(p):
        assert len(p["validations"]) == 1
        return {"fixture_id": "f1", "findings": [{"attack_family": "IDOR"}]}

    out = _bind(InvokeReportTool(fake_report), bb).invoke({})
    assert "f1" in out
    assert bb.get_phase_context("report")["fixture_id"] == "f1"


# ── Pivot ────────────────────────────────────────────────────────────────
def test_pivot_tool_resets_loop_signatures_and_logs(tmp_path):
    bb = _bb(tmp_path)
    bb.push_loop_signature("a")
    bb.push_loop_signature("a")
    assert bb.loop_count("a") == 2

    out = _bind(PivotTool(), bb).invoke({"reason": "stuck on SQLi"})
    assert "pivoted" in out
    assert bb.loop_count("a") == 0
    assert any(e["phase"] == "pivot" for e in bb.events)
