"""Recon agent tests: heuristic fallback + LLM-driven path with mocked model."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

from vapt_orchestrator_safe.agents.base import AgentDependencies
from vapt_orchestrator_safe.agents.recon import ReconAgent
from vapt_orchestrator_safe.engine.budget import BudgetTracker
from vapt_orchestrator_safe.engine.router import ModelRouter
from vapt_orchestrator_safe.llm.fake_models import RuleBasedModel
from vapt_orchestrator_safe.llm.ollama_model import OllamaResponse
from vapt_orchestrator_safe.llm.registry import ModelRegistry
from vapt_orchestrator_safe.memory.shared_memory import SharedMemory
from vapt_orchestrator_safe.types import ModelProfile


def _profile() -> ModelProfile:
    return ModelProfile(
        name="t", label="t",
        reasoning=0.5, analysis=0.5, coding=0.5, reporting=0.5, recon=0.5, validation=0.5,
        cost_per_step=0.001, simulated_tokens_per_step=100,
    )


def _build_deps(model, tmp_path: Path) -> AgentDependencies:
    profiles = {"t": _profile()}
    profile_set = {"recon": "t"}
    router = ModelRouter(profiles, profile_set)
    registry = ModelRegistry(profiles, backend="rule")  # backend irrelevant; we inject model below
    deps = AgentDependencies(
        router=router,
        model_registry=registry,
        memory=SharedMemory(run_id="t", run_dir=tmp_path),
        budget=BudgetTracker(),
    )
    deps.budget.start()
    return deps


def _agent_with_model(model, tmp_path):
    deps = _build_deps(model, tmp_path)
    agent = ReconAgent(deps)
    agent.model = model  # bypass registry
    return agent, deps


# ── heuristic fallback ─────────────────────────────────────────────────────
def test_heuristic_path_when_model_lacks_generate(tmp_path):
    agent, _ = _agent_with_model(RuleBasedModel(_profile()), tmp_path)
    transcript = {
        "routes": [
            {"method": "GET", "path": "/api/invoices/1001"},
            {"method": "POST", "path": "/login"},
        ],
        "observations": ["session cookie issued"],
    }
    sources = [
        {"path": "app.py", "content": "SELECT * FROM users WHERE id = {user_id}"},
    ]
    result = agent.run(transcript, sources)
    assert "GET /api/invoices/1001" in result["route_map"]
    assert "unsafe_sql_formatting" in result["source_indicators"]
    # legacy field shape preserved
    assert isinstance(result["auth_surface"], bool)
    assert "_llm_raw" not in result


# ── LLM happy path ─────────────────────────────────────────────────────────
def test_llm_path_normalises_rich_json(tmp_path):
    fake_model = MagicMock()
    llm_payload = {
        "endpoints": [
            {"method": "GET", "path": "/api/invoices/1001", "params": ["invoice_id"]},
            {"method": "POST", "path": "/login", "params": ["username", "password"]},
        ],
        "auth_surface": "session",
        "stack_fingerprint": "Flask + SQLite",
        "suspicious_patterns": [
            {"id": "missing_ownership_check", "evidence": "app.py:42 fetches by id without owner check", "confidence": 0.8},
            {"id": "unsafe_sql_formatting", "evidence": "f\"SELECT * FROM users WHERE id={uid}\"", "confidence": 0.9},
        ],
        "next_recon_actions": ["enumerate /api/invoices/*"],
    }
    fake_model.generate.return_value = OllamaResponse(
        text='```json\n' + __import__("json").dumps(llm_payload) + '\n```',
        prompt_tokens=100, completion_tokens=200, total_duration_ns=10**9, raw=llm_payload,
    )
    agent, _ = _agent_with_model(fake_model, tmp_path)
    result = agent.run({"routes": [], "observations": []}, [{"path": "x", "content": "y"}])
    assert "GET /api/invoices/1001" in result["route_map"]
    assert "POST /login" in result["route_map"]
    assert result["parameters"] == ["invoice_id", "password", "username"]
    assert result["auth_surface"] is True
    assert set(result["source_indicators"]) == {"missing_ownership_check", "unsafe_sql_formatting"}
    assert result["_llm_raw"] == llm_payload
    # Verify think=False was sent (recon doesn't need CoT)
    call = fake_model.generate.call_args
    assert call.kwargs.get("think") is False


def test_llm_path_falls_back_when_response_is_garbage(tmp_path):
    fake_model = MagicMock()
    fake_model.generate.return_value = OllamaResponse(
        text="I am unable to comply with this request.",
        prompt_tokens=50, completion_tokens=10, total_duration_ns=10**9, raw={},
    )
    agent, deps = _agent_with_model(fake_model, tmp_path)
    transcript = {"routes": [{"method": "GET", "path": "/login"}], "observations": []}
    sources = [{"path": "app.py", "content": "SELECT * FROM x WHERE id = {q}"}]
    result = agent.run(transcript, sources)
    # Heuristic detected the unsafe SQL pattern and login route
    assert "GET /login" in result["route_map"]
    assert "unsafe_sql_formatting" in result["source_indicators"]
    # Memory log records the fallback
    assert any("falling back" in e["message"] for e in deps.memory.events)


def test_llm_path_falls_back_when_generate_raises(tmp_path):
    fake_model = MagicMock()
    fake_model.generate.side_effect = ConnectionError("VPS unreachable")
    agent, deps = _agent_with_model(fake_model, tmp_path)
    transcript = {"routes": [{"method": "GET", "path": "/api/invoices/1"}], "observations": []}
    sources = []
    result = agent.run(transcript, sources)
    assert "GET /api/invoices/1" in result["route_map"]
    assert any("falling back" in e["message"] for e in deps.memory.events)


def test_llm_path_rejects_non_object_json(tmp_path):
    fake_model = MagicMock()
    fake_model.generate.return_value = OllamaResponse(
        text='[1, 2, 3]',  # array, not object
        prompt_tokens=10, completion_tokens=10, total_duration_ns=10**9, raw=[1, 2, 3],
    )
    agent, deps = _agent_with_model(fake_model, tmp_path)
    result = agent.run({"routes": [], "observations": []}, [])
    # falls back to heuristic (which produces empty result for empty inputs)
    assert result["route_map"] == []
    assert any("falling back" in e["message"] for e in deps.memory.events)
