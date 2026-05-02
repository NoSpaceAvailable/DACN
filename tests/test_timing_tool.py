"""BlindTimingSampler tests -- timing side-channel detection without real HTTP."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict

import pytest

from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.tools.security.timing import BlindTimingSampler
from vapt_orchestrator_safe.utils.scope import Scope, ScopeError, ScopeGuard


def _bb(tmp_path: Path) -> Blackboard:
    return Blackboard(run_id="t", run_dir=tmp_path)


def _scope_localhost() -> ScopeGuard:
    return ScopeGuard(Scope.from_manifest({
        "scope": {"allow_hosts": ["127.0.0.1", "localhost"], "allow_ports": [80, 8080]}
    }))


# ── fake session that simulates timing ───────────────────────────────────
class _FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.headers = {}
        self.text = "ok"


class _TimingSession:
    """Simulates response-time differences based on parameter values."""

    def __init__(self, *, sleep_param_value: str, sleep_seconds: float):
        self._sleep_value = sleep_param_value
        self._sleep_seconds = sleep_seconds
        self.calls: list = []

    def request(self, **kwargs: Any) -> _FakeResponse:
        self.calls.append(kwargs)
        param_value = self._extract_param_value(kwargs)
        if param_value == self._sleep_value:
            time.sleep(self._sleep_seconds)
        return _FakeResponse()

    @staticmethod
    def _extract_param_value(kwargs: Dict[str, Any]) -> str:
        for key in ("params", "data", "json"):
            container = kwargs.get(key)
            if isinstance(container, dict):
                for v in container.values():
                    return str(v)
        return ""


# ── happy path: vulnerable detected ─────────────────────────────────────
def test_timing_detects_vulnerable_endpoint(tmp_path):
    bb = _bb(tmp_path)
    session = _TimingSession(sleep_param_value="1' AND SLEEP(0.3)--", sleep_seconds=0.3)
    tool = BlindTimingSampler(scope=_scope_localhost(), session=session).bind_blackboard(bb)

    out = tool.invoke({
        "url": "http://127.0.0.1:8080/search",
        "param_name": "q",
        "baseline_value": "hello",
        "payload_value": "1' AND SLEEP(0.3)--",
        "sleep_seconds": 0.3,
        "samples": 2,
        "timeout": 5.0,
        "threshold": 0.5,
    })

    assert "exit=0" in out
    payload = json.loads(out.split("\n", 1)[1])
    assert payload["is_vulnerable"] is True
    assert payload["delta_ms"] > 100
    assert payload["samples"] == 2
    assert len(bb.artifacts) == 1
    assert bb.artifacts[0]["kind"] == "tool:blind_timing"


# ── happy path: not vulnerable ───────────────────────────────────────────
def test_timing_reports_not_vulnerable_when_no_delay(tmp_path):
    bb = _bb(tmp_path)
    session = _TimingSession(sleep_param_value="NEVER_MATCH", sleep_seconds=0.5)
    tool = BlindTimingSampler(scope=_scope_localhost(), session=session).bind_blackboard(bb)

    out = tool.invoke({
        "url": "http://127.0.0.1:8080/search",
        "param_name": "q",
        "baseline_value": "hello",
        "payload_value": "1' AND SLEEP(3)--",
        "sleep_seconds": 3.0,
        "samples": 2,
    })

    payload = json.loads(out.split("\n", 1)[1])
    assert payload["is_vulnerable"] is False
    assert abs(payload["delta_ms"]) < 500


# ── scope enforcement ────────────────────────────────────────────────────
def test_timing_refuses_out_of_scope_url():
    tool = BlindTimingSampler(scope=_scope_localhost())
    out = tool.invoke({
        "url": "http://evil.example/",
        "param_name": "q",
        "baseline_value": "a",
        "payload_value": "b",
    })
    assert "exit=-1" in out
    assert "ScopeError" in out


# ── inject modes ─────────────────────────────────────────────────────────
def test_timing_inject_in_body():
    session = _TimingSession(sleep_param_value="NEVER", sleep_seconds=0)
    tool = BlindTimingSampler(scope=_scope_localhost(), session=session)
    tool.invoke({
        "url": "http://127.0.0.1/",
        "method": "POST",
        "param_name": "user",
        "baseline_value": "admin",
        "payload_value": "admin'--",
        "inject_in": "body",
        "samples": 2,
    })
    assert any(c.get("data") == {"user": "admin"} for c in session.calls)


def test_timing_inject_in_json():
    session = _TimingSession(sleep_param_value="NEVER", sleep_seconds=0)
    tool = BlindTimingSampler(scope=_scope_localhost(), session=session)
    tool.invoke({
        "url": "http://127.0.0.1/",
        "method": "POST",
        "param_name": "user",
        "baseline_value": "admin",
        "payload_value": "admin'--",
        "inject_in": "json",
        "samples": 2,
    })
    assert any(c.get("json") == {"user": "admin"} for c in session.calls)


# ── validation ───────────────────────────────────────────────────────────
def test_timing_rejects_invalid_method():
    tool = BlindTimingSampler(scope=_scope_localhost())
    out = tool.invoke({
        "url": "http://127.0.0.1/",
        "param_name": "q",
        "baseline_value": "a",
        "payload_value": "b",
        "method": "DELETE",
    })
    assert "exit=2" in out


def test_timing_rejects_invalid_inject_in():
    tool = BlindTimingSampler(scope=_scope_localhost())
    out = tool.invoke({
        "url": "http://127.0.0.1/",
        "param_name": "q",
        "baseline_value": "a",
        "payload_value": "b",
        "inject_in": "cookie",
    })
    assert "exit=2" in out


# ── samples clamped ──────────────────────────────────────────────────────
def test_timing_clamps_samples_to_bounds():
    session = _TimingSession(sleep_param_value="NEVER", sleep_seconds=0)
    tool = BlindTimingSampler(scope=_scope_localhost(), session=session)
    out = tool.invoke({
        "url": "http://127.0.0.1/",
        "param_name": "q",
        "baseline_value": "a",
        "payload_value": "b",
        "samples": 1,  # below min (2)
    })
    payload = json.loads(out.split("\n", 1)[1])
    assert payload["samples"] == 2


# ── metadata recorded ───────────────────────────────────────────────────
def test_timing_metadata_contains_verdict(tmp_path):
    bb = _bb(tmp_path)
    session = _TimingSession(sleep_param_value="NEVER", sleep_seconds=0)
    tool = BlindTimingSampler(scope=_scope_localhost(), session=session).bind_blackboard(bb)
    tool.invoke({
        "url": "http://127.0.0.1/",
        "param_name": "q",
        "baseline_value": "a",
        "payload_value": "b",
        "samples": 2,
    })
    meta = bb.artifacts[0]["payload"]["result"]["metadata"]
    assert "verdict" in meta
    assert "delta_ms" in meta


# ── works without blackboard ─────────────────────────────────────────────
def test_timing_works_unbound():
    session = _TimingSession(sleep_param_value="NEVER", sleep_seconds=0)
    tool = BlindTimingSampler(scope=_scope_localhost(), session=session)
    out = tool.invoke({
        "url": "http://127.0.0.1/",
        "param_name": "q",
        "baseline_value": "a",
        "payload_value": "b",
        "samples": 2,
    })
    assert "exit=0" in out
