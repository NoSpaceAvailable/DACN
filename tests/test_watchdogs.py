"""C1 mid-thinking watchdogs — unit tests + Dispatcher streaming integration."""
from __future__ import annotations

from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage, AIMessageChunk, BaseMessage, HumanMessage
from pydantic import BaseModel, ConfigDict

from vapt_orchestrator_safe.engine.dispatcher import Dispatcher
from vapt_orchestrator_safe.engine.watchdogs import (
    DriftWatchdog,
    LoopWatchdog,
    ScopeWatchdog,
    Watchdog,
    WatchdogVerdict,
)
from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.utils.scope import Scope, ScopeGuard


def _bb(tmp_path: Path) -> Blackboard:
    return Blackboard(run_id="t", run_dir=tmp_path)


# ── DriftWatchdog ───────────────────────────────────────────────────────
def test_drift_does_not_fire_before_min_buffer():
    wd = DriftWatchdog(focus_keywords=["target"], max_drift_chars=500, min_buffer_chars=200)
    assert wd.check("short").tripped is False


def test_drift_does_not_fire_when_focus_keyword_present():
    wd = DriftWatchdog(focus_keywords=["target_x"], max_drift_chars=200, min_buffer_chars=50)
    assert wd.check("I will attack target_x now " * 20).tripped is False


def test_drift_fires_after_max_chars_without_focus():
    wd = DriftWatchdog(focus_keywords=["target_x"], max_drift_chars=200, min_buffer_chars=50)
    v = wd.check("random musing about nothing relevant here " * 10)
    assert v.tripped is True
    assert v.name == "drift"
    assert "focus" in v.correction_for_next_turn.lower() or "focus" in v.reason.lower() or \
           "re-centre" in v.correction_for_next_turn.lower()


def test_drift_is_no_op_when_no_focus_keywords_given():
    wd = DriftWatchdog(focus_keywords=[], max_drift_chars=100, min_buffer_chars=50)
    assert wd.check("any text " * 50).tripped is False


# ── ScopeWatchdog ───────────────────────────────────────────────────────
def test_scope_watchdog_fires_on_out_of_scope_url():
    guard = ScopeGuard(Scope.from_manifest({"scope": {"allow_hosts": ["127.0.0.1"]}}))
    wd = ScopeWatchdog(guard)
    v = wd.check("I will request http://evil.example/path next")
    assert v.tripped is True
    assert "evil.example" in v.correction_for_next_turn


def test_scope_watchdog_allows_in_scope_url():
    guard = ScopeGuard(Scope.from_manifest({"scope": {"allow_hosts": ["127.0.0.1"]}}))
    wd = ScopeWatchdog(guard)
    assert wd.check("I will request http://127.0.0.1/api/x").tripped is False


def test_scope_watchdog_ignores_url_already_seen():
    guard = ScopeGuard(Scope.from_manifest({"scope": {"allow_hosts": ["127.0.0.1"]}}))
    wd = ScopeWatchdog(guard)
    # First time: fires. Trailing space marks URL as complete (not still streaming).
    assert wd.check("http://evil.example/ ").tripped is True
    # Second time (same URL): silent — so we don't fire again on the same chunk content.
    assert wd.check("http://evil.example/ and more text").tripped is False


def test_scope_watchdog_strips_trailing_punctuation():
    """Greedy URL regex captures sentence-terminating '.', ',', '!', '?', etc.
    Treating 'http://127.0.0.1:9007.' literally makes urlparse.port raise
    ValueError on '9007.' — used to crash the whole run."""
    guard = ScopeGuard(Scope.from_manifest(
        {"scope": {"allow_hosts": ["127.0.0.1"], "allow_ports": [9007]}}
    ))
    wd = ScopeWatchdog(guard)
    # Trailing period belongs to the sentence, not the URL. After strip,
    # the URL is in-scope → no trip, no crash.
    assert wd.check("I will hit http://127.0.0.1:9007. Next step is...").tripped is False


def test_scope_watchdog_skips_partial_url_at_buffer_end():
    """URL at buffer end may still be streaming — defer judgement until a
    terminator char arrives (otherwise we trip on every chunk of a typed-out
    URL like 'http://127.', 'http://127.0.', 'http://127.0.0.', …)."""
    guard = ScopeGuard(Scope.from_manifest(
        {"scope": {"allow_hosts": ["127.0.0.1"], "allow_ports": [9007]}}
    ))
    wd = ScopeWatchdog(guard)
    # Partial URL — buffer ends mid-IP. Don't trip.
    assert wd.check("I will exploit http://127.0.0.").tripped is False
    # Once a terminator arrives, judgement resumes (in-scope → silent).
    assert wd.check("I will exploit http://127.0.0.1:9007/key now.").tripped is False


# ── LoopWatchdog ────────────────────────────────────────────────────────
def test_loop_watchdog_fires_when_proposed_tool_already_at_threshold(tmp_path):
    bb = _bb(tmp_path)
    for _ in range(3):
        bb.push_loop_signature("invoke_exploit:abc")
    wd = LoopWatchdog(bb, threshold=3)
    proposed = '{"name": "invoke_exploit", "args": {"attack_family": "IDOR"}}'
    v = wd.check(f"Let me try another attempt {proposed}")
    assert v.tripped is True
    assert "pivot" in v.correction_for_next_turn


def test_loop_watchdog_silent_below_threshold(tmp_path):
    bb = _bb(tmp_path)
    bb.push_loop_signature("invoke_exploit:abc")
    wd = LoopWatchdog(bb, threshold=3)
    proposed = '{"name": "invoke_exploit", "args": {}}'
    assert wd.check(proposed).tripped is False


# ── Dispatcher streaming integration ────────────────────────────────────
class _StreamingChat:
    """Fake chat model with a scripted stream() method.

    Accepts a list of lists-of-chunks, one list per expected stream()
    invocation. bind_tools is chainable but no-op.
    """

    def __init__(self, stream_scripts, invoke_script=None):
        self.stream_scripts = iter(stream_scripts)
        self.invoke_script = iter(invoke_script or [])
        self.invoke_calls = 0
        self.sent: List[List[BaseMessage]] = []

    def bind_tools(self, _tools):
        return self

    def stream(self, messages, **_kw):
        self.sent.append(list(messages))
        return iter(next(self.stream_scripts))

    def invoke(self, messages, **_kw):
        self.invoke_calls += 1
        self.sent.append(list(messages))
        return next(self.invoke_script)


def _chunks(*texts):
    return [AIMessageChunk(content=t) for t in texts]


def test_dispatcher_streams_and_intervenes_on_drift(tmp_path):
    bb = _bb(tmp_path)
    # Turn 1: long drift with no focus keyword → drift watchdog trips.
    turn1 = _chunks("I have many thoughts ", "about cooking and poetry but nothing relevant " * 30)
    # Turn 2: final message (no tool calls) — intervention already resolved,
    # LLM now complies by producing an empty response to end the run.
    turn2 = _chunks("ok, re-focusing target_x and stopping.")
    chat = _StreamingChat(stream_scripts=[turn1, turn2])
    watchdog = DriftWatchdog(focus_keywords=["target_x"], max_drift_chars=200, min_buffer_chars=50)

    d = Dispatcher(
        chat_model=chat, tools=[], blackboard=bb,
        system_prompt="sys", max_steps=5, watchdogs=[watchdog],
    )
    result = d.run("go")

    assert len(d.watchdog_trips) == 1
    assert d.watchdog_trips[0]["name"] == "drift"
    # Turn 2 must see the injected HumanMessage correction.
    turn2_msgs = chat.sent[1]
    assert any(isinstance(m, HumanMessage) and "mid_thinking_guard" in m.content for m in turn2_msgs)
    # Events logged.
    messages = [e["message"] for e in bb.events]
    assert "drift" in messages
    assert any(m.endswith(".intervened") for m in messages)


def test_dispatcher_non_streaming_path_unaffected_when_no_watchdogs(tmp_path):
    """Sanity: without watchdogs, the dispatcher keeps using .invoke()."""
    chat = MagicMock()
    chat.bind_tools.return_value = chat
    chat.invoke.return_value = AIMessage(content="done", tool_calls=[])
    d = Dispatcher(chat_model=chat, tools=[], blackboard=_bb(tmp_path),
                   system_prompt="sys", max_steps=5)
    d.run("go")
    assert chat.invoke.called
    # No stream() attribute usage.
    assert not chat.stream.called


def test_dispatcher_falls_back_to_invoke_when_model_has_no_stream(tmp_path):
    """Watchdogs configured but model lacks .stream() → dispatcher uses invoke() safely."""
    class _NoStream:
        def bind_tools(self, _t): return self
        def invoke(self, _m, **_k): return AIMessage(content="done", tool_calls=[])
    chat = _NoStream()
    d = Dispatcher(chat_model=chat, tools=[], blackboard=_bb(tmp_path),
                   system_prompt="sys", max_steps=5,
                   watchdogs=[DriftWatchdog(focus_keywords=["x"])])
    r = d.run("go")
    assert r.stop_reason == "finished"
    assert d.watchdog_trips == []


def test_dispatcher_stream_completes_normally_when_no_watchdog_trips(tmp_path):
    bb = _bb(tmp_path)
    chunks = _chunks("all good, target_x mentioned. done.")
    chat = _StreamingChat(stream_scripts=[chunks])
    d = Dispatcher(
        chat_model=chat, tools=[], blackboard=bb,
        system_prompt="sys", max_steps=3,
        watchdogs=[DriftWatchdog(focus_keywords=["target_x"], max_drift_chars=200, min_buffer_chars=10)],
    )
    r = d.run("go")
    assert r.stop_reason == "finished"
    assert d.watchdog_trips == []


# ── DispatcherRunner wiring ─────────────────────────────────────────────
def test_runner_overrides_mid_thinking_flag(tmp_path):
    """ponytail: watchdogs tạm tắt while harness baseline is being evaluated.
    The runner ignores the enable_mid_thinking=True argument and treats it
    as False until the override in dispatcher_runner.__init__ is removed."""
    from vapt_orchestrator_safe.engine.dispatcher_runner import DispatcherRunner

    # Mid-thinking is overridden → dispatcher uses .invoke() not .stream().
    turn1 = _chunks("unused — stream path is bypassed when watchdog override is on")
    chat = _StreamingChat(
        stream_scripts=[turn1],
        invoke_script=[AIMessage(content="quick response, done.", tool_calls=[])],
    )

    fixture = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "challenge_idor_01"
    summary = DispatcherRunner(
        outputs_root=tmp_path, backend="rule",
        chat_model=chat, chat_model_backend_spec="scripted",
        max_steps=3, enable_sandbox=False,
        enable_mid_thinking=True,
        mid_thinking_max_drift_chars=50_000,
        require_report=False,
    ).run_fixture(fixture)

    import json
    memory = json.loads((Path(summary["output_dir"]) / "memory.json").read_text())
    messages = [e["message"] for e in memory["events"]]
    assert "mid_thinking.enabled" not in messages
    assert summary["watchdog_trips"] == []
