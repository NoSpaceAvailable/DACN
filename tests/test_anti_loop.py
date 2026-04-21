"""C2 Anti-loop guard — unit tests for LoopGuard + AntiLoopHook + end-to-end."""
from __future__ import annotations

from pathlib import Path
from typing import List, Type
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from pydantic import BaseModel, ConfigDict

from vapt_orchestrator_safe.engine.anti_loop import AntiLoopHook, LoopGuard
from vapt_orchestrator_safe.engine.dispatcher import Dispatcher
from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


def _bb(tmp_path: Path) -> Blackboard:
    return Blackboard(run_id="t", run_dir=tmp_path)


# ── LoopGuard (pure detection) ──────────────────────────────────────────
def test_loop_guard_fires_at_threshold(tmp_path):
    bb = _bb(tmp_path)
    guard = LoopGuard(bb, threshold=3)
    for _ in range(2):
        bb.push_loop_signature("sig-A")
    assert guard.check() is None
    bb.push_loop_signature("sig-A")  # now 3
    d = guard.check()
    assert d is not None
    assert d.signature == "sig-A"
    assert d.count == 3


def test_loop_guard_does_not_double_fire_on_same_signature(tmp_path):
    bb = _bb(tmp_path)
    guard = LoopGuard(bb, threshold=2)
    bb.push_loop_signature("x")
    bb.push_loop_signature("x")
    assert guard.check() is not None
    assert guard.check() is None  # same signature, no new detection


def test_loop_guard_refires_after_reset(tmp_path):
    bb = _bb(tmp_path)
    guard = LoopGuard(bb, threshold=2)
    bb.push_loop_signature("x")
    bb.push_loop_signature("x")
    guard.check()
    guard.reset()
    bb.push_loop_signature("x")
    bb.push_loop_signature("x")
    assert guard.check() is not None


def test_loop_guard_rejects_threshold_below_2(tmp_path):
    with pytest.raises(ValueError):
        LoopGuard(_bb(tmp_path), threshold=1)


def test_loop_guard_picks_most_repeated(tmp_path):
    bb = _bb(tmp_path)
    guard = LoopGuard(bb, threshold=2)
    bb.push_loop_signature("a"); bb.push_loop_signature("a")
    bb.push_loop_signature("b"); bb.push_loop_signature("b"); bb.push_loop_signature("b")
    d = guard.check()
    assert d.signature == "b" and d.count == 3


# ── AntiLoopHook (integration with Dispatcher) ──────────────────────────
class _LoopToolArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")


class _LoopTool(BaseTool):
    name: str = "loop_tool"
    description: str = "No-op; pushes a loop signature each call."
    args_schema: Type[BaseModel] = _LoopToolArgs

    def _invoke(self, **kwargs) -> ToolResult:
        return ToolResult(stdout="ok")


def _scripted_chat(script):
    it = iter(script)

    class _C:
        def __init__(self):
            self.sent: List[List[BaseMessage]] = []
        def bind_tools(self, tools): return self
        def invoke(self, messages, **_k):
            self.sent.append(list(messages))
            return next(it)
    return _C()


def test_anti_loop_hook_injects_pivot_guidance_after_three_repeats(tmp_path):
    bb = _bb(tmp_path)
    # 4 identical loop_tool calls then a terminator.
    script = [
        AIMessage(content="", tool_calls=[{"id": f"c{i}", "name": "loop_tool", "args": {}}])
        for i in range(4)
    ] + [AIMessage(content="done", tool_calls=[])]
    chat = _scripted_chat(script)
    tool = _LoopTool()
    hook = AntiLoopHook(bb, threshold=3, max_trips=4)
    d = Dispatcher(chat, tools=[tool], blackboard=bb,
                   system_prompt="sys", max_steps=10, hook=hook)
    d.run("go")

    assert len(hook.guard.trips) >= 1
    # The hook must have injected a HumanMessage with pivot guidance into
    # one of the later turns.
    injected_flags = [
        any(isinstance(m, HumanMessage) and "anti_loop_guard" in m.content for m in turn)
        for turn in chat.sent
    ]
    assert any(injected_flags), "Expected the hook to inject pivot guidance"

    messages = [e["message"] for e in bb.events]
    assert any(m == "loop_detected" for m in messages)


def test_anti_loop_hook_stops_intervening_after_max_trips(tmp_path):
    bb = _bb(tmp_path)
    # 15 repeats — far more than max_trips=2.
    script = [
        AIMessage(content="", tool_calls=[{"id": f"c{i}", "name": "loop_tool", "args": {}}])
        for i in range(15)
    ] + [AIMessage(content="done", tool_calls=[])]
    chat = _scripted_chat(script)
    hook = AntiLoopHook(bb, threshold=3, max_trips=2)
    d = Dispatcher(chat, tools=[_LoopTool()], blackboard=bb,
                   system_prompt="sys", max_steps=20, hook=hook)
    d.run("go")

    # Trips recorded = threshold crossings; with max_trips=2, further crossings
    # log max_trips.exhausted rather than injecting.
    msgs = [e["message"] for e in bb.events]
    assert msgs.count("loop_detected") <= 2
    assert "max_trips.exhausted" in msgs


def test_anti_loop_hook_noop_when_signatures_vary(tmp_path):
    bb = _bb(tmp_path)
    # Different args each call → different signatures → no loop.
    script = [
        AIMessage(
            content="",
            tool_calls=[{"id": f"c{i}", "name": "echo", "args": {"text": f"t{i}", "times": 1}}],
        ) for i in range(6)
    ] + [AIMessage(content="done", tool_calls=[])]
    from vapt_orchestrator_safe.tools.base import EchoTool
    chat = _scripted_chat(script)
    hook = AntiLoopHook(bb, threshold=3)
    d = Dispatcher(chat, tools=[EchoTool()], blackboard=bb,
                   system_prompt="sys", max_steps=10, hook=hook)
    d.run("go")
    assert hook.guard.trips == []
    assert not any(e["message"] == "loop_detected" for e in bb.events)


# ── DispatcherRunner wiring ──────────────────────────────────────────────
def test_dispatcher_runner_attaches_anti_loop_by_default(tmp_path):
    from vapt_orchestrator_safe.engine.dispatcher_runner import DispatcherRunner

    chat = _scripted_chat([
        AIMessage(content="", tool_calls=[{"id": "r1", "name": "invoke_recon", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "s1", "name": "invoke_signature", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "a1", "name": "invoke_analyst", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "e1", "name": "invoke_exploit",
                                          "args": {"attack_family": "IDOR"}}]),
        AIMessage(content="", tool_calls=[{"id": "rp", "name": "invoke_report", "args": {}}]),
        AIMessage(content="done", tool_calls=[]),
    ])
    fixture = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "challenge_idor_01"
    summary = DispatcherRunner(
        outputs_root=tmp_path, backend="rule",
        chat_model=chat, chat_model_backend_spec="scripted",
        max_steps=10, enable_sandbox=False,
    ).run_fixture(fixture)

    # anti-loop was enabled → recorded in events; no trips on a clean run.
    events_file = Path(summary["output_dir"]) / "memory.json"
    import json
    memory = json.loads(events_file.read_text())
    messages = [e["message"] for e in memory["events"]]
    assert "anti_loop.enabled" in messages
    assert "loop_detected" not in messages


def test_dispatcher_runner_can_disable_anti_loop(tmp_path):
    from vapt_orchestrator_safe.engine.dispatcher_runner import DispatcherRunner

    chat = _scripted_chat([
        AIMessage(content="", tool_calls=[{"id": "r1", "name": "invoke_recon", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "s1", "name": "invoke_signature", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "a1", "name": "invoke_analyst", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "e1", "name": "invoke_exploit",
                                          "args": {"attack_family": "IDOR"}}]),
        AIMessage(content="", tool_calls=[{"id": "rp", "name": "invoke_report", "args": {}}]),
        AIMessage(content="done", tool_calls=[]),
    ])
    fixture = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "challenge_idor_01"
    summary = DispatcherRunner(
        outputs_root=tmp_path, backend="rule",
        chat_model=chat, chat_model_backend_spec="scripted",
        max_steps=10, enable_sandbox=False,
        enable_anti_loop=False,
    ).run_fixture(fixture)

    import json
    memory = json.loads((Path(summary["output_dir"]) / "memory.json").read_text())
    messages = [e["message"] for e in memory["events"]]
    assert "anti_loop.enabled" not in messages
