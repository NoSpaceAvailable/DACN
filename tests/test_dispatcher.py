"""Dispatcher tool-use loop — mock-based tests, zero network.

We build a fake chat model that returns a scripted sequence of
``AIMessage`` objects so we can assert the dispatcher:

- executes tool calls the LLM emits,
- appends ``ToolMessage`` replies in the right order,
- stops when the LLM emits no tool calls,
- stops at ``max_steps`` when the LLM loops forever,
- honours a :class:`DispatcherHook` that aborts,
- binds tools via ``chat_model.bind_tools`` when available.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Type

import pytest
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from pydantic import BaseModel, ConfigDict, Field

from vapt_orchestrator_safe.engine.dispatcher import (
    Dispatcher,
    DispatcherHook,
    DispatcherResult,
)
from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


# ── tiny tools used by these tests ───────────────────────────────────────
class _AddArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    a: int
    b: int


class AddTool(BaseTool):
    name: str = "add"
    description: str = "Add two integers."
    args_schema: Type[BaseModel] = _AddArgs

    def _invoke(self, **kwargs: Any) -> ToolResult:
        return ToolResult(stdout=str(kwargs["a"] + kwargs["b"]))


class _NoArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CrashTool(BaseTool):
    name: str = "crash"
    description: str = "Always raises — used to verify error envelope."
    args_schema: Type[BaseModel] = _NoArgs

    def _invoke(self, **kwargs: Any) -> ToolResult:
        raise RuntimeError("boom")


# ── scripted chat model ──────────────────────────────────────────────────
class _ScriptedChatModel:
    """Returns a pre-scripted sequence of AIMessages; records bind_tools calls."""

    def __init__(self, script: Iterable[AIMessage]):
        self.script = iter(script)
        self.sent_messages: List[List[BaseMessage]] = []
        self.bound_tools: List[List[Any]] = []

    def bind_tools(self, tools):
        self.bound_tools.append(list(tools))
        return self  # chainable; real LangChain returns a new runnable

    def invoke(self, messages, **_kwargs):
        self.sent_messages.append(list(messages))
        try:
            return next(self.script)
        except StopIteration as exc:                       # pragma: no cover
            raise AssertionError(
                "Chat script exhausted; dispatcher asked for more turns than scripted."
            ) from exc


def _bb(tmp_path: Path) -> Blackboard:
    return Blackboard(run_id="t", run_dir=tmp_path)


# ── tests ────────────────────────────────────────────────────────────────
def test_dispatcher_finishes_when_llm_emits_no_tool_calls(tmp_path):
    chat = _ScriptedChatModel([AIMessage(content="done", tool_calls=[])])
    d = Dispatcher(chat, tools=[], blackboard=_bb(tmp_path),
                   system_prompt="sys", max_steps=5)
    r = d.run("go")
    assert r.stop_reason == "finished"
    assert r.final_text == "done"
    assert r.steps == 1
    assert r.tool_invocations == []


def test_dispatcher_executes_tool_then_follows_up(tmp_path):
    bb = _bb(tmp_path)
    script = [
        AIMessage(
            content="",
            tool_calls=[{"id": "c1", "name": "add", "args": {"a": 2, "b": 3}}],
        ),
        AIMessage(content="result=5", tool_calls=[]),
    ]
    chat = _ScriptedChatModel(script)
    tool = AddTool()
    d = Dispatcher(chat, tools=[tool], blackboard=bb, system_prompt="sys", max_steps=5)
    r = d.run("compute 2+3")

    assert r.stop_reason == "finished"
    assert r.final_text == "result=5"
    assert r.steps == 2
    assert r.tool_invocations == [{"name": "add", "args": {"a": 2, "b": 3}, "ok": True}]

    # The 2nd LLM invocation should have seen the tool result message.
    second_turn = chat.sent_messages[1]
    assert any(isinstance(m, ToolMessage) and m.tool_call_id == "c1" for m in second_turn)


def test_dispatcher_reports_unknown_tool_and_continues(tmp_path):
    bb = _bb(tmp_path)
    script = [
        AIMessage(
            content="",
            tool_calls=[{"id": "c1", "name": "mystery", "args": {}}],
        ),
        AIMessage(content="gave up", tool_calls=[]),
    ]
    chat = _ScriptedChatModel(script)
    d = Dispatcher(chat, tools=[AddTool()], blackboard=bb, system_prompt="sys", max_steps=5)
    r = d.run("go")

    assert r.stop_reason == "finished"
    assert r.tool_invocations[0]["ok"] is False
    assert r.tool_invocations[0]["error"] == "unknown_tool"

    # The LLM was fed back an error payload so it could react.
    second_turn = chat.sent_messages[1]
    reply = next(m for m in second_turn if isinstance(m, ToolMessage) and m.tool_call_id == "c1")
    assert "Unknown tool" in reply.content


def test_dispatcher_tool_crash_is_caught_as_failed_result(tmp_path):
    """BaseTool wraps exceptions into ToolResult(exit_code=-1) — dispatcher sees ok=True
    because the LangChain tool didn't raise; but the LLM sees the error text."""
    bb = _bb(tmp_path)
    script = [
        AIMessage(
            content="",
            tool_calls=[{"id": "c1", "name": "crash", "args": {}}],
        ),
        AIMessage(content="ok, moving on", tool_calls=[]),
    ]
    chat = _ScriptedChatModel(script)
    d = Dispatcher(chat, tools=[CrashTool()], blackboard=bb, system_prompt="sys", max_steps=5)
    r = d.run("go")
    assert r.stop_reason == "finished"
    reply = next(m for m in chat.sent_messages[1] if isinstance(m, ToolMessage))
    assert "RuntimeError" in reply.content or "boom" in reply.content


def test_dispatcher_stops_at_max_steps(tmp_path):
    # Loops forever: each turn calls add again.
    endless = [
        AIMessage(content="", tool_calls=[{"id": f"c{i}", "name": "add", "args": {"a": 1, "b": 1}}])
        for i in range(10)
    ]
    chat = _ScriptedChatModel(endless)
    d = Dispatcher(chat, tools=[AddTool()], blackboard=_bb(tmp_path),
                   system_prompt="sys", max_steps=3)
    r = d.run("go")
    assert r.stop_reason == "max_steps"
    assert r.steps == 3
    assert r.final_text is None


def test_dispatcher_binds_tools_to_chat_model(tmp_path):
    chat = _ScriptedChatModel([AIMessage(content="done", tool_calls=[])])
    tool = AddTool()
    Dispatcher(chat, tools=[tool], blackboard=_bb(tmp_path), system_prompt="sys")
    assert chat.bound_tools == [[tool]]


def test_dispatcher_hook_can_abort_before_step(tmp_path):
    class AbortAfterFirst(DispatcherHook):
        def __init__(self):
            self.steps_seen: List[int] = []

        def before_step(self, step, messages):
            self.steps_seen.append(step)
            return step <= 1  # abort before step 2

    script = [
        AIMessage(content="", tool_calls=[{"id": "c1", "name": "add", "args": {"a": 1, "b": 1}}]),
        AIMessage(content="never reached", tool_calls=[]),
    ]
    chat = _ScriptedChatModel(script)
    hook = AbortAfterFirst()
    d = Dispatcher(chat, tools=[AddTool()], blackboard=_bb(tmp_path),
                   system_prompt="sys", max_steps=5, hook=hook)
    r = d.run("go")
    assert r.stop_reason == "hook_abort"
    assert hook.steps_seen == [1, 2]  # returned True on 1, False on 2


def test_dispatcher_logs_events_to_blackboard(tmp_path):
    bb = _bb(tmp_path)
    chat = _ScriptedChatModel([AIMessage(content="done", tool_calls=[])])
    Dispatcher(chat, tools=[], blackboard=bb, system_prompt="sys").run("go")
    messages = [e["message"] for e in bb.events]
    assert any(m.startswith("step.1.invoke") for m in messages)
    assert any(m.startswith("step.1.finished") for m in messages)


def test_dispatcher_skips_bind_when_chat_model_has_no_bind_tools(tmp_path):
    class _Plain:
        def invoke(self, _m, **_k):
            return AIMessage(content="plain", tool_calls=[])
    plain = _Plain()
    tool = AddTool()
    d = Dispatcher(plain, tools=[tool], blackboard=_bb(tmp_path), system_prompt="sys")
    # Runs without raising — model is used as-is even though tools exist.
    r = d.run("x")
    assert r.stop_reason == "finished"
    assert r.final_text == "plain"


def test_dispatcher_skips_bind_when_no_tools(tmp_path):
    chat = _ScriptedChatModel([AIMessage(content="done", tool_calls=[])])
    Dispatcher(chat, tools=[], blackboard=_bb(tmp_path), system_prompt="sys")
    assert chat.bound_tools == []


# ── text-tool fallback tests ────────────────────────────────────────────

class _ToolUnsupportedModel:
    """Raises 'does not support tools' on first invoke, then works via text."""

    def __init__(self, text_responses: list[str]):
        self._responses = iter(text_responses)
        self._first = True

    def bind_tools(self, tools):
        return self

    def invoke(self, messages, **_kwargs):
        if self._first:
            self._first = False
            raise RuntimeError(
                "registry.ollama.ai/library/test:7b does not support tools "
                "(status code: 400)"
            )
        text = next(self._responses)
        return AIMessage(content=text, tool_calls=[])


def test_dispatcher_auto_fallback_to_text_tool_calling(tmp_path):
    """When native tool-calling raises 'does not support tools', the
    dispatcher switches to TextToolChatModel and retries."""
    model = _ToolUnsupportedModel([
        '```json\n{"tool_call": {"name": "add", "args": {"a": 3, "b": 4}}}\n```',
        "Result is 7. Done.",
    ])
    tool = AddTool()
    bb = _bb(tmp_path)
    d = Dispatcher(model, tools=[tool], blackboard=bb, system_prompt="sys", max_steps=5)
    r = d.run("compute 3 + 4")

    assert d._text_tool_fallback is True
    assert r.stop_reason == "finished"
    assert any(inv["name"] == "add" and inv["ok"] for inv in r.tool_invocations)
    fallback_events = [e for e in bb.events if e["message"] == "text_tool_fallback"]
    assert len(fallback_events) == 1


class _MisplacedToolCallModel:
    """Returns tool-call JSON in content with tool_calls=[] (simulates weak models)."""

    def __init__(self, responses: list[AIMessage]):
        self._responses = iter(responses)

    def bind_tools(self, tools):
        return self

    def invoke(self, messages, **_kwargs):
        return next(self._responses)


def test_dispatcher_adaptive_fallback_on_misplaced_tool_call(tmp_path):
    """When native tool_calls is empty but content contains a JSON tool call,
    the dispatcher switches to TextToolChatModel and rescues the call."""
    model = _MisplacedToolCallModel([
        AIMessage(
            content='```json\n{"name": "add", "args": {"a": 3, "b": 4}}\n```',
            tool_calls=[],
        ),
        AIMessage(content="The answer is 7.", tool_calls=[]),
    ])
    tool = AddTool()
    bb = _bb(tmp_path)
    d = Dispatcher(model, tools=[tool], blackboard=bb, system_prompt="sys", max_steps=5)
    r = d.run("compute 3 + 4")

    assert d._text_tool_fallback is True
    assert r.stop_reason == "finished"
    assert any(inv["name"] == "add" and inv["ok"] for inv in r.tool_invocations)
    adaptive_events = [e for e in bb.events if e["message"] == "text_tool_fallback_adaptive"]
    assert len(adaptive_events) == 1
    assert adaptive_events[0]["data"]["rescued_tool"] == "add"
