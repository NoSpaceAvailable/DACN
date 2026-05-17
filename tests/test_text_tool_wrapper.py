"""Unit tests for the text-based tool-calling wrapper."""
from __future__ import annotations

from typing import Any, List, Type

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from pydantic import BaseModel, ConfigDict, Field

from vapt_orchestrator_safe.llm.text_tool_wrapper import (
    TextToolChatModel,
    _parse_tool_call,
    is_tool_unsupported_error,
)


# ── fixtures ──────────────────────────────────────────────────────────────

class _AddArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    a: int
    b: int


class _FakeTool:
    name = "add"
    description = "Add two integers."
    args_schema = _AddArgs


class _NoArgTool:
    name = "scan"
    description = "Run a scan."
    args_schema = None


TOOLS = [_FakeTool(), _NoArgTool()]
KNOWN = {"add", "scan"}


class _EchoModel:
    """Returns whatever text is given at construction."""

    def __init__(self, text: str):
        self._text = text

    def invoke(self, messages, **_kw):
        return AIMessage(content=self._text, tool_calls=[])

    def stream(self, messages, **_kw):
        from langchain_core.messages import AIMessageChunk
        for ch in self._text:
            yield AIMessageChunk(content=ch)


# ── _parse_tool_call ──────────────────────────────────────────────────────

def test_parse_fenced_tool_call():
    text = 'Sure!\n```json\n{"tool_call": {"name": "add", "args": {"a": 1, "b": 2}}}\n```'
    tc = _parse_tool_call(text, KNOWN)
    assert tc is not None
    assert tc["name"] == "add"
    assert tc["args"] == {"a": 1, "b": 2}


def test_parse_tool_calls_array():
    text = '```json\n{"tool_calls": [{"name": "scan", "args": {}}]}\n```'
    tc = _parse_tool_call(text, KNOWN)
    assert tc is not None
    assert tc["name"] == "scan"


def test_parse_bare_json():
    text = 'I will scan.\n{"tool_call": {"name": "scan", "args": {}}}'
    tc = _parse_tool_call(text, KNOWN)
    assert tc is not None
    assert tc["name"] == "scan"


def test_parse_direct_name_args():
    text = '{"name": "add", "args": {"a": 5, "b": 6}}'
    tc = _parse_tool_call(text, KNOWN)
    assert tc is not None
    assert tc["name"] == "add"


def test_parse_no_json_returns_none():
    tc = _parse_tool_call("No tools needed. The answer is 42.", KNOWN)
    assert tc is None


def test_parse_unknown_tool_returns_none():
    text = '```json\n{"tool_call": {"name": "unknown_tool", "args": {}}}\n```'
    tc = _parse_tool_call(text, KNOWN)
    assert tc is None


def test_parse_strips_think_tags():
    text = '<think>Let me think...</think>\n```json\n{"tool_call": {"name": "add", "args": {"a": 1, "b": 1}}}\n```'
    tc = _parse_tool_call(text, KNOWN)
    assert tc is not None
    assert tc["name"] == "add"


def test_parse_non_tool_json_ignored():
    text = 'Results: {"routes": ["/api/test"], "count": 3}'
    tc = _parse_tool_call(text, KNOWN)
    assert tc is None


# ── TextToolChatModel ─────────────────────────────────────────────────────

def test_invoke_parses_tool_call():
    inner = _EchoModel('```json\n{"tool_call": {"name": "add", "args": {"a": 2, "b": 3}}}\n```')
    wrapper = TextToolChatModel(inner, TOOLS)
    resp = wrapper.invoke([SystemMessage(content="sys"), HumanMessage(content="go")])
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0]["name"] == "add"
    assert resp.tool_calls[0]["args"] == {"a": 2, "b": 3}


def test_invoke_no_tool_call():
    inner = _EchoModel("All done. No vulnerabilities found.")
    wrapper = TextToolChatModel(inner, TOOLS)
    resp = wrapper.invoke([SystemMessage(content="sys"), HumanMessage(content="go")])
    assert resp.tool_calls == []
    assert "No vulnerabilities" in resp.content


def test_stream_yields_tool_call_at_end():
    text = '```json\n{"tool_call": {"name": "scan", "args": {}}}\n```'
    inner = _EchoModel(text)
    wrapper = TextToolChatModel(inner, TOOLS)
    chunks = list(wrapper.stream([SystemMessage(content="sys"), HumanMessage(content="go")]))
    all_tool_calls = []
    for c in chunks:
        all_tool_calls.extend(getattr(c, "tool_calls", []))
    assert len(all_tool_calls) == 1
    assert all_tool_calls[0]["name"] == "scan"


def test_bind_tools_returns_new_wrapper():
    inner = _EchoModel("x")
    wrapper = TextToolChatModel(inner, [])
    bound = wrapper.bind_tools(TOOLS)
    assert isinstance(bound, TextToolChatModel)
    assert len(bound.tools) == 2


def test_tool_message_converted_to_human():
    inner = _EchoModel("Done.")
    wrapper = TextToolChatModel(inner, TOOLS)
    messages = [
        SystemMessage(content="sys"),
        HumanMessage(content="go"),
        AIMessage(content="calling add", tool_calls=[{"name": "add", "args": {"a": 1, "b": 1}, "id": "c1"}]),
        ToolMessage(content="2", tool_call_id="c1"),
    ]
    resp = wrapper.invoke(messages)
    assert resp.tool_calls == []


# ── is_tool_unsupported_error ─────────────────────────────────────────────

def test_detects_tool_unsupported():
    err = RuntimeError("registry.ollama.ai/library/deepseek-coder-v2:16b does not support tools (status code: 400)")
    assert is_tool_unsupported_error(err) is True


def test_unrelated_error_not_detected():
    err = RuntimeError("connection refused")
    assert is_tool_unsupported_error(err) is False
