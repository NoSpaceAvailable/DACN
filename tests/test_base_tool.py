"""BaseTool tests — covering the contract subclasses must follow."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Type

import pytest
from pydantic import BaseModel as PydanticModel

from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.tools.base import (
    BaseTool,
    EchoTool,
    ToolError,
    ToolResult,
    _loop_sig,
)


def _bb(tmp_path: Path) -> Blackboard:
    return Blackboard(run_id="t", run_dir=tmp_path)


# ── ToolResult ─────────────────────────────────────────────────────────────
def test_tool_result_ok_property():
    assert ToolResult(exit_code=0).ok is True
    assert ToolResult(exit_code=1).ok is False


def test_tool_result_summary_includes_exit_and_duration():
    r = ToolResult(stdout="hello", exit_code=0, duration_ms=42)
    s = r.summary_for_llm()
    assert "exit=0" in s
    assert "t=42ms" in s
    assert "hello" in s


def test_tool_result_summary_does_not_truncate():
    """ponytail: summary_for_llm sends full body — agent decides what to read."""
    r = ToolResult(stdout="Z" * 5000, exit_code=0, duration_ms=1)
    s = r.summary_for_llm(limit=100)
    assert "(truncated)" not in s
    assert s.count("Z") == 5000


def test_tool_result_failure_summary_uses_stderr():
    r = ToolResult(stdout="ignored", stderr="boom", exit_code=1, duration_ms=1)
    s = r.summary_for_llm()
    assert "boom" in s
    assert "ignored" not in s


# ── EchoTool happy path ────────────────────────────────────────────────────
def test_echo_tool_runs_and_writes_artifact(tmp_path):
    bb = _bb(tmp_path)
    tool = EchoTool().bind_blackboard(bb)
    out = tool.invoke({"text": "hi", "times": 2})
    assert "hi\nhi\n" in out
    assert "exit=0" in out
    # Artifact recorded
    assert len(bb.artifacts) == 1
    art = bb.artifacts[0]
    assert art["kind"] == "tool:echo"
    assert art["payload"]["result"]["stdout"].count("hi") == 2
    # Loop signature pushed
    assert len(bb.loop_signatures) == 1


def test_echo_tool_error_path_returns_nonzero(tmp_path):
    bb = _bb(tmp_path)
    tool = EchoTool().bind_blackboard(bb)
    out = tool.invoke({"text": "hi", "times": -3})
    assert "exit=2" in out
    assert "must be >= 0" in out


def test_tool_works_without_blackboard():
    # When unbound, _record is a no-op; tool must still return a string.
    tool = EchoTool()
    assert "hi\n" in tool.invoke({"text": "hi", "times": 1})


def test_loop_signature_is_stable_for_same_kwargs():
    s1 = _loop_sig("echo", {"text": "hi", "times": 1})
    s2 = _loop_sig("echo", {"times": 1, "text": "hi"})  # different dict order
    assert s1 == s2


def test_loop_signature_changes_with_payload():
    assert _loop_sig("echo", {"text": "a"}) != _loop_sig("echo", {"text": "b"})


# ── exception inside _invoke is captured into ToolResult, not raised ───────
class _BoomArgs(PydanticModel):
    pass


class BoomTool(BaseTool):
    name: str = "boom"
    description: str = "raises on every call"
    args_schema: Type[PydanticModel] = _BoomArgs

    def _invoke(self, **kwargs: Any) -> ToolResult:
        raise RuntimeError("kaboom")


def test_invoke_exception_becomes_tool_result(tmp_path):
    bb = _bb(tmp_path)
    tool = BoomTool().bind_blackboard(bb)
    out = tool.invoke({})
    assert "exit=-1" in out
    assert "RuntimeError" in out and "kaboom" in out
    # Artifact still recorded so the run report can show the failure.
    assert bb.artifacts[0]["payload"]["result"]["exit_code"] == -1


# ── subclass MUST return ToolResult ────────────────────────────────────────
class _BadArgs(PydanticModel):
    pass


class BadReturnTool(BaseTool):
    name: str = "bad"
    description: str = "returns the wrong type"
    args_schema: Type[PydanticModel] = _BadArgs

    def _invoke(self, **kwargs: Any) -> ToolResult:
        return "not a tool result"  # type: ignore[return-value]


def test_subclass_returning_wrong_type_raises_tool_error():
    with pytest.raises(ToolError, match="must return ToolResult"):
        BadReturnTool().invoke({})


# ── auto-truncation flag flips when output > truncate_at ───────────────────
class _BigArgs(PydanticModel):
    pass


class BigOutputTool(BaseTool):
    name: str = "big"
    description: str = "produces a large stdout"
    args_schema: Type[PydanticModel] = _BigArgs
    truncate_at: int = 100  # tiny limit for the test

    def _invoke(self, **kwargs: Any) -> ToolResult:
        return ToolResult(stdout="A" * 500)


def test_truncated_flag_set_when_output_exceeds_limit(tmp_path):
    """The size-threshold flag still tracks for telemetry; full output now
    reaches both the LLM (no trimming) and the artifact store."""
    bb = _bb(tmp_path)
    out = BigOutputTool().bind_blackboard(bb).invoke({})
    # LLM-facing payload is full — no TRUNCATED marker, full 500-char body.
    assert "TRUNCATED" not in out
    assert out.count("A") == 500
    # Artifact still has the full payload AND tracks the size-threshold flag.
    art = bb.artifacts[0]["payload"]["result"]
    assert len(art["stdout"]) == 500
    assert art["truncated"] is True
