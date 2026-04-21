"""DispatcherRunner — end-to-end on a real fixture with a scripted chat model.

Uses the existing `challenge_idor_01` fixture and a hand-crafted chat
model that pretends to be a real LLM choosing tools. The legacy
``--llm rule`` backend drives the sub-agents so the test stays offline.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, List

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from vapt_orchestrator_safe.engine.dispatcher_runner import DispatcherRunner


FIXTURE = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "challenge_idor_01"


class _ScriptedChat:
    def __init__(self, script: Iterable[AIMessage]):
        self.script = iter(script)
        self.sent: List[List[BaseMessage]] = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages, **_kw):
        self.sent.append(list(messages))
        return next(self.script)


def _happy_path_script() -> List[AIMessage]:
    """Scripts the dispatcher through: recon → signature → analyst → exploit(IDOR) → report → done."""
    return [
        AIMessage(content="", tool_calls=[{"id": "r1", "name": "invoke_recon", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "s1", "name": "invoke_signature", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "a1", "name": "invoke_analyst", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "e1", "name": "invoke_exploit", "args": {"attack_family": "IDOR"}}]),
        AIMessage(content="", tool_calls=[{"id": "rp1", "name": "invoke_report", "args": {}}]),
        AIMessage(content="IDOR validated. See report.md.", tool_calls=[]),
    ]


def test_dispatcher_runner_happy_path_on_idor_fixture(tmp_path):
    chat = _ScriptedChat(_happy_path_script())
    runner = DispatcherRunner(
        outputs_root=tmp_path,
        backend="rule",
        chat_model=chat,
        chat_model_backend_spec="scripted",
        max_steps=10,
    )
    summary = runner.run_fixture(FIXTURE)

    assert summary["status"] == "validated"
    assert summary["stop_reason"] == "finished"
    assert summary["pipeline"] == "dispatcher"
    assert len(summary["tool_invocations"]) == 5
    names = [inv["name"] for inv in summary["tool_invocations"]]
    assert names == ["invoke_recon", "invoke_signature", "invoke_analyst", "invoke_exploit", "invoke_report"]
    assert any(f["attack_family"] == "IDOR" for f in summary["validated_findings"])
    assert "IDOR" in summary["final_text"]

    # Report files were actually written to the run dir.
    run_dir = Path(summary["output_dir"])
    assert (run_dir / "report.md").exists()
    assert (run_dir / "report.json").exists()
    assert (run_dir / "memory.json").exists()
    assert (run_dir / "run_summary.json").exists()


def test_dispatcher_runner_pivots_after_wrong_family_attempt(tmp_path):
    """Script: recon → sig → analyst → exploit(SSRF) = fail → pivot → exploit(IDOR) = verified → report."""
    script = [
        AIMessage(content="", tool_calls=[{"id": "r1", "name": "invoke_recon", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "s1", "name": "invoke_signature", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "a1", "name": "invoke_analyst", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "e1", "name": "invoke_exploit",
                                          "args": {"attack_family": "SSRF"}}]),
        AIMessage(content="", tool_calls=[{"id": "p1", "name": "pivot",
                                          "args": {"reason": "SSRF missing from hypotheses"}}]),
        AIMessage(content="", tool_calls=[{"id": "e2", "name": "invoke_exploit",
                                          "args": {"attack_family": "IDOR"}}]),
        AIMessage(content="", tool_calls=[{"id": "rp1", "name": "invoke_report", "args": {}}]),
        AIMessage(content="Confirmed IDOR.", tool_calls=[]),
    ]
    runner = DispatcherRunner(
        outputs_root=tmp_path, backend="rule",
        chat_model=_ScriptedChat(script),
        chat_model_backend_spec="scripted",
        max_steps=15,
    )
    summary = runner.run_fixture(FIXTURE)
    names = [inv["name"] for inv in summary["tool_invocations"]]
    assert "pivot" in names
    # First exploit attempt (SSRF) fails because fixture has no SSRF hypothesis.
    assert summary["tool_invocations"][3]["name"] == "invoke_exploit"
    assert summary["tool_invocations"][3]["ok"] is True  # tool itself ran (returned exit=2)
    assert summary["status"] == "validated"


def test_dispatcher_runner_records_backend_label_and_pipeline(tmp_path):
    chat = _ScriptedChat(_happy_path_script())
    runner = DispatcherRunner(
        outputs_root=tmp_path, backend="rule",
        chat_model=chat,
        chat_model_backend_spec="scripted-xyz",
        max_steps=10,
    )
    summary = runner.run_fixture(FIXTURE)
    assert summary["backend"] == "scripted-xyz"
    assert summary["pipeline"] == "dispatcher"
