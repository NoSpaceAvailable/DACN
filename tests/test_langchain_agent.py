"""LangChainAgent tests — chat model + tool binding via mocks (no API calls)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, List
from unittest.mock import MagicMock

import pytest

from vapt_orchestrator_safe.agents.base import LangChainAgent, LangChainAgentSpec
from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.tools.base import EchoTool


def _bb(tmp_path: Path) -> Blackboard:
    return Blackboard(run_id="t", run_dir=tmp_path)


def _spec(tmp_path, *, chat_model=None, tools=(), system_prompt="System."):
    return LangChainAgentSpec(
        role="recon",  # has prompts/recon.md as fallback if system_prompt is None
        chat_model=chat_model or MagicMock(),
        blackboard=_bb(tmp_path),
        tools=tools,
        system_prompt=system_prompt,
    )


def test_agent_uses_role_from_spec(tmp_path):
    agent = LangChainAgent(_spec(tmp_path))
    assert agent.role == "recon"


def test_agent_loads_system_prompt_from_file_when_none_supplied(tmp_path):
    """If spec.system_prompt is None and role='recon', load prompts/recon.md."""
    spec = LangChainAgentSpec(
        role="recon",
        chat_model=MagicMock(),
        blackboard=_bb(tmp_path),
        tools=(),
        system_prompt=None,  # force file load
    )
    agent = LangChainAgent(spec)
    text = agent.system_prompt
    assert "Recon agent" in text  # prompts/recon.md headline


def test_agent_extra_system_appended(tmp_path):
    spec = LangChainAgentSpec(
        role="recon",
        chat_model=MagicMock(),
        blackboard=_bb(tmp_path),
        system_prompt="Base.",
        extra_system="Override-me.",
    )
    agent = LangChainAgent(spec)
    assert agent.system_prompt.endswith("Override-me.")
    assert "Base." in agent.system_prompt


def test_agent_binds_tools_when_chat_model_supports_it(tmp_path):
    chat = MagicMock()
    chat.bind_tools.return_value = MagicMock(name="bound_chat")
    tool = EchoTool()
    agent = LangChainAgent(_spec(tmp_path, chat_model=chat, tools=[tool]))
    chat.bind_tools.assert_called_once_with([tool])
    assert agent.chat_model is chat.bind_tools.return_value


def test_agent_skips_bind_tools_when_no_tools(tmp_path):
    chat = MagicMock()
    chat.bind_tools = MagicMock()
    agent = LangChainAgent(_spec(tmp_path, chat_model=chat, tools=[]))
    chat.bind_tools.assert_not_called()
    assert agent.chat_model is chat


def test_agent_skips_bind_tools_when_chat_model_does_not_support(tmp_path):
    """Plain models without bind_tools must still work — agent just won't call tools."""
    class _Plain:
        def invoke(self, *_a, **_k):
            return "plain"
    plain = _Plain()
    tool = EchoTool()
    agent = LangChainAgent(_spec(tmp_path, chat_model=plain, tools=[tool]))
    assert agent.chat_model is plain  # unchanged


def test_agent_injects_blackboard_into_tools(tmp_path):
    bb = _bb(tmp_path)
    tool = EchoTool()
    spec = LangChainAgentSpec(
        role="recon", chat_model=MagicMock(), blackboard=bb, tools=[tool],
        system_prompt="x",
    )
    LangChainAgent(spec)
    # Use the tool to verify the binding happened
    tool.invoke({"text": "hello", "times": 1})
    assert len(bb.artifacts) == 1


def test_invoke_model_calls_with_system_and_human_messages(tmp_path):
    chat = MagicMock()
    fake_response = MagicMock()
    fake_response.content = "answer"
    chat.invoke.return_value = fake_response
    agent = LangChainAgent(_spec(tmp_path, chat_model=chat, system_prompt="SYS"))
    result = agent.invoke_model("hello there")
    assert result is fake_response

    # Inspect message structure
    sent = chat.invoke.call_args.args[0]
    assert len(sent) == 2
    from langchain_core.messages import HumanMessage, SystemMessage
    assert isinstance(sent[0], SystemMessage) and sent[0].content == "SYS"
    assert isinstance(sent[1], HumanMessage) and sent[1].content == "hello there"


def test_invoke_model_logs_begin_and_end_events(tmp_path):
    bb = _bb(tmp_path)
    chat = MagicMock()
    fake_response = MagicMock()
    fake_response.content = "answer"
    chat.invoke.return_value = fake_response
    spec = LangChainAgentSpec(
        role="recon", chat_model=chat, blackboard=bb,
        system_prompt="x",
    )
    LangChainAgent(spec).invoke_model("hello")
    messages = [e["message"] for e in bb.events]
    assert "invoke_model.begin" in messages
    assert "invoke_model.end" in messages
