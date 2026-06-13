"""Text-based tool-calling wrapper for models without native tool support.

When an Ollama model does not support the ``tools`` API (returns HTTP 400),
the Dispatcher auto-switches to this wrapper.  It injects tool descriptions
into the system prompt as plain text, instructs the model to emit a JSON
block when it wants to call a tool, and parses that block back into
LangChain ``AIMessage.tool_calls`` so the rest of the pipeline works
unchanged.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Iterator, List, Optional, Sequence

from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from vapt_orchestrator_safe.utils.llm_json import extract_json

logger = logging.getLogger(__name__)

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*.*?```", re.DOTALL)


# ── Prompt builder ────────────────────────────────────────────────────────

def _tool_schema_text(tool: Any) -> str:
    schema: dict = {}
    if hasattr(tool, "args_schema") and tool.args_schema is not None:
        try:
            schema = tool.args_schema.model_json_schema()
        except Exception:
            try:
                schema = tool.args_schema.schema()
            except Exception:
                pass

    props = schema.get("properties", {})
    required = set(schema.get("required", []))

    arg_lines: list[str] = []
    for k, v in props.items():
        desc = v.get("description", v.get("type", "any"))
        opt = "" if k in required else " (optional)"
        arg_lines.append(f"    - {k}{opt}: {desc}")

    if arg_lines:
        return (
            f"  **{tool.name}**: {tool.description}\n"
            f"    Arguments:\n" + "\n".join(arg_lines)
        )
    return f"  **{tool.name}**: {tool.description}  (no arguments)"


def _build_tool_prompt(tools: Sequence[Any]) -> str:
    lines = ["", "# Available Tools", ""]
    for tool in tools:
        lines.append(_tool_schema_text(tool))
        lines.append("")

    lines.extend([
        "# How to Call a Tool",
        "",
        "To call a tool, output a JSON block inside a ```json fence:",
        "",
        "```json",
        '{"tool_call": {"name": "tool_name_here", "args": {"arg1": "value1"}}}',
        "```",
        "",
        "Rules:",
        "- Call exactly ONE tool per response.",
        "- After you receive the tool result you may call another tool.",
        "- When DONE, respond in plain text with NO JSON block.",
        '- If a tool needs no arguments use empty args: {"args": {}}',
    ])
    return "\n".join(lines)


# ── Message transformer ──────────────────────────────────────────────────

def _transform_messages(
    messages: List[BaseMessage],
    tool_prompt: str,
) -> List[BaseMessage]:
    """Rewrite history so a non-tool-calling model can follow the conversation."""
    out: List[BaseMessage] = []
    system_patched = False

    for msg in messages:
        if isinstance(msg, SystemMessage) and not system_patched:
            out.append(SystemMessage(content=msg.content + "\n" + tool_prompt))
            system_patched = True

        elif isinstance(msg, ToolMessage):
            out.append(HumanMessage(
                content=f"[Tool Result for {msg.tool_call_id}]:\n{msg.content}",
            ))

        elif isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            content = msg.content or ""
            content = _JSON_FENCE_RE.sub("", content).strip()
            tc_desc = ", ".join(
                f'{c.get("name", "?")}({json.dumps(c.get("args", {}), ensure_ascii=False)})'
                for c in msg.tool_calls
            )
            suffix = f"[I called: {tc_desc}]"
            content = f"{content}\n\n{suffix}" if content else suffix
            out.append(AIMessage(content=content, tool_calls=[]))

        else:
            out.append(msg)

    if not system_patched:
        out.insert(0, SystemMessage(content=tool_prompt))

    return out


# ── Response parser ───────────────────────────────────────────────────────

def _parse_tool_call(
    text: str,
    known_names: set[str],
) -> Optional[Dict[str, Any]]:
    """Extract a single tool-call dict from free-form LLM text, or *None*."""
    clean = _THINK_RE.sub("", text).strip()
    data = extract_json(clean)
    if data is None or not isinstance(data, dict):
        return None

    tc: Optional[dict] = None

    if "tool_call" in data and isinstance(data["tool_call"], dict):
        tc = data["tool_call"]
    elif "tool_calls" in data and isinstance(data["tool_calls"], list):
        tc = data["tool_calls"][0] if data["tool_calls"] else None
    elif "name" in data and ("args" in data or "arguments" in data):
        tc = data

    if tc and isinstance(tc.get("name"), str) and tc["name"] in known_names:
        args = tc.get("args") or tc.get("arguments") or {}
        return {
            "name": tc["name"],
            "args": args,
            "id": f"text_{tc['name']}",
        }
    return None


# ── Wrapper class ─────────────────────────────────────────────────────────

class TextToolChatModel:
    """Drop-in wrapper that emulates tool-calling via text prompting.

    The Dispatcher only calls ``.invoke()`` / ``.stream()`` and reads
    ``.tool_calls`` from the response — this class provides all three.
    """

    def __init__(self, inner: Any, tools: Sequence[Any]):
        self.inner = inner
        self.tools = list(tools)
        self._tool_prompt = _build_tool_prompt(tools) if tools else ""
        self._tool_names: set[str] = {t.name for t in tools}

    def bind_tools(self, tools: Sequence[Any]) -> "TextToolChatModel":
        return TextToolChatModel(self.inner, tools)

    # ── non-streaming ─────────────────────────────────────────────────
    def invoke(self, messages: List[BaseMessage], **kwargs: Any) -> AIMessage:
        transformed = _transform_messages(messages, self._tool_prompt)
        response = self.inner.invoke(transformed, **kwargs)

        content: str = getattr(response, "content", "") or ""
        tool_call = _parse_tool_call(content, self._tool_names)

        if tool_call is not None:
            return AIMessage(content=content, tool_calls=[tool_call])
        return AIMessage(content=content, tool_calls=[])

    # ── streaming (preserves watchdog real-time checking) ─────────────
    def stream(
        self, messages: List[BaseMessage], **kwargs: Any,
    ) -> Iterator[AIMessageChunk]:
        transformed = _transform_messages(messages, self._tool_prompt)
        accumulated = ""

        for chunk in self.inner.stream(transformed, **kwargs):
            text = getattr(chunk, "content", "") or ""
            if isinstance(text, list):
                text = "".join(
                    p.get("text", "") if isinstance(p, dict) else str(p)
                    for p in text
                )
            accumulated += text
            yield chunk

        tool_call = _parse_tool_call(accumulated, self._tool_names)
        if tool_call is not None:
            yield AIMessageChunk(content="", tool_calls=[tool_call])


# ── Error detection helper ────────────────────────────────────────────────

def is_tool_unsupported_error(exc: Exception) -> bool:
    """True when the exception signals native tool-calling is unusable.

    Covers two cases:
    - Ollama models that reject the ``tools`` API ("does not support tools").
    - Gemini via its OpenAI-compatible endpoint, which 400s on multi-turn tool
      use because the compat layer drops the required ``thought_signature``
      field. Switching to text-based tool calling sidesteps both.
    """
    msg = str(exc).lower()
    return (
        "does not support tools" in msg
        or "thought_signature" in msg
        or "thought signature" in msg
    )
