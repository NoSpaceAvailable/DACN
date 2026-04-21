"""Dispatcher — LLM-driven supervisor (Claude-CLI style).

The Dispatcher is a thin tool-use loop around a LangChain
``BaseChatModel`` that has been ``bind_tools``-ed with a set of
:class:`~vapt_orchestrator_safe.tools.base.BaseTool` instances. Each
iteration:

1. Call ``chat_model.invoke(messages)``.
2. If the response has tool calls → execute every tool call, append a
   ``ToolMessage`` with the serialised result for each one, loop.
3. If the response has no tool calls → treat ``.content`` as the final
   answer and return.

The supervisor tools typically wrap sub-agents (``invoke_recon``,
``invoke_analyst`` …), RAG / KG queries (Sprint 5), and a ``pivot`` hook
(Sprint 6). The dispatcher itself is agnostic to what the tools do; it
only knows how to route calls.

Streaming hook for Sprint 6 (C1 mid-thinking intervention): the loop
accepts an optional :class:`DispatcherHook` with ``before_step`` /
``after_step`` callbacks. Sprint 6 will add an ``on_stream_chunk``
variant that uses ``chat_model.stream(...)`` and lets the hook cancel
mid-generation. Keeping the seam here so we don't have to refactor
later.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from vapt_orchestrator_safe.engine.watchdogs import Watchdog, WatchdogVerdict
from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.tools.base import BaseTool


_DEFAULT_MAX_STEPS = 20


@dataclass
class DispatcherResult:
    final_text: Optional[str]
    steps: int
    stop_reason: str                        # "finished" | "max_steps" | "pivot" | "hook_abort"
    messages: List[BaseMessage] = field(default_factory=list)
    tool_invocations: List[Dict[str, Any]] = field(default_factory=list)


class DispatcherHook:
    """Optional callbacks the dispatcher fires around each step.

    - ``before_step(step, messages)`` — called just before the LLM is
      invoked for step ``step``. Receives the **live** ``messages`` list
      (not a copy) so the hook can append a guidance message that will
      reach the LLM on this same turn. Sprint 5's :class:`AntiLoopHook`
      uses this to inject pivot nudges.
    - ``after_step(step, response, tool_invocations)`` — called after
      the response for step ``step`` has been handled (tool calls
      executed, replies appended). Sprint 6 (C1) will add an
      ``on_stream_chunk`` variant that fires mid-generation.

    Returning ``False`` from any callback short-circuits the loop with
    ``stop_reason="hook_abort"``.
    """

    def before_step(self, step: int, messages: List[BaseMessage]) -> bool:       # noqa: D401
        return True

    def after_step(                                                              # noqa: D401
        self,
        step: int,
        response: AIMessage,
        tool_invocations: Sequence[Dict[str, Any]],
    ) -> bool:
        return True


class Dispatcher:
    """Supervisor loop over a LangChain chat model with bound tools.

    The constructor does NOT call ``bind_tools`` itself; the caller is
    expected to pass a model that already has the tools bound (or the
    dispatcher falls back to plain invocation, which means the LLM has
    no way to request tool calls — useful for tests).
    """

    def __init__(
        self,
        chat_model: Any,
        tools: Sequence[BaseTool],
        blackboard: Blackboard,
        *,
        system_prompt: str,
        max_steps: int = _DEFAULT_MAX_STEPS,
        hook: Optional[DispatcherHook] = None,
        watchdogs: Optional[Sequence[Watchdog]] = None,
    ):
        self.chat_model = self._maybe_bind(chat_model, tools)
        self.tools_by_name: Dict[str, BaseTool] = {t.name: t for t in tools}
        self.blackboard = blackboard
        self.system_prompt = system_prompt
        self.max_steps = max_steps
        self.hook = hook
        self.watchdogs: List[Watchdog] = list(watchdogs or [])
        # When a watchdog trips, the correction is queued here and injected
        # into the NEXT turn's messages (like AntiLoopHook).
        self._pending_correction: Optional[str] = None
        self.watchdog_trips: List[Dict[str, Any]] = []

        # Inject blackboard once, so tools can append to artifacts / loop sigs.
        for tool in tools:
            if hasattr(tool, "bind_blackboard"):
                tool.bind_blackboard(blackboard)

    # ── construction helpers ─────────────────────────────────────────────
    @staticmethod
    def _maybe_bind(chat_model: Any, tools: Sequence[BaseTool]) -> Any:
        if not tools:
            return chat_model
        bind = getattr(chat_model, "bind_tools", None)
        if bind is None:
            return chat_model
        return bind(list(tools))

    # ── public API ───────────────────────────────────────────────────────
    def run(self, user_goal: str) -> DispatcherResult:
        messages: List[BaseMessage] = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=user_goal),
        ]
        invocations: List[Dict[str, Any]] = []

        for step in range(1, self.max_steps + 1):
            # Inject any watchdog correction queued from the previous step.
            if self._pending_correction is not None:
                messages.append(HumanMessage(content=self._pending_correction))
                self._pending_correction = None

            if self.hook and not self.hook.before_step(step, messages):
                return DispatcherResult(
                    final_text=None,
                    steps=step - 1,
                    stop_reason="hook_abort",
                    messages=messages,
                    tool_invocations=invocations,
                )

            self.blackboard.log_event(
                "dispatcher",
                f"step.{step}.invoke",
                {"message_count": len(messages)},
            )
            response, intervened = self._call_llm(messages)
            if not isinstance(response, AIMessage):
                response = AIMessage(
                    content=getattr(response, "content", str(response)),
                    tool_calls=getattr(response, "tool_calls", []) or [],
                )
            messages.append(response)

            # Watchdog intervention: skip normal tool-call / termination logic
            # and head straight to the next step, which will see the injected
            # correction message.
            if intervened:
                self.blackboard.log_event(
                    "dispatcher", f"step.{step}.intervened", {},
                )
                continue

            tool_calls = getattr(response, "tool_calls", None) or []
            if not tool_calls:
                self.blackboard.log_event(
                    "dispatcher",
                    f"step.{step}.finished",
                    {"final_chars": len(response.content or "")},
                )
                if self.hook and not self.hook.after_step(step, response, []):
                    return DispatcherResult(
                        final_text=None, steps=step,
                        stop_reason="hook_abort",
                        messages=messages, tool_invocations=invocations,
                    )
                return DispatcherResult(
                    final_text=response.content,
                    steps=step,
                    stop_reason="finished",
                    messages=messages,
                    tool_invocations=invocations,
                )

            step_invocations: List[Dict[str, Any]] = []
            for call in tool_calls:
                name = call.get("name")
                args = call.get("args") or {}
                call_id = call.get("id") or f"call_{step}_{len(step_invocations)}"

                tool = self.tools_by_name.get(name)
                if tool is None:
                    payload = f"[dispatcher] Unknown tool {name!r}. Available: {sorted(self.tools_by_name)}"
                    messages.append(ToolMessage(content=payload, tool_call_id=call_id))
                    step_invocations.append({"name": name, "args": args, "ok": False, "error": "unknown_tool"})
                    continue

                try:
                    output = tool.invoke(args)
                except Exception as exc:                    # pragma: no cover — defensive
                    payload = f"[dispatcher] Tool {name!r} crashed: {type(exc).__name__}: {exc}"
                    messages.append(ToolMessage(content=payload, tool_call_id=call_id))
                    step_invocations.append({"name": name, "args": args, "ok": False, "error": str(exc)})
                    continue

                payload = output if isinstance(output, str) else _to_json(output)
                messages.append(ToolMessage(content=payload, tool_call_id=call_id))
                step_invocations.append({"name": name, "args": args, "ok": True})

                # ``pivot`` is a sentinel tool — returning control to the dispatcher.
                if name == "pivot":
                    self.blackboard.log_event("dispatcher", f"step.{step}.pivot", {"args": args})
                    # Still continue the loop; the LLM will pick a new branch next turn.

            invocations.extend(step_invocations)
            if self.hook and not self.hook.after_step(step, response, step_invocations):
                return DispatcherResult(
                    final_text=None,
                    steps=step,
                    stop_reason="hook_abort",
                    messages=messages,
                    tool_invocations=invocations,
                )

        self.blackboard.log_event(
            "dispatcher",
            "max_steps",
            {"max_steps": self.max_steps},
        )
        return DispatcherResult(
            final_text=None,
            steps=self.max_steps,
            stop_reason="max_steps",
            messages=messages,
            tool_invocations=invocations,
        )


    # ── LLM invocation with optional streaming + watchdogs ──────────────
    def _call_llm(self, messages: List[BaseMessage]) -> Tuple[AIMessage, bool]:
        """Invoke the chat model. When watchdogs are configured, stream the
        response and run each watchdog after every chunk. On trip, log the
        event, queue a correction for the next turn, and return (partial,
        intervened=True). Otherwise return (full_response, False)."""
        if not self.watchdogs or not hasattr(self.chat_model, "stream"):
            return self.chat_model.invoke(messages), False

        buffer_text = ""
        last_chunk: Any = None
        for chunk in self.chat_model.stream(messages):
            last_chunk = chunk if last_chunk is None else (last_chunk + chunk)
            text_part = getattr(chunk, "content", "") or ""
            if isinstance(text_part, list):                 # content can be a list of parts
                text_part = "".join(
                    p.get("text", "") if isinstance(p, dict) else str(p) for p in text_part
                )
            buffer_text += text_part

            for watchdog in self.watchdogs:
                verdict = watchdog.check(buffer_text)
                if not verdict.tripped:
                    continue
                self.blackboard.log_event(
                    "watchdog", verdict.name,
                    {"reason": verdict.reason, "buffer_chars": len(buffer_text)},
                )
                self.watchdog_trips.append({
                    "name": verdict.name,
                    "reason": verdict.reason,
                    "buffer_chars": len(buffer_text),
                })
                self._pending_correction = verdict.correction_for_next_turn
                partial = AIMessage(
                    content=f"[intervened:{verdict.name}] {buffer_text}",
                    tool_calls=[],
                )
                return partial, True

        # Stream finished without intervention. Convert the accumulated chunk
        # into a plain AIMessage so downstream typing stays consistent.
        if last_chunk is None:
            return AIMessage(content="", tool_calls=[]), False
        return AIMessage(
            content=getattr(last_chunk, "content", "") or "",
            tool_calls=getattr(last_chunk, "tool_calls", None) or [],
        ), False


def _to_json(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except Exception:                                       # pragma: no cover
        return repr(value)
