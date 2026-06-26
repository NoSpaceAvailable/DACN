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
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


def _trace_on() -> bool:
    return os.environ.get("DACN_TRACE", "").lower() in {"1", "true", "yes", "on"}


def _trace(msg: str) -> None:
    if _trace_on():
        print(msg, flush=True)


def _short(v: Any, n: int = 300) -> str:
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
    return s if len(s) <= n else s[:n] + f"… (+{len(s) - n} chars)"

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

logger = logging.getLogger(__name__)


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
        require_report: bool = False,
        max_completion_nudges: int = 2,
        call_delay_s: float = 0.0,
        require_source_read: bool = False,
        rate_limit_retries: int = 4,
        rate_limit_backoff_s: float = 30.0,
        history_compaction: bool = True,
        keep_recent_tool_msgs: int = 3,
        compact_over_chars: int = 800,
    ):
        self._raw_chat_model = chat_model
        self._tools_list = list(tools)
        self._text_tool_fallback = False
        self.chat_model = self._maybe_bind(chat_model, tools)
        self.tools_by_name: Dict[str, BaseTool] = {t.name: t for t in tools}
        self.blackboard = blackboard
        self.system_prompt = system_prompt
        self.max_steps = max_steps
        self.hook = hook
        self.watchdogs: List[Watchdog] = list(watchdogs or [])
        self._pending_correction: Optional[str] = None
        self.watchdog_trips: List[Dict[str, Any]] = []
        self.require_report = require_report
        self.max_completion_nudges = max_completion_nudges
        self._completion_nudges = 0
        self.call_delay_s = call_delay_s
        self.require_source_read = require_source_read
        self.rate_limit_retries = rate_limit_retries
        self.rate_limit_backoff_s = rate_limit_backoff_s
        self.history_compaction = history_compaction
        self.keep_recent_tool_msgs = keep_recent_tool_msgs
        self.compact_over_chars = compact_over_chars

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
            # Shrink stale tool outputs so each request stays lean (they would
            # otherwise be resent in full on every step).
            self._compact_history(messages)
            # Pace LLM calls to stay under free-tier rate limits (RPM). The
            # sub-agents are rule-based and make no API calls, so the
            # dispatcher's per-step call is the only thing to throttle.
            if self.call_delay_s and step > 1:
                time.sleep(self.call_delay_s)
            response, intervened = self._call_llm(messages)
            if not isinstance(response, AIMessage):
                response = AIMessage(
                    content=getattr(response, "content", str(response)),
                    tool_calls=getattr(response, "tool_calls", []) or [],
                )
            messages.append(response)

            if _trace_on():
                _trace(f"\n=== step {step} ===")
                if response.content:
                    _trace(f"[think] {_short(response.content, 800)}")
                planned = getattr(response, "tool_calls", None) or []
                if planned:
                    _trace(f"[plan]  {len(planned)} tool call(s): "
                           + ", ".join(c.get('name', '?') for c in planned))

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
                rescued = self._try_rescue_tool_call(response, step)
                if rescued is not None:
                    tool_calls = [rescued]
                    response = AIMessage(
                        content=response.content or "",
                        tool_calls=tool_calls,
                    )
                    messages[-1] = response
                elif (nudge := self._completion_nudge(invocations)) is not None:
                    # Completion guard: don't accept a premature finish. Nudge the
                    # model back to read the source / produce a report, a bounded
                    # number of times. Robust to weak prompt adherence.
                    self._completion_nudges += 1
                    self.blackboard.log_event(
                        "dispatcher", f"step.{step}.completion_nudge",
                        {"nudge": self._completion_nudges},
                    )
                    self._pending_correction = nudge
                    continue
                else:
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
                _trace(f"[call]  {name}({_short(args, 200)})")
                _trace(f"[out]   {_short(payload, 400)}")

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


    def _completion_nudge(self, invocations: Sequence[Dict[str, Any]]) -> Optional[str]:
        """Return a corrective nudge if the model tries to finish prematurely, or
        None to allow the finish. Bounded by ``max_completion_nudges``.

        Two guards: (1) if source analysis is required but the model never read
        the source, push it to analyse the code; (2) if a report is required but
        never produced, push it to finish the pipeline."""
        if self._completion_nudges >= self.max_completion_nudges:
            return None
        names = {inv.get("name") for inv in invocations}
        if self.require_source_read and "read_source" not in names:
            return (
                "You are about to finish without reading the target source code. "
                "Source analysis is your PRIMARY job: call read_source (no args to "
                "list files, then path=<file> to read each one), reason about the "
                "code, and call record_finding for every vulnerability you find — of "
                "ANY class. Do this before finishing."
            )
        if self.require_report and "invoke_report" not in names:
            return (
                "You stopped before completing the engagement, and you have NOT "
                "called invoke_report yet — so there is no final report. Do not give "
                "a final answer now. Record any remaining findings, then call "
                "invoke_report to finish."
            )
        return None

    # ── adaptive rescue ──────────────────────────────────────────────────
    def _try_rescue_tool_call(
        self, response: AIMessage, step: int,
    ) -> Optional[Dict[str, Any]]:
        """If the model put a tool call in *content* instead of *tool_calls*,
        parse it out and switch to ``TextToolChatModel`` for subsequent steps.
        Returns the parsed tool-call dict, or ``None``."""
        if self._text_tool_fallback:
            return None
        content = response.content or ""
        if not content.strip():
            return None

        from vapt_orchestrator_safe.llm.text_tool_wrapper import (
            TextToolChatModel,
            _parse_tool_call,
        )

        parsed = _parse_tool_call(content, set(self.tools_by_name))
        if parsed is None:
            return None

        logger.warning(
            "Native tool_calls empty but content contains a tool call; "
            "switching to text-based fallback (adaptive)."
        )
        self.blackboard.log_event(
            "dispatcher", "text_tool_fallback_adaptive",
            {"step": step, "rescued_tool": parsed["name"]},
        )
        self.chat_model = TextToolChatModel(
            self._raw_chat_model, self._tools_list,
        )
        self._text_tool_fallback = True
        return parsed

    def _compact_history(self, messages: List[BaseMessage]) -> None:
        """Shrink stale tool outputs in place to keep each request lean.

        Every step resends the whole conversation, so large tool results (source
        dumps, scan output) otherwise get re-sent N times. We keep the most
        recent ``keep_recent_tool_msgs`` tool results full (the model is actively
        using them) and replace older oversized ones with a short stub. The full
        output still lives on the Blackboard artifacts."""
        if not self.history_compaction:
            return
        tool_idxs = [i for i, m in enumerate(messages) if isinstance(m, ToolMessage)]
        stale = tool_idxs[:-self.keep_recent_tool_msgs] if self.keep_recent_tool_msgs else tool_idxs
        for i in stale:
            m = messages[i]
            content = m.content if isinstance(m.content, str) else str(m.content)
            if len(content) > self.compact_over_chars and not content.startswith("[omitted"):
                messages[i] = ToolMessage(
                    content=f"[omitted {len(content)} chars of earlier tool output to save context]",
                    tool_call_id=getattr(m, "tool_call_id", "compacted"),
                )

    @staticmethod
    def _is_rate_limit(exc: Exception) -> bool:
        s = str(exc).lower()
        return "429" in s or "rate limit" in s or "rate_limited" in s or "quota" in s

    # ── LLM invocation with optional streaming + watchdogs ──────────────
    def _call_llm(self, messages: List[BaseMessage]) -> Tuple[AIMessage, bool]:
        """Invoke the chat model. When watchdogs are configured, stream the
        response and run each watchdog after every chunk. On trip, log the
        event, queue a correction for the next turn, and return (partial,
        intervened=True). Otherwise return (full_response, False).

        Survives transient rate-limit (429) errors by backing off and retrying
        the same call, so a free-tier-throttled run completes (slowly) instead
        of dying mid-pipeline."""
        rl_attempts = 0
        while True:
            try:
                return self._call_llm_inner(messages)
            except Exception as exc:
                if not self._text_tool_fallback:
                    from vapt_orchestrator_safe.llm.text_tool_wrapper import (
                        TextToolChatModel,
                        is_tool_unsupported_error,
                    )
                    if is_tool_unsupported_error(exc):
                        logger.warning(
                            "Model does not support native tool-calling; "
                            "switching to text-based fallback."
                        )
                        self.blackboard.log_event(
                            "dispatcher", "text_tool_fallback",
                            {"reason": str(exc)},
                        )
                        self.chat_model = TextToolChatModel(
                            self._raw_chat_model, self._tools_list,
                        )
                        self._text_tool_fallback = True
                        continue
                if self._is_rate_limit(exc) and rl_attempts < self.rate_limit_retries:
                    wait = self.rate_limit_backoff_s * (2 ** rl_attempts)
                    # Adaptive throttling: each rate-limit hit ratchets up the
                    # per-call delay floor so we don't immediately burst again
                    # on the next step. Capped at 10s — free-tier mistral is
                    # 1 RPS, so a 3-second floor is enough to never hit it
                    # again, but we step gradually to avoid over-correcting.
                    old_delay = self.call_delay_s
                    self.call_delay_s = min(10.0, max(self.call_delay_s + 1.5, 3.0))
                    self.blackboard.log_event(
                        "dispatcher", "rate_limit_backoff",
                        {"attempt": rl_attempts + 1, "wait_s": wait,
                         "call_delay_s_before": old_delay,
                         "call_delay_s_after": self.call_delay_s},
                    )
                    # Trace-mode users mistake the logger warning for a new
                    # step. Emit through _trace with an explicit [retry] label
                    # so it visibly sits BETWEEN steps and doesn't bump the
                    # step counter (the retry loops inside _call_llm; the
                    # outer step counter is untouched).
                    _trace(f"[retry] rate-limited; sleeping {wait:.0f}s "
                           f"(attempt {rl_attempts + 1}/{self.rate_limit_retries}, "
                           f"NOT a new step) — bumping call_delay {old_delay:.1f}→"
                           f"{self.call_delay_s:.1f}s")
                    if not _trace_on():
                        logger.warning("Rate limited; backing off %.0fs (retry %d/%d), "
                                       "call_delay→%.1fs",
                                       wait, rl_attempts + 1, self.rate_limit_retries,
                                       self.call_delay_s)
                    time.sleep(wait)
                    rl_attempts += 1
                    continue
                raise

    def _call_llm_inner(self, messages: List[BaseMessage]) -> Tuple[AIMessage, bool]:
        if not self.watchdogs or not hasattr(self.chat_model, "stream"):
            return self.chat_model.invoke(messages), False

        buffer_text = ""
        last_chunk: Any = None
        for chunk in self.chat_model.stream(messages):
            last_chunk = chunk if last_chunk is None else (last_chunk + chunk)
            text_part = getattr(chunk, "content", "") or ""
            if isinstance(text_part, list):
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
