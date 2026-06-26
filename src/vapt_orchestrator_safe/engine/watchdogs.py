"""C1 — Mid-thinking watchdogs (DACN headline novel contribution).

PentestGPT / Red-MIRROR / MAPTA all wait for the LLM to emit EOS before
reacting. That means a 1500-token chain of thought that's clearly
drifting / out-of-scope / about to loop burns the whole budget before
the orchestrator gets to react.

DACN runs the Dispatcher's LLM in **streaming** mode and inspects the
accumulating buffer after each chunk. Three watchdogs ship today:

- :class:`DriftWatchdog` — the model emitted ``max_drift_tokens`` worth
  of reasoning without mentioning any of the expected focus keywords
  (the intake manifest id, the target host, the active attack family).
  Intervention injects "re-focus on X" into the next turn.
- :class:`ScopeWatchdog` — the model is proposing a URL / host that
  isn't in the fixture's declared scope. Intervention injects "stay on
  the declared target".
- :class:`LoopWatchdog` — the model is about to emit a tool call whose
  signature has already hit the anti-loop threshold in the Blackboard.
  Intervention injects "call ``pivot`` next, DON'T repeat".

Each watchdog is pure-python, zero-dependency, and fires after every
chunk — so the whole cost of being wrong is cancelled once the first
offending chunk arrives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence

from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.utils.scope import ScopeError, ScopeGuard


@dataclass(frozen=True)
class WatchdogVerdict:
    tripped: bool
    name: str = ""
    reason: str = ""
    correction_for_next_turn: str = ""


_OK = WatchdogVerdict(tripped=False)


class Watchdog:
    """Subclasses override :meth:`check`.

    ``check`` is called with the *entire accumulated buffer text so far*
    (plain string, not an AIMessageChunk — so watchdogs don't depend on
    LangChain internals). It must be fast: it runs after every chunk.
    """

    name: str = "watchdog"

    def check(self, buffer_text: str) -> WatchdogVerdict:       # noqa: D401
        return _OK


# ── DriftWatchdog ───────────────────────────────────────────────────────
class DriftWatchdog(Watchdog):
    """Fire when the accumulated text grows past the drift budget without
    mentioning any focus keyword."""

    name = "drift"

    def __init__(
        self,
        focus_keywords: Sequence[str],
        *,
        max_drift_chars: int = 1200,     # ~300 tokens at 4 chars/token
        min_buffer_chars: int = 300,     # don't fire on a short preamble
    ):
        # Store lowercased for case-insensitive match.
        self.focus = tuple(k.lower().strip() for k in focus_keywords if k)
        self.max_drift_chars = int(max_drift_chars)
        self.min_buffer_chars = int(min_buffer_chars)

    def check(self, buffer_text: str) -> WatchdogVerdict:
        if len(buffer_text) < self.min_buffer_chars:
            return _OK
        if not self.focus:
            return _OK
        lowered = buffer_text.lower()
        if any(k in lowered for k in self.focus):
            return _OK
        if len(buffer_text) < self.max_drift_chars:
            return _OK
        return WatchdogVerdict(
            tripped=True,
            name=self.name,
            reason=f"emitted {len(buffer_text)} chars without any focus keyword",
            correction_for_next_turn=(
                f"[mid_thinking_guard] You've been reasoning for {len(buffer_text)} "
                f"characters without mentioning any of the focus keywords "
                f"{list(self.focus)}. Re-centre: state the target and attack "
                f"family you are going to act on in one sentence, then issue "
                f"a tool call. Do NOT continue the previous reasoning chain."
            ),
        )


# ── ScopeWatchdog ───────────────────────────────────────────────────────
_URL_RE = re.compile(r"https?://[^\s\"'<>`)]+", re.IGNORECASE)


class ScopeWatchdog(Watchdog):
    """Fire when the accumulated text contains a URL that's out of scope."""

    name = "scope"

    def __init__(self, scope_guard: ScopeGuard):
        self._guard = scope_guard
        self._already_seen: set = set()

    def check(self, buffer_text: str) -> WatchdogVerdict:
        for m in _URL_RE.finditer(buffer_text):
            url = m.group(0)
            # Skip URLs that end at the buffer tail — they may still be
            # streaming (e.g. 'http://127.0.0.' before the trailing '1:9007'
            # arrives), and parsing them prematurely yields a bogus host that
            # trips this watchdog every single chunk. Wait for a terminator.
            if m.end() >= len(buffer_text):
                continue
            # The greedy regex also captures trailing sentence punctuation
            # (e.g. 'http://127.0.0.1:9007.' at the end of a sentence). That
            # makes urlparse(...).port raise ValueError on '9007.' and crash
            # the whole run, not just trip the watchdog. Strip trailing
            # punctuation before parsing.
            url = url.rstrip(".,!?:;")
            if not url or url in self._already_seen:
                continue
            self._already_seen.add(url)
            try:
                self._guard.check_url(url)
            except ScopeError as exc:
                return WatchdogVerdict(
                    tripped=True,
                    name=self.name,
                    reason=str(exc),
                    correction_for_next_turn=(
                        f"[mid_thinking_guard] You proposed {url!r}, which is "
                        f"outside the fixture scope ({exc}). Stay on the declared "
                        f"target only. Restate your plan using the allowed host."
                    ),
                )
            except Exception:  # noqa: BLE001
                # Defensive: a malformed URL slipping through (urlparse
                # ValueError on a weird port, etc.) should never kill the run.
                # Just skip — the corresponding http_probe call will surface
                # the real error if the model actually invokes it.
                continue
        return _OK


# ── LoopWatchdog ────────────────────────────────────────────────────────
# Crude pattern-match on the kind of JSON the LLM emits when proposing a tool
# call. We don't need to parse everything — we just need to catch the common
# case early. The anti-loop guard in engine/anti_loop.py catches the rest.
_TOOL_HINT_RE = re.compile(
    r'"name"\s*:\s*"([a-z_][a-z0-9_]*)".*?"args"\s*:\s*(\{[^}]*\})',
    re.IGNORECASE | re.DOTALL,
)


class LoopWatchdog(Watchdog):
    """Fire when the streamed text encodes a tool call whose signature is
    already at the loop threshold on the Blackboard."""

    name = "loop"

    def __init__(self, blackboard: Blackboard, *, threshold: int = 3):
        self.blackboard = blackboard
        self.threshold = int(threshold)

    def check(self, buffer_text: str) -> WatchdogVerdict:
        match = _TOOL_HINT_RE.search(buffer_text)
        if match is None:
            return _OK
        proposed_name, proposed_args_hint = match.group(1), match.group(2)
        # We can't compute the exact signature without running through
        # ``BaseTool._record``; approximate by matching on tool name.
        counts_for_tool = sum(
            1 for sig in self.blackboard.loop_signatures if sig.startswith(f"{proposed_name}:")
        )
        if counts_for_tool < self.threshold:
            return _OK
        return WatchdogVerdict(
            tripped=True,
            name=self.name,
            reason=f"{proposed_name} already invoked {counts_for_tool}× this run",
            correction_for_next_turn=(
                f"[mid_thinking_guard] You are about to call {proposed_name!r} again "
                f"({counts_for_tool} identical-family calls already in this run). "
                f"Call `pivot(reason=...)` NEXT and pick a different attack family."
            ),
        )
