"""C2 — Anti-loop guard (DACN novel contribution).

Each concrete tool (nmap / curl / invoke_exploit / …) pushes a signature
``hash(tool_name, kwargs)`` onto ``Blackboard.loop_signatures`` every
time it runs. ``LoopGuard`` inspects that deque after every dispatcher
step; when any signature has appeared ``threshold`` times in the bounded
buffer, the guard flips the ``tripped`` flag.

The dispatcher plugs the guard in via :class:`AntiLoopHook`
(a :class:`DispatcherHook` subclass). On trip, the hook:

1. Logs a ``loop_detected`` event on the Blackboard with the offending
   signature + count.
2. Resets the signature deque so the next loop is detected afresh.
3. Injects a synthetic ``HumanMessage`` into the next dispatcher turn
   telling the LLM to call ``pivot(reason=...)`` and pick a different
   attack family. We inject guidance rather than abort the whole run,
   because the LLM still has useful context — it just needs a shove.

Why this matters for DACN
-------------------------
PentestGPT / VulnBot / AutoPT either retry blindly or rely on chain-level
reflection (Red-MIRROR's Inter-reflection vote) which still loops within
the same attack family. A signature-based structural check cuts through
that: if the *mechanical action* is the same three times in a row, we
know the model is stuck regardless of its reasoning. Cheap, model-
agnostic, backend-agnostic — it works the same on gemma-4B or
claude-sonnet.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage

from vapt_orchestrator_safe.engine.dispatcher import DispatcherHook
from vapt_orchestrator_safe.memory.shared_memory import Blackboard


_DEFAULT_THRESHOLD = 3


@dataclass
class LoopDetection:
    signature: str
    count: int
    total_tripped: int   # how many times THIS guard has fired during this run


class LoopGuard:
    """Pure detection logic — no dispatcher coupling. Easy to unit test."""

    def __init__(self, blackboard: Blackboard, threshold: int = _DEFAULT_THRESHOLD):
        if threshold < 2:
            raise ValueError("LoopGuard threshold must be >= 2")
        self.blackboard = blackboard
        self.threshold = threshold
        self.trips: List[LoopDetection] = []
        self._last_trip_signature: Optional[str] = None

    def check(self) -> Optional[LoopDetection]:
        """Return a fresh detection if a new loop crossed the threshold, else None.

        Successive calls don't re-fire for the same signature until it's
        been reset (the dispatcher hook always resets on trip).
        """
        counts: Dict[str, int] = {}
        for sig in self.blackboard.loop_signatures:
            counts[sig] = counts.get(sig, 0) + 1
        # Pick the most repeated signature that has crossed the threshold.
        offender = max(
            (s for s, c in counts.items() if c >= self.threshold),
            default=None,
            key=lambda s: counts[s],
        )
        if offender is None:
            return None
        if offender == self._last_trip_signature:
            return None
        detection = LoopDetection(
            signature=offender,
            count=counts[offender],
            total_tripped=len(self.trips) + 1,
        )
        self.trips.append(detection)
        self._last_trip_signature = offender
        return detection

    def reset(self) -> None:
        """Clear the Blackboard buffer so the next loop is detected fresh."""
        self.blackboard.reset_loop_signatures()
        self._last_trip_signature = None


class AntiLoopHook(DispatcherHook):
    """DispatcherHook that wires :class:`LoopGuard` into the supervisor loop.

    Configuration:

    - ``threshold`` — how many times a signature must repeat before we
      intervene (default 3).
    - ``max_trips`` — after this many interventions we give up, log, and
      let the dispatcher run to ``max_steps`` naturally. Keeps a truly
      broken run from wedging on the same family forever.
    """

    def __init__(
        self,
        blackboard: Blackboard,
        *,
        threshold: int = _DEFAULT_THRESHOLD,
        max_trips: int = 4,
    ):
        self.blackboard = blackboard
        self.guard = LoopGuard(blackboard, threshold=threshold)
        self.max_trips = max_trips
        self._pending_injection: Optional[HumanMessage] = None

    # ── DispatcherHook surface ───────────────────────────────────────────
    def before_step(self, step: int, messages: List[BaseMessage]) -> bool:
        # The dispatcher passes its live message list; append the pending
        # pivot nudge so it reaches the LLM on the NEXT invoke.
        if self._pending_injection is not None:
            messages.append(self._pending_injection)
            self._pending_injection = None
        return True

    def after_step(
        self,
        step: int,
        response: AIMessage,
        tool_invocations: Sequence[Dict[str, Any]],
    ) -> bool:
        detection = self.guard.check()
        if detection is None:
            return True
        if detection.total_tripped > self.max_trips:
            self.blackboard.log_event(
                "anti_loop",
                "max_trips.exhausted",
                {"signature": detection.signature, "count": detection.count},
            )
            return True

        self.blackboard.log_event(
            "anti_loop",
            "loop_detected",
            {
                "step": step,
                "signature": detection.signature,
                "count": detection.count,
                "trip_number": detection.total_tripped,
            },
        )
        self._pending_injection = HumanMessage(
            content=(
                f"[anti_loop_guard] Detected a repeating action signature "
                f"{detection.signature!r} ({detection.count}× in the last 32 steps). "
                f"You are looping. On the next tool call, invoke `pivot(reason=...)` "
                f"with a short justification, THEN pick a DIFFERENT attack family "
                f"from the analyst's ranked list. Do not repeat the offending action."
            )
        )
        # Reset so the same family doesn't immediately re-trip; if the LLM
        # ignores the nudge and loops again, the guard fires again naturally.
        self.guard.reset()
        return True
