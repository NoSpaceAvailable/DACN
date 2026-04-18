"""Blackboard — thread-safe shared state for all agents.

The class is the orchestration-layer blackboard (per architecture v2). It
keeps the inherited ``SharedMemory`` API verbatim so existing tests/agents
keep working, and adds:

- ``threading.RLock`` around every mutator (multiple sandbox agents may run
  concurrently in Sprint 4+).
- ``phase_context``: per-phase scratchpad dict used by phase-scoped agents.
- ``kg_handle``: opaque pointer to the Neo4j driver session (populated in
  Sprint 5; ``None`` until then).
- ``loop_signatures``: bounded deque of ``(action, target, payload)`` hashes
  used by the anti-loop guard (Sprint 6).

``SharedMemory`` is preserved as a module-level alias so existing imports
``from vapt_orchestrator_safe.memory.shared_memory import SharedMemory``
continue to work.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any, Deque, Dict, List, Optional

from vapt_orchestrator_safe.memory.evidence import EvidenceItem
from vapt_orchestrator_safe.utils.io import write_json


_LOOP_SIG_CAPACITY = 32


@dataclass
class Blackboard:
    run_id: str
    run_dir: Path
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    task_graph: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    budget: Dict[str, Any] = field(default_factory=dict)

    # ── new in v2 ──────────────────────────────────────────────────────────
    phase_context: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    kg_handle: Optional[Any] = None
    loop_signatures: Deque[str] = field(
        default_factory=lambda: deque(maxlen=_LOOP_SIG_CAPACITY)
    )

    # ── concurrency ────────────────────────────────────────────────────────
    # `init=False` keeps the dataclass `__eq__`/`__repr__` clean and prevents
    # the lock from being copied/pickled with the data.
    _lock: RLock = field(default_factory=RLock, init=False, repr=False, compare=False)

    # ── task graph ─────────────────────────────────────────────────────────
    def add_task(self, name: str, status: str, metadata: Dict[str, Any] | None = None) -> None:
        with self._lock:
            self.task_graph.append({"name": name, "status": status, "metadata": metadata or {}})

    def update_task(self, name: str, status: str, metadata: Dict[str, Any] | None = None) -> None:
        with self._lock:
            for task in reversed(self.task_graph):
                if task["name"] == name:
                    task["status"] = status
                    if metadata:
                        task["metadata"].update(metadata)
                    return
            self.add_task(name=name, status=status, metadata=metadata)

    # ── evidence / artifacts / events ──────────────────────────────────────
    def add_evidence(self, item: EvidenceItem) -> None:
        with self._lock:
            self.evidence.append(item.to_dict())

    def add_artifact(self, kind: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self.artifacts.append({"kind": kind, "payload": payload})

    def log_event(self, phase: str, message: str, data: Dict[str, Any] | None = None) -> None:
        with self._lock:
            self.events.append({"phase": phase, "message": message, "data": data or {}})

    def set_budget(self, budget: Dict[str, Any]) -> None:
        with self._lock:
            self.budget = budget

    # ── phase context ──────────────────────────────────────────────────────
    def get_phase_context(self, phase: str) -> Dict[str, Any]:
        with self._lock:
            return self.phase_context.setdefault(phase, {})

    def set_phase_context(self, phase: str, ctx: Dict[str, Any]) -> None:
        with self._lock:
            self.phase_context[phase] = ctx

    # ── anti-loop signatures (Sprint 6 will read these) ────────────────────
    def push_loop_signature(self, signature: str) -> int:
        """Append a ``hash(action,target,payload)`` and return its current count."""
        with self._lock:
            self.loop_signatures.append(signature)
            return sum(1 for s in self.loop_signatures if s == signature)

    def loop_count(self, signature: str) -> int:
        with self._lock:
            return sum(1 for s in self.loop_signatures if s == signature)

    def reset_loop_signatures(self) -> None:
        with self._lock:
            self.loop_signatures.clear()

    # ── persistence ────────────────────────────────────────────────────────
    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "run_id": self.run_id,
                "evidence": list(self.evidence),
                "artifacts": list(self.artifacts),
                "task_graph": list(self.task_graph),
                "events": list(self.events),
                "budget": dict(self.budget),
                "phase_context": {k: dict(v) for k, v in self.phase_context.items()},
                "loop_signatures": list(self.loop_signatures),
                # kg_handle is intentionally NOT serialised (it's a live driver)
            }

    def persist(self) -> None:
        write_json(self.run_dir / "memory.json", self.snapshot())


# ── backwards compatibility ────────────────────────────────────────────────
# Existing code does ``from ...memory.shared_memory import SharedMemory``;
# the alias keeps every Sprint 1 import path valid.
SharedMemory = Blackboard
