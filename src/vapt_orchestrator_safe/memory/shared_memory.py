from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from vapt_orchestrator_safe.memory.evidence import EvidenceItem
from vapt_orchestrator_safe.utils.io import write_json


@dataclass
class SharedMemory:
    run_id: str
    run_dir: Path
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    task_graph: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    budget: Dict[str, Any] = field(default_factory=dict)

    def add_task(self, name: str, status: str, metadata: Dict[str, Any] | None = None) -> None:
        self.task_graph.append({"name": name, "status": status, "metadata": metadata or {}})

    def update_task(self, name: str, status: str, metadata: Dict[str, Any] | None = None) -> None:
        for task in reversed(self.task_graph):
            if task["name"] == name:
                task["status"] = status
                if metadata:
                    task["metadata"].update(metadata)
                return
        self.add_task(name=name, status=status, metadata=metadata)

    def add_evidence(self, item: EvidenceItem) -> None:
        self.evidence.append(item.to_dict())

    def add_artifact(self, kind: str, payload: Dict[str, Any]) -> None:
        self.artifacts.append({"kind": kind, "payload": payload})

    def log_event(self, phase: str, message: str, data: Dict[str, Any] | None = None) -> None:
        self.events.append({"phase": phase, "message": message, "data": data or {}})

    def set_budget(self, budget: Dict[str, Any]) -> None:
        self.budget = budget

    def snapshot(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "evidence": self.evidence,
            "artifacts": self.artifacts,
            "task_graph": self.task_graph,
            "events": self.events,
            "budget": self.budget,
        }

    def persist(self) -> None:
        write_json(self.run_dir / "memory.json", self.snapshot())
