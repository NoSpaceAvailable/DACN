from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from vapt_orchestrator_safe.engine.budget import BudgetTracker
from vapt_orchestrator_safe.engine.router import ModelRouter
from vapt_orchestrator_safe.llm.registry import ModelRegistry
from vapt_orchestrator_safe.memory.shared_memory import SharedMemory


@dataclass
class AgentDependencies:
    router: ModelRouter
    model_registry: ModelRegistry
    memory: SharedMemory
    budget: BudgetTracker


class BaseAgent:
    role: str = "agent"

    def __init__(self, deps: AgentDependencies):
        self.deps = deps
        self.profile = deps.router.profile_for_role(self.role)
        self.model = deps.model_registry.get(self.profile.name)

    def charge(self) -> None:
        self.deps.budget.record_tool(
            cost=self.profile.cost_per_step,
            tokens=self.profile.simulated_tokens_per_step,
        )
        self.deps.memory.set_budget(self.deps.budget.to_dict())

    def log(self, message: str, data: Dict[str, Any] | None = None) -> None:
        self.deps.memory.log_event(self.role, message, data)
