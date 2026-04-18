"""Agent bases.

Two coexisting bases:

- :class:`BaseAgent` (Sprint 1) — original lightweight base used by the
  inherited 7 agents (Intake / Recon / Signature / Analyst / Exploit /
  Validator / Report). It only knows about a model, a router and the
  Blackboard. Kept unchanged so Sprint 1 agents keep working until they
  are migrated.

- :class:`LangChainAgent` (Sprint 2) — new base for the v2 architecture.
  Wraps a LangChain ``BaseChatModel`` plus bound tools, loads its system
  prompt from ``prompts/<role>.md``, and writes back to the Blackboard
  via dependency injection. Sprint 3 will rewire the existing concrete
  agents on top of this. Sprint 2 only ships the base + tests; no agent
  is migrated yet.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from vapt_orchestrator_safe.engine.budget import BudgetTracker
from vapt_orchestrator_safe.engine.router import ModelRouter
from vapt_orchestrator_safe.llm.registry import ModelRegistry
from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.prompts import load_prompt


# ── Sprint 1 base (unchanged) ──────────────────────────────────────────────
@dataclass
class AgentDependencies:
    router: ModelRouter
    model_registry: ModelRegistry
    memory: Blackboard
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


# ── Sprint 2 base (NEW) ────────────────────────────────────────────────────
@dataclass
class LangChainAgentSpec:
    """All the wiring the new agent base needs at construction time."""
    role: str
    chat_model: Any                     # langchain_core BaseChatModel; typed Any to keep tests offline
    blackboard: Blackboard
    tools: Sequence[Any] = field(default_factory=tuple)   # subclasses of project BaseTool
    system_prompt: Optional[str] = None  # if None, load prompts/<role>.md
    extra_system: Optional[str] = None   # appended to system_prompt at run time
    backend_spec: Optional[str] = None   # purely informational, recorded in events


class LangChainAgent:
    """Base for v2 agents.

    Sub-classes typically do nothing more than set ``role`` and override
    :meth:`act` to wrap a domain-specific workflow. The base handles:

    - Loading and caching the system prompt.
    - Binding tools to the chat model (via ``model.bind_tools(...)``) when
      the model supports tool-calling. Plain models still work; the base
      will just call ``model.invoke([SystemMessage, HumanMessage])``.
    - Logging the agent's call into the Blackboard ``events`` list.
    - Auto-injecting the Blackboard into each tool so tool results land
      in artifacts.
    """

    role: str = "agent"

    def __init__(self, spec: LangChainAgentSpec):
        if spec.role:
            self.role = spec.role
        self.spec = spec
        self.blackboard = spec.blackboard
        self.tools = list(spec.tools)
        # Inject blackboard into every tool that supports it.
        for tool in self.tools:
            if hasattr(tool, "bind_blackboard"):
                tool.bind_blackboard(self.blackboard)
        # Bind tools to the chat model when supported (most LangChain
        # ChatModels expose .bind_tools); on plain LLMs we keep the raw
        # model and the agent just won't request tool calls.
        bind = getattr(spec.chat_model, "bind_tools", None)
        self.chat_model = bind(self.tools) if (bind and self.tools) else spec.chat_model

    @property
    def system_prompt(self) -> str:
        text = self.spec.system_prompt
        if text is None:
            text = load_prompt(self.role)  # raises FileNotFoundError if missing
        if self.spec.extra_system:
            text = f"{text}\n\n{self.spec.extra_system}"
        return text

    def log(self, message: str, data: Dict[str, Any] | None = None) -> None:
        self.blackboard.log_event(self.role, message, data)

    def invoke_model(self, user_text: str) -> Any:
        """Single-turn convenience: SystemMessage + HumanMessage → response.

        Concrete agents that need multi-turn / streaming / tool-calling loops
        will subclass and call self.chat_model directly.
        """
        from langchain_core.messages import HumanMessage, SystemMessage
        messages = [SystemMessage(content=self.system_prompt), HumanMessage(content=user_text)]
        self.log("invoke_model.begin", {"user_chars": len(user_text), "tools": len(self.tools)})
        response = self.chat_model.invoke(messages)
        self.log("invoke_model.end", {"response_chars": len(getattr(response, "content", "") or "")})
        return response
