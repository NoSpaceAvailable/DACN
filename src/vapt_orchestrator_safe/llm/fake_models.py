from __future__ import annotations

from typing import Any, Dict

from vapt_orchestrator_safe.llm.base import BaseModel
from vapt_orchestrator_safe.utils.text import compact


class RuleBasedModel(BaseModel):
    """Offline placeholder model used for the safe lab scaffold.

    It does not call any external API. It only provides deterministic,
    lightweight summarization for benchmarking the orchestration layer.
    """

    def summarize(self, prompt: str, metadata: Dict[str, Any] | None = None) -> str:
        meta = metadata or {}
        prefix = meta.get("role", "agent").replace("_", " ")
        return f"[{self.profile.label} | {prefix}] {compact(prompt, 180)}"
