from __future__ import annotations

from typing import Dict

from vapt_orchestrator_safe.llm.fake_models import RuleBasedModel
from vapt_orchestrator_safe.types import ModelProfile


class ModelRegistry:
    def __init__(self, profiles: Dict[str, ModelProfile]):
        self._profiles = profiles

    def get(self, name: str) -> RuleBasedModel:
        profile = self._profiles[name]
        return RuleBasedModel(profile)
