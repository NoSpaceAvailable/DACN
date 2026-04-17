from __future__ import annotations

from typing import Dict

from vapt_orchestrator_safe.types import ModelProfile


class ModelRouter:
    def __init__(self, profiles: Dict[str, ModelProfile], profile_set: Dict[str, str]):
        self.profiles = profiles
        self.profile_set = profile_set

    def profile_for_role(self, role: str) -> ModelProfile:
        profile_name = self.profile_set[role]
        return self.profiles[profile_name]

    def capability_for_role(self, role: str) -> float:
        profile = self.profile_for_role(role)
        mapping = {
            "coordinator": profile.reasoning,
            "recon": profile.recon,
            "signature": profile.analysis,
            "analyst": profile.analysis,
            "exploit": max(profile.coding, profile.reasoning),
            "validator": profile.validation,
            "report": profile.reporting,
        }
        return mapping[role]
