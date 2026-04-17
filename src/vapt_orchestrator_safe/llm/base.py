from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from vapt_orchestrator_safe.types import ModelProfile


class BaseModel(ABC):
    def __init__(self, profile: ModelProfile):
        self.profile = profile

    @abstractmethod
    def summarize(self, prompt: str, metadata: Dict[str, Any] | None = None) -> str:
        raise NotImplementedError
