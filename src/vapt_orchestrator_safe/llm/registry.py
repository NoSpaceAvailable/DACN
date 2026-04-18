"""Factory for LLM backends used by agents.

Backend syntax (CLI `--llm` flag):
  rule                  → RuleBasedModel (offline, deterministic; default)
  ollama:<model_tag>    → OllamaModel hitting OLLAMA_BASE_URL with given tag
                          (e.g. ollama:gemma4:e2b, ollama:qwen2.5:7b)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from vapt_orchestrator_safe.llm.base import BaseModel
from vapt_orchestrator_safe.llm.fake_models import RuleBasedModel
from vapt_orchestrator_safe.llm.ollama_model import OllamaModel
from vapt_orchestrator_safe.types import ModelProfile


@dataclass
class OllamaConfig:
    base_url: str
    token: Optional[str] = None
    timeout: int = 180


def parse_backend(spec: str) -> tuple[str, Optional[str]]:
    """Split CLI spec into (kind, model_tag).

    'rule'                → ('rule', None)
    'ollama:gemma4:e2b'   → ('ollama', 'gemma4:e2b')   (split on first colon)
    """
    if ":" not in spec:
        return spec, None
    kind, model_tag = spec.split(":", 1)
    return kind, model_tag


class ModelRegistry:
    def __init__(
        self,
        profiles: Dict[str, ModelProfile],
        backend: str = "rule",
        ollama_config: Optional[OllamaConfig] = None,
    ) -> None:
        self._profiles = profiles
        kind, model_tag = parse_backend(backend)
        if kind not in {"rule", "ollama"}:
            raise ValueError(f"Unknown LLM backend '{kind}'. Expected 'rule' or 'ollama:<tag>'.")
        if kind == "ollama":
            if not model_tag:
                raise ValueError("ollama backend requires a model tag, e.g. ollama:gemma4:e2b")
            if ollama_config is None:
                raise ValueError("ollama backend requires ollama_config (set OLLAMA_BASE_URL)")
        self._kind = kind
        self._model_tag = model_tag
        self._ollama_config = ollama_config

    @property
    def backend_label(self) -> str:
        if self._kind == "ollama":
            return f"ollama:{self._model_tag}"
        return self._kind

    def get(self, name: str) -> BaseModel:
        profile = self._profiles[name]
        if self._kind == "rule":
            return RuleBasedModel(profile)
        # ollama
        assert self._ollama_config is not None and self._model_tag is not None
        return OllamaModel(
            profile=profile,
            base_url=self._ollama_config.base_url,
            model_name=self._model_tag,
            token=self._ollama_config.token,
            timeout=self._ollama_config.timeout,
        )
