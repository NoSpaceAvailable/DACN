"""LangChain backend factory.

Builds a LangChain ``BaseChatModel`` from a single ``spec`` string so callers
can swap providers (Ollama / OpenAI / Anthropic / OpenRouter / any
OpenAI-compatible URL) without changing code — only an env var.

Spec syntax (split on the FIRST colon):
    ollama:<model_tag>          → ChatOllama
    openai:<model>              → ChatOpenAI (api.openai.com)
    anthropic:<model>           → ChatAnthropic
    openrouter:<model>          → ChatOpenAI(base_url=https://openrouter.ai/api/v1)
    custom:<model>              → ChatOpenAI(base_url=$LLM_CUSTOM_BASE_URL)
                                  (escape hatch for vLLM / LM Studio / TGI / etc.)

Per-role override: ``LLM_BACKEND_<ROLE>`` env var (e.g. ``LLM_BACKEND_RECON``)
falls back to ``LLM_BACKEND_DEFAULT`` if unset; the latter falls back to
``ollama:gemma4:e2b`` so dev work on the VPS keeps working out of the box.

Sprint 2 scope: build the wrapper only — no real API calls are exercised
during tests; an offline-friendly mock factory is exposed for unit tests.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from vapt_orchestrator_safe.config import _load_dotenv_if_present


_DEFAULT_SPEC = "ollama:gemma4:e2b"
_VALID_PROVIDERS = ("ollama", "openai", "anthropic", "openrouter", "custom")


class BackendError(RuntimeError):
    """Raised when the requested backend cannot be constructed."""


@dataclass(frozen=True)
class BackendSpec:
    provider: str        # one of _VALID_PROVIDERS
    model: str           # e.g. "gemma4:e2b" or "gpt-5-mini" or "claude-sonnet-4-5"


def parse_spec(spec: str) -> BackendSpec:
    """``ollama:gemma4:e2b`` → BackendSpec('ollama', 'gemma4:e2b'). First-colon split."""
    if ":" not in spec:
        raise BackendError(
            f"Invalid backend spec {spec!r}: expected 'provider:model' "
            f"(provider in {_VALID_PROVIDERS})"
        )
    provider, model = spec.split(":", 1)
    if provider not in _VALID_PROVIDERS:
        raise BackendError(
            f"Unknown provider {provider!r} in spec {spec!r}; "
            f"expected one of {_VALID_PROVIDERS}"
        )
    if not model:
        raise BackendError(f"Empty model in spec {spec!r}")
    return BackendSpec(provider=provider, model=model)


def resolve_spec(role: Optional[str] = None) -> str:
    """Read ``LLM_BACKEND_<ROLE>`` → ``LLM_BACKEND_DEFAULT`` → built-in default."""
    _load_dotenv_if_present()
    if role:
        env_key = f"LLM_BACKEND_{role.upper()}"
        if os.environ.get(env_key):
            return os.environ[env_key]
    return os.environ.get("LLM_BACKEND_DEFAULT", _DEFAULT_SPEC)


# ── Builder registry ───────────────────────────────────────────────────────
def _build_ollama(model: str, **overrides: Any):
    from langchain_ollama import ChatOllama  # local import keeps tests offline-able

    base_url = overrides.pop("base_url", None) or os.environ.get("OLLAMA_BASE_URL")
    if not base_url:
        raise BackendError(
            "OLLAMA_BASE_URL is not set; required for the 'ollama' provider"
        )
    headers: Dict[str, str] = {}
    token = overrides.pop("token", None) or os.environ.get("OLLAMA_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    timeout_raw = overrides.pop("timeout", None) or os.environ.get("OLLAMA_TIMEOUT", "600")
    try:
        timeout = float(timeout_raw)
    except (TypeError, ValueError):
        raise BackendError(f"OLLAMA_TIMEOUT must be numeric, got {timeout_raw!r}")
    return ChatOllama(
        model=model,
        base_url=base_url,
        client_kwargs={"headers": headers} if headers else None,
        **{**{"temperature": 0.1, "timeout": timeout}, **overrides},
    )


def _build_openai(model: str, **overrides: Any):
    from langchain_openai import ChatOpenAI

    api_key = overrides.pop("api_key", None) or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise BackendError(
            "OPENAI_API_KEY is not set; required for the 'openai' provider"
        )
    base_url = overrides.pop("base_url", None) or os.environ.get("OPENAI_BASE_URL")
    return ChatOpenAI(
        model=model,
        api_key=api_key,
        base_url=base_url,  # None → default api.openai.com
        **{**{"temperature": 0.1, "timeout": 600}, **overrides},
    )


def _build_anthropic(model: str, **overrides: Any):
    from langchain_anthropic import ChatAnthropic

    api_key = overrides.pop("api_key", None) or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise BackendError(
            "ANTHROPIC_API_KEY is not set; required for the 'anthropic' provider"
        )
    return ChatAnthropic(
        model=model,
        api_key=api_key,
        **{**{"temperature": 0.1, "timeout": 600}, **overrides},
    )


def _build_openrouter(model: str, **overrides: Any):
    from langchain_openai import ChatOpenAI

    api_key = overrides.pop("api_key", None) or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise BackendError(
            "OPENROUTER_API_KEY is not set; required for the 'openrouter' provider"
        )
    return ChatOpenAI(
        model=model,
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        **{**{"temperature": 0.1, "timeout": 600}, **overrides},
    )


def _build_custom(model: str, **overrides: Any):
    from langchain_openai import ChatOpenAI

    base_url = overrides.pop("base_url", None) or os.environ.get("LLM_CUSTOM_BASE_URL")
    if not base_url:
        raise BackendError(
            "LLM_CUSTOM_BASE_URL is not set; required for the 'custom' provider"
        )
    api_key = overrides.pop("api_key", None) or os.environ.get("LLM_CUSTOM_API_KEY", "EMPTY")
    return ChatOpenAI(
        model=model,
        api_key=api_key,
        base_url=base_url,
        **{**{"temperature": 0.1, "timeout": 600}, **overrides},
    )


_BUILDERS: Dict[str, Callable[..., Any]] = {
    "ollama": _build_ollama,
    "openai": _build_openai,
    "anthropic": _build_anthropic,
    "openrouter": _build_openrouter,
    "custom": _build_custom,
}


def build_chat_model(spec: str, **overrides: Any):
    """Construct a LangChain ``BaseChatModel`` instance for ``spec``.

    Raises :class:`BackendError` (with a clear message) if the env is missing
    the required credentials or the spec is malformed. ``overrides`` are
    forwarded to the underlying ``ChatModel`` constructor (e.g. ``temperature``,
    ``streaming``).
    """
    parsed = parse_spec(spec)
    return _BUILDERS[parsed.provider](parsed.model, **overrides)


def build_for_role(role: str, **overrides: Any) -> Tuple[str, Any]:
    """Resolve env spec for ``role`` and build the model. Returns (spec, model)."""
    spec = resolve_spec(role)
    return spec, build_chat_model(spec, **overrides)
