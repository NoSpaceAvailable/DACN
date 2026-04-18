"""Backend factory tests — pure unit tests, no real API calls."""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from vapt_orchestrator_safe.llm.backend_factory import (
    BackendError,
    BackendSpec,
    build_chat_model,
    build_for_role,
    parse_spec,
    resolve_spec,
)


# ── parse_spec ─────────────────────────────────────────────────────────────
def test_parse_spec_simple():
    assert parse_spec("openai:gpt-5-mini") == BackendSpec("openai", "gpt-5-mini")


def test_parse_spec_first_colon_only_for_ollama_tag():
    # gemma4:e2b contains a colon — must NOT split it
    assert parse_spec("ollama:gemma4:e2b") == BackendSpec("ollama", "gemma4:e2b")


def test_parse_spec_anthropic_dashes():
    assert parse_spec("anthropic:claude-sonnet-4-5") == BackendSpec(
        "anthropic", "claude-sonnet-4-5"
    )


def test_parse_spec_openrouter_slash():
    assert parse_spec("openrouter:google/gemma-3-27b") == BackendSpec(
        "openrouter", "google/gemma-3-27b"
    )


def test_parse_spec_rejects_missing_colon():
    with pytest.raises(BackendError, match="Invalid backend spec"):
        parse_spec("ollama")


def test_parse_spec_rejects_unknown_provider():
    with pytest.raises(BackendError, match="Unknown provider"):
        parse_spec("groq:llama")


def test_parse_spec_rejects_empty_model():
    with pytest.raises(BackendError, match="Empty model"):
        parse_spec("openai:")


# ── resolve_spec env precedence ────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Clear env vars used by resolve_spec / builders so tests don't leak."""
    for k in [
        "LLM_BACKEND_DEFAULT", "LLM_BACKEND_RECON", "LLM_BACKEND_ANALYST",
        "LLM_BACKEND_EXPLOIT", "LLM_BACKEND_REPORT",
        "OLLAMA_BASE_URL", "OLLAMA_TOKEN", "OLLAMA_TIMEOUT",
        "OPENAI_API_KEY", "OPENAI_BASE_URL",
        "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY",
        "LLM_CUSTOM_BASE_URL", "LLM_CUSTOM_API_KEY",
    ]:
        monkeypatch.delenv(k, raising=False)


def test_resolve_spec_falls_back_to_builtin_default():
    assert resolve_spec("recon") == "ollama:gemma4:e2b"


def test_resolve_spec_uses_default_env_when_role_unset(monkeypatch):
    monkeypatch.setenv("LLM_BACKEND_DEFAULT", "openai:gpt-5-mini")
    assert resolve_spec("recon") == "openai:gpt-5-mini"


def test_resolve_spec_role_override_wins(monkeypatch):
    monkeypatch.setenv("LLM_BACKEND_DEFAULT", "openai:gpt-5-mini")
    monkeypatch.setenv("LLM_BACKEND_RECON", "anthropic:claude-sonnet-4-5")
    assert resolve_spec("recon") == "anthropic:claude-sonnet-4-5"
    assert resolve_spec("exploit") == "openai:gpt-5-mini"  # falls back to default


def test_resolve_spec_no_role_returns_default(monkeypatch):
    monkeypatch.setenv("LLM_BACKEND_DEFAULT", "anthropic:claude-sonnet-4-5")
    assert resolve_spec(None) == "anthropic:claude-sonnet-4-5"


# ── build_chat_model — env-missing errors ──────────────────────────────────
def test_build_ollama_requires_base_url():
    with pytest.raises(BackendError, match="OLLAMA_BASE_URL"):
        build_chat_model("ollama:gemma4:e2b")


def test_build_openai_requires_api_key():
    with pytest.raises(BackendError, match="OPENAI_API_KEY"):
        build_chat_model("openai:gpt-5-mini")


def test_build_anthropic_requires_api_key():
    with pytest.raises(BackendError, match="ANTHROPIC_API_KEY"):
        build_chat_model("anthropic:claude-sonnet-4-5")


def test_build_openrouter_requires_api_key():
    with pytest.raises(BackendError, match="OPENROUTER_API_KEY"):
        build_chat_model("openrouter:google/gemma-3-27b")


def test_build_custom_requires_base_url():
    with pytest.raises(BackendError, match="LLM_CUSTOM_BASE_URL"):
        build_chat_model("custom:my-model")


# ── build_chat_model — happy path returns the right ChatModel class ────────
def test_build_ollama_returns_chat_ollama(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://example.invalid")
    monkeypatch.setenv("OLLAMA_TOKEN", "tok")
    monkeypatch.setenv("OLLAMA_TIMEOUT", "120")
    from langchain_ollama import ChatOllama
    model = build_chat_model("ollama:gemma4:e2b")
    assert isinstance(model, ChatOllama)
    assert model.model == "gemma4:e2b"
    assert model.base_url == "http://example.invalid"


def test_build_openai_uses_base_url_override(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.example.com/v1")
    from langchain_openai import ChatOpenAI
    model = build_chat_model("openai:gpt-5-mini")
    assert isinstance(model, ChatOpenAI)
    assert str(model.openai_api_base) == "https://api.example.com/v1"


def test_build_openrouter_pins_known_base_url(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test")
    from langchain_openai import ChatOpenAI
    model = build_chat_model("openrouter:google/gemma-3-27b")
    assert isinstance(model, ChatOpenAI)
    assert "openrouter.ai" in str(model.openai_api_base)


def test_build_anthropic_returns_chat_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    from langchain_anthropic import ChatAnthropic
    model = build_chat_model("anthropic:claude-sonnet-4-5")
    assert isinstance(model, ChatAnthropic)
    assert model.model == "claude-sonnet-4-5"


def test_build_for_role_returns_spec_and_model(monkeypatch):
    monkeypatch.setenv("LLM_BACKEND_RECON", "ollama:gemma4:e2b")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://x")
    spec, model = build_for_role("recon")
    assert spec == "ollama:gemma4:e2b"
    from langchain_ollama import ChatOllama
    assert isinstance(model, ChatOllama)


def test_build_chat_model_overrides_forwarded(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://x")
    model = build_chat_model("ollama:gemma4:e2b", temperature=0.9)
    assert model.temperature == 0.9
