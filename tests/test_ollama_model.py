"""Tests for the Ollama HTTP adapter — uses a mocked requests so they run offline."""
from __future__ import annotations

from typing import Any, Dict
from unittest.mock import patch

import pytest

from vapt_orchestrator_safe.llm.ollama_model import (
    OllamaError,
    OllamaModel,
    OllamaResponse,
)
from vapt_orchestrator_safe.llm.registry import (
    ModelRegistry,
    OllamaConfig,
    parse_backend,
)
from vapt_orchestrator_safe.types import ModelProfile


def _profile() -> ModelProfile:
    return ModelProfile(
        name="probe", label="probe",
        reasoning=0.5, analysis=0.5, coding=0.5, reporting=0.5, recon=0.5, validation=0.5,
        cost_per_step=0.001, simulated_tokens_per_step=100,
    )


class _FakeResponse:
    def __init__(self, status: int, payload: Dict[str, Any] | str):
        self.status_code = status
        self._payload = payload

    @property
    def text(self) -> str:
        return str(self._payload)

    def json(self) -> Any:
        if isinstance(self._payload, str):
            raise ValueError("not json")
        return self._payload


def test_parse_backend_rule():
    assert parse_backend("rule") == ("rule", None)


def test_parse_backend_ollama_split_first_colon_only():
    # Critical: model tag itself contains a colon (gemma4:e2b)
    assert parse_backend("ollama:gemma4:e2b") == ("ollama", "gemma4:e2b")


def test_registry_treats_api_backend_as_rule():
    # API-based backends (anthropic/openai/openrouter/custom) are handled by the
    # dispatcher's ChatModel, not the sub-agent registry. The registry falls back
    # to 'rule' so the runner can still construct it without crashing.
    reg = ModelRegistry({"probe": _profile()}, backend="claude:opus")
    assert reg.backend_label == "rule"


def test_registry_ollama_requires_config():
    with pytest.raises(ValueError):
        ModelRegistry({"probe": _profile()}, backend="ollama:gemma4:e2b")


def test_registry_ollama_requires_model_tag():
    with pytest.raises(ValueError):
        ModelRegistry(
            {"probe": _profile()},
            backend="ollama",
            ollama_config=OllamaConfig(base_url="http://x"),
        )


def test_registry_returns_ollama_model_with_correct_tag():
    reg = ModelRegistry(
        {"probe": _profile()},
        backend="ollama:gemma4:e2b",
        ollama_config=OllamaConfig(base_url="http://x", token="t", timeout=42),
    )
    model = reg.get("probe")
    assert isinstance(model, OllamaModel)
    assert model.model_name == "gemma4:e2b"
    assert model.base_url == "http://x"
    assert model.token == "t"
    assert model.timeout == 42
    assert reg.backend_label == "ollama:gemma4:e2b"


def test_generate_happy_path_records_token_counts():
    payload = {
        "response": "OK",
        "prompt_eval_count": 7,
        "eval_count": 3,
        "total_duration": 1_234_567_890,
    }
    model = OllamaModel(_profile(), base_url="http://x", model_name="gemma4:e2b")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _FakeResponse(200, payload)
        result = model.generate("hi", system="sys", options={"temperature": 0.0})
    assert isinstance(result, OllamaResponse)
    assert result.text == "OK"
    assert result.prompt_tokens == 7
    assert result.completion_tokens == 3
    assert result.total_duration_ns == 1_234_567_890
    sent_kwargs = post.call_args.kwargs
    assert sent_kwargs["json"]["model"] == "gemma4:e2b"
    assert sent_kwargs["json"]["prompt"] == "hi"
    assert sent_kwargs["json"]["system"] == "sys"
    assert sent_kwargs["json"]["stream"] is False
    assert sent_kwargs["json"]["options"] == {"temperature": 0.0}


def test_generate_merges_default_options_with_call_options():
    payload = {"response": "OK", "prompt_eval_count": 0, "eval_count": 0, "total_duration": 0}
    model = OllamaModel(
        _profile(),
        base_url="http://x",
        model_name="g",
        default_options={"num_ctx": 8192, "temperature": 0.2},
    )
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _FakeResponse(200, payload)
        model.generate("hi", options={"temperature": 0.0})
    assert post.call_args.kwargs["json"]["options"] == {
        "num_ctx": 8192,
        "temperature": 0.0,
    }


def test_summarize_wraps_generate_and_includes_label():
    payload = {"response": "the body", "prompt_eval_count": 1, "eval_count": 1, "total_duration": 0}
    model = OllamaModel(_profile(), base_url="http://x", model_name="gemma4:e2b")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _FakeResponse(200, payload)
        text = model.summarize("hello", metadata={"role": "recon"})
    assert "[probe | recon]" in text
    assert "the body" in text


def test_bearer_token_header_set_only_when_token_present():
    model = OllamaModel(_profile(), base_url="http://x", model_name="g", token="abc")
    assert model._headers()["Authorization"] == "Bearer abc"
    model_no = OllamaModel(_profile(), base_url="http://x", model_name="g")
    assert "Authorization" not in model_no._headers()


def test_401_raises_clear_error():
    model = OllamaModel(_profile(), base_url="http://x", model_name="g", token="bad")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _FakeResponse(401, {"error": "unauthorized"})
        with pytest.raises(OllamaError, match="401 Unauthorized"):
            model.generate("hi")


def test_404_mentions_model_name():
    model = OllamaModel(_profile(), base_url="http://x", model_name="ghost-model")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _FakeResponse(404, {"error": "model not found"})
        with pytest.raises(OllamaError, match="ghost-model"):
            model.generate("hi")


def test_non_200_includes_status_code():
    model = OllamaModel(_profile(), base_url="http://x", model_name="g")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _FakeResponse(500, {"error": "internal"})
        with pytest.raises(OllamaError, match="HTTP 500"):
            model.generate("hi")


def test_non_json_body_raises():
    model = OllamaModel(_profile(), base_url="http://x", model_name="g")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _FakeResponse(200, "<html>oops</html>")
        with pytest.raises(OllamaError, match="Non-JSON"):
            model.generate("hi")


def test_timeout_raises_with_actionable_message():
    import requests as _requests
    model = OllamaModel(_profile(), base_url="http://x", model_name="g", timeout=5)
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.side_effect = _requests.Timeout("slow")
        with pytest.raises(OllamaError, match="OLLAMA_TIMEOUT"):
            model.generate("hi")


def test_list_tags_returns_names():
    model = OllamaModel(_profile(), base_url="http://x", model_name="g")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.get") as get:
        get.return_value = _FakeResponse(200, {"models": [{"name": "gemma4:e2b"}, {"name": "qwen2.5:7b"}]})
        assert model.list_tags() == ["gemma4:e2b", "qwen2.5:7b"]


def test_chat_extracts_message_content():
    payload = {"message": {"role": "assistant", "content": "hi back"}, "prompt_eval_count": 0, "eval_count": 0, "total_duration": 0}
    model = OllamaModel(_profile(), base_url="http://x", model_name="g")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _FakeResponse(200, payload)
        result = model.chat([{"role": "user", "content": "hi"}])
    assert result.text == "hi back"
