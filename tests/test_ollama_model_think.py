"""Tests for the new `think` parameter on OllamaModel.generate()."""
from __future__ import annotations

from typing import Any, Dict
from unittest.mock import patch

from vapt_orchestrator_safe.llm.ollama_model import OllamaModel
from vapt_orchestrator_safe.types import ModelProfile


def _profile() -> ModelProfile:
    return ModelProfile(
        name="p", label="p",
        reasoning=0.5, analysis=0.5, coding=0.5, reporting=0.5, recon=0.5, validation=0.5,
        cost_per_step=0.001, simulated_tokens_per_step=100,
    )


class _Resp:
    status_code = 200
    text = ""
    def json(self) -> Dict[str, Any]:
        return {"response": "x", "prompt_eval_count": 1, "eval_count": 1, "total_duration": 0}


def test_think_omitted_when_none():
    model = OllamaModel(_profile(), base_url="http://x", model_name="g")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _Resp()
        model.generate("hi")
    assert "think" not in post.call_args.kwargs["json"]


def test_think_false_passed_at_top_level():
    model = OllamaModel(_profile(), base_url="http://x", model_name="g")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _Resp()
        model.generate("hi", think=False)
    assert post.call_args.kwargs["json"]["think"] is False


def test_think_true_passed_at_top_level():
    model = OllamaModel(_profile(), base_url="http://x", model_name="g")
    with patch("vapt_orchestrator_safe.llm.ollama_model.requests.post") as post:
        post.return_value = _Resp()
        model.generate("hi", think=True)
    assert post.call_args.kwargs["json"]["think"] is True
