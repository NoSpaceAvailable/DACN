"""Adapter for Ollama HTTP API.

Used when the CLI is invoked with `--llm ollama:<model_tag>`. The adapter is a
thin wrapper around `POST /api/generate` and `POST /api/chat` on a remote
Ollama server (typically fronted by a Caddy reverse proxy with bearer-token
auth, see infra/vps-setup.sh).

Design notes
------------
- Keeps the BaseModel.summarize() contract so existing agents that still call
  RuleBasedModel.summarize() continue to work when swapped in.
- Adds OllamaModel.generate(...) returning a structured dict with token
  counts, so future agents (Phase 1 D3+) can charge the BudgetTracker
  accurately and inspect prompt/response usage.
- Uses requests for clarity. Network errors raise OllamaError with a clear
  message rather than silently returning a placeholder, so failures are
  visible during agent runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

from vapt_orchestrator_safe.llm.base import BaseModel
from vapt_orchestrator_safe.types import ModelProfile
from vapt_orchestrator_safe.utils.text import compact


class OllamaError(RuntimeError):
    """Raised when the Ollama backend cannot serve a request."""


@dataclass
class OllamaResponse:
    text: str
    prompt_tokens: int
    completion_tokens: int
    total_duration_ns: int
    raw: Dict[str, Any]


class OllamaModel(BaseModel):
    def __init__(
        self,
        profile: ModelProfile,
        base_url: str,
        model_name: str,
        token: Optional[str] = None,
        timeout: int = 180,
    ) -> None:
        super().__init__(profile)
        if not base_url:
            raise OllamaError("base_url is required for OllamaModel")
        if not model_name:
            raise OllamaError("model_name is required for OllamaModel")
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.token = token
        self.timeout = timeout

    # ── BaseModel contract ──────────────────────────────────────────────────
    def summarize(self, prompt: str, metadata: Dict[str, Any] | None = None) -> str:
        meta = metadata or {}
        role = str(meta.get("role", "general")).replace("_", " ")
        system = (
            f"You are the {role} agent in an automated web pentest pipeline. "
            "Reply concisely and avoid adding speculation outside the input."
        )
        result = self.generate(prompt=prompt, system=system, options={"temperature": 0.3})
        return f"[{self.profile.label} | {role}] {compact(result.text, 800)}"

    # ── Extended API used by Phase 1+ agents ────────────────────────────────
    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> OllamaResponse:
        url = f"{self.base_url}/api/generate"
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system
        if options:
            payload["options"] = options
        return self._post(url, payload)

    def chat(
        self,
        messages: List[Dict[str, str]],
        options: Optional[Dict[str, Any]] = None,
    ) -> OllamaResponse:
        url = f"{self.base_url}/api/chat"
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
        }
        if options:
            payload["options"] = options
        return self._post(url, payload, response_field=("message", "content"))

    def list_tags(self) -> List[str]:
        """Return model names available on the server (used by `llm-test`)."""
        url = f"{self.base_url}/api/tags"
        try:
            response = requests.get(url, headers=self._headers(), timeout=self.timeout)
        except requests.RequestException as exc:
            raise OllamaError(f"GET {url} failed: {exc}") from exc
        if response.status_code == 401:
            raise OllamaError("401 Unauthorized — check OLLAMA_TOKEN")
        if response.status_code != 200:
            raise OllamaError(f"GET {url} returned HTTP {response.status_code}: {response.text[:200]}")
        models = response.json().get("models", [])
        return [m.get("name", "") for m in models if m.get("name")]

    # ── internals ───────────────────────────────────────────────────────────
    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _post(
        self,
        url: str,
        payload: Dict[str, Any],
        response_field: Optional[tuple] = None,
    ) -> OllamaResponse:
        try:
            response = requests.post(
                url, json=payload, headers=self._headers(), timeout=self.timeout
            )
        except requests.Timeout as exc:
            raise OllamaError(
                f"POST {url} timed out after {self.timeout}s — the model is slow on CPU; "
                "consider raising OLLAMA_TIMEOUT or switching to a smaller model"
            ) from exc
        except requests.RequestException as exc:
            raise OllamaError(f"POST {url} failed: {exc}") from exc

        if response.status_code == 401:
            raise OllamaError("401 Unauthorized — check OLLAMA_TOKEN")
        if response.status_code == 404:
            raise OllamaError(
                f"404 Not Found — model '{self.model_name}' may not be pulled on the server. "
                "Run `ollama pull {self.model_name}` on the VPS."
            )
        if response.status_code != 200:
            raise OllamaError(
                f"POST {url} returned HTTP {response.status_code}: {response.text[:300]}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise OllamaError(f"Non-JSON response from {url}: {response.text[:200]}") from exc

        if response_field is not None:
            text = data
            for key in response_field:
                if not isinstance(text, dict) or key not in text:
                    raise OllamaError(
                        f"Response missing field {response_field}: {str(data)[:200]}"
                    )
                text = text[key]
        else:
            text = data.get("response", "")

        return OllamaResponse(
            text=str(text),
            prompt_tokens=int(data.get("prompt_eval_count", 0) or 0),
            completion_tokens=int(data.get("eval_count", 0) or 0),
            total_duration_ns=int(data.get("total_duration", 0) or 0),
            raw=data,
        )
