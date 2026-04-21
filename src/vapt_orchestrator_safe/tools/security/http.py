"""HttpProbeTool — pure-python HTTP request with scope gating.

Preferred over CurlTool for typical dispatcher use because:

- No subprocess, no shell — cleaner, faster, no spawn cost.
- Response surface (status / headers / body) is returned as structured
  JSON in ``stdout`` so the LLM can pattern-match cleanly.
- Easier to mock in tests (monkeypatch ``requests.request`` once).

Trade-off: the tool disables HTTP redirect-following so the scope guard
stays in control — a redirect to a new host would be an un-gated
request. If the LLM needs to follow a redirect it must call the tool
again with the new URL.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Type

import requests
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult
from vapt_orchestrator_safe.utils.scope import ScopeGuard


_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


class _HttpArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    url: str = Field(description="URL to request. Host must be in the fixture scope.")
    method: str = Field(default="GET", description="HTTP method.")
    headers: Optional[Dict[str, str]] = Field(default=None)
    data: Optional[str] = Field(
        default=None,
        description="Raw body string. Mutually exclusive with 'json_body'.",
    )
    json_body: Optional[Dict[str, Any]] = Field(default=None, description="JSON body.")
    timeout: float = Field(default=10.0, description="Request timeout (seconds).")
    max_body_chars: int = Field(
        default=4000,
        description="Truncate response body at this many chars before returning.",
    )


class HttpProbeTool(BaseTool):
    name: str = "http_probe"
    description: str = (
        "Send one HTTP request to an in-scope URL and return a structured JSON "
        "summary (status / headers / truncated body). Redirects are NOT followed; "
        "the tool must be called again with the new URL."
    )
    args_schema: Type[BaseModel] = _HttpArgs

    _scope: Optional[ScopeGuard] = PrivateAttr(default=None)
    _session: Optional[requests.Session] = PrivateAttr(default=None)

    def __init__(
        self,
        scope: Optional[ScopeGuard] = None,
        session: Optional[requests.Session] = None,
        **data: Any,
    ):
        super().__init__(**data)
        self._scope = scope
        self._session = session  # tests inject a fake session; prod uses requests directly

    def _invoke(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        method = str(kwargs.get("method", "GET")).upper()
        if method not in _ALLOWED_METHODS:
            return ToolResult(stderr=f"Method {method!r} not allowed", exit_code=2)
        if self._scope is not None:
            self._scope.check_url(url)

        headers = kwargs.get("headers") or {}
        data = kwargs.get("data")
        json_body = kwargs.get("json_body")
        if data is not None and json_body is not None:
            return ToolResult(stderr="Pass either data or json_body, not both.", exit_code=2)

        timeout = float(kwargs.get("timeout", 10.0))
        requester = self._session.request if self._session is not None else requests.request

        response = requester(
            method=method,
            url=url,
            headers=headers,
            data=data,
            json=json_body,
            timeout=timeout,
            allow_redirects=False,
        )

        body = response.text or ""
        max_body = int(kwargs.get("max_body_chars", 4000))
        body_truncated = len(body) > max_body
        if body_truncated:
            body = body[:max_body]

        payload = {
            "status": response.status_code,
            "headers": {k: v for k, v in response.headers.items()},
            "body": body,
            "body_truncated": body_truncated,
            "url": url,
            "method": method,
        }
        return ToolResult(
            stdout=json.dumps(payload, ensure_ascii=False),
            exit_code=0 if response.status_code < 500 else 1,
            metadata={"status": response.status_code},
        )
