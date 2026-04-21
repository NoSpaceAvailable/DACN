"""CurlTool — HTTP request via the curl binary, scope-gated.

Most "send HTTP and see what happens" use cases are better served by
:class:`vapt_orchestrator_safe.tools.security.http.HttpProbeTool`, which
uses the requests library and gives structured access to headers / body.
Keep CurlTool for cases where the LLM genuinely needs raw curl semantics
(e.g. exotic TLS flags, cookie jars, streaming).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Type

from pydantic import BaseModel, ConfigDict, Field

from vapt_orchestrator_safe.tools.shell import ShellTool


_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


class _CurlArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    url: str = Field(description="URL to fetch. Host must be in the fixture scope.")
    method: str = Field(default="GET", description="HTTP method (GET/POST/…).")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Additional request headers.")
    data: Optional[str] = Field(default=None, description="Request body (string).")
    max_time: int = Field(default=10, description="Request timeout in seconds.")


class CurlTool(ShellTool):
    name: str = "curl_request"
    description: str = (
        "Send one HTTP request via curl to an in-scope URL. Useful when you need "
        "raw curl semantics. For typical requests prefer http_probe."
    )
    args_schema: Type[BaseModel] = _CurlArgs
    binary: str = "curl"
    default_timeout: int = 15

    def build_argv(self, **kwargs: Any) -> Sequence[str]:
        url = kwargs["url"]
        method = str(kwargs.get("method", "GET")).upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError(f"Method {method!r} not allowed ({sorted(_ALLOWED_METHODS)})")
        if self._scope is not None:
            self._scope.check_url(url)

        argv: List[str] = [
            self.binary,
            "-sS",                                  # silent except errors
            "-L",                                   # follow redirects (still re-checked by scope? NO — see NOTE)
            "--max-time", str(int(kwargs.get("max_time", 10))),
            "--max-redirs", "3",
            "-i",                                   # include response headers in stdout
            "-X", method,
        ]
        # NOTE: curl's own redirect-following cannot be intercepted by ScopeGuard,
        # so we cap redirects hard (3) and let the caller inspect the final URL in
        # the response headers. Out-of-scope redirects will trip the guard on the
        # NEXT call, not this one.
        headers = kwargs.get("headers") or {}
        for key, value in headers.items():
            argv.extend(["-H", f"{key}: {value}"])
        body = kwargs.get("data")
        if body is not None:
            argv.extend(["--data-raw", body])
        argv.append(url)
        return argv
