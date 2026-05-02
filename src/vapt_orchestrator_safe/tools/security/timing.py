"""BlindTimingSampler -- detect blind injection via response-time side channel.

Addresses the headline gap shared by PentestGPT / Red-MIRROR / MAPTA /
VulnBot / AutoPT / PentestAgent: **0% success on blind SQL injection**.

The tool sends a pair of HTTP requests (baseline vs payload) and
compares wall-clock response times. A statistically significant delta
indicates the server executed a sleep/waitfor, confirming a blind
injection sink.

How it works:

1. Send ``samples`` baseline requests (with ``baseline_value``).
2. Send ``samples`` payload requests (with ``payload_value`` --
   typically containing ``SLEEP(N)`` / ``WAITFOR DELAY`` / ``pg_sleep``).
3. Compute the timing delta.  If ``delta > sleep_seconds * threshold``
   the tool reports ``is_vulnerable=True``.

Pure Python (``requests``), scope-gated, no subprocess.
"""
from __future__ import annotations

import json
import statistics
import time
from typing import Any, Dict, List, Optional, Type

import requests
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult
from vapt_orchestrator_safe.utils.scope import ScopeGuard


class _TimingArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    url: str = Field(
        description="Target URL with the injectable parameter in the query string or path.",
    )
    method: str = Field(default="GET", description="HTTP method (GET / POST).")
    param_name: str = Field(
        description="Name of the parameter being tested for blind injection.",
    )
    baseline_value: str = Field(
        description="Benign value for the parameter (no sleep).",
    )
    payload_value: str = Field(
        description=(
            "Payload value that triggers a server-side sleep if the sink is "
            "injectable (e.g. \"1' AND SLEEP(3)--\")."
        ),
    )
    inject_in: str = Field(
        default="query",
        description=(
            "Where to place the parameter: 'query' (URL query string), "
            "'body' (form-encoded body), or 'json' (JSON body)."
        ),
    )
    sleep_seconds: float = Field(
        default=3.0,
        description="Expected sleep duration embedded in the payload.",
    )
    samples: int = Field(
        default=3,
        description="Number of requests per phase (baseline and payload). Min 2, max 10.",
    )
    timeout: float = Field(
        default=15.0,
        description="Per-request timeout in seconds.",
    )
    headers: Optional[Dict[str, str]] = Field(default=None)
    threshold: float = Field(
        default=0.6,
        description=(
            "Fraction of sleep_seconds the delta must exceed to flag as "
            "vulnerable (default 0.6 = 60%%)."
        ),
    )


_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH"}
_INJECT_MODES = {"query", "body", "json"}
_MAX_SAMPLES = 10


class BlindTimingSampler(BaseTool):
    name: str = "blind_timing"
    description: str = (
        "Detect blind SQL injection (or similar time-based side channels) by "
        "comparing response times between a baseline request and a payload "
        "request that triggers a server-side sleep. Reports timing delta, "
        "statistical confidence, and a boolean is_vulnerable verdict."
    )
    args_schema: Type[BaseModel] = _TimingArgs

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
        self._session = session

    def _invoke(self, **kwargs: Any) -> ToolResult:
        url: str = kwargs["url"]
        method: str = str(kwargs.get("method", "GET")).upper()
        if method not in _ALLOWED_METHODS:
            return ToolResult(stderr=f"Method {method!r} not allowed", exit_code=2)

        inject_in: str = kwargs.get("inject_in", "query")
        if inject_in not in _INJECT_MODES:
            return ToolResult(stderr=f"inject_in must be one of {_INJECT_MODES}", exit_code=2)

        if self._scope is not None:
            self._scope.check_url(url)

        param_name: str = kwargs["param_name"]
        baseline_value: str = kwargs["baseline_value"]
        payload_value: str = kwargs["payload_value"]
        sleep_seconds: float = float(kwargs.get("sleep_seconds", 3.0))
        samples: int = min(max(int(kwargs.get("samples", 3)), 2), _MAX_SAMPLES)
        timeout: float = float(kwargs.get("timeout", 15.0))
        headers: Dict[str, str] = kwargs.get("headers") or {}
        threshold: float = float(kwargs.get("threshold", 0.6))

        requester = self._session.request if self._session is not None else requests.request

        baseline_times = self._sample(
            requester, url, method, param_name, baseline_value,
            inject_in, headers, timeout, samples,
        )
        payload_times = self._sample(
            requester, url, method, param_name, payload_value,
            inject_in, headers, timeout, samples,
        )

        baseline_avg = statistics.mean(baseline_times)
        payload_avg = statistics.mean(payload_times)
        delta = payload_avg - baseline_avg

        min_delta = sleep_seconds * threshold
        is_vulnerable = delta >= min_delta

        stdev_baseline = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.0
        stdev_payload = statistics.stdev(payload_times) if len(payload_times) > 1 else 0.0

        result_payload = {
            "param_name": param_name,
            "baseline_avg_ms": round(baseline_avg * 1000, 1),
            "payload_avg_ms": round(payload_avg * 1000, 1),
            "delta_ms": round(delta * 1000, 1),
            "stdev_baseline_ms": round(stdev_baseline * 1000, 1),
            "stdev_payload_ms": round(stdev_payload * 1000, 1),
            "sleep_seconds": sleep_seconds,
            "threshold": threshold,
            "min_delta_ms": round(min_delta * 1000, 1),
            "is_vulnerable": is_vulnerable,
            "samples": samples,
            "baseline_times_ms": [round(t * 1000, 1) for t in baseline_times],
            "payload_times_ms": [round(t * 1000, 1) for t in payload_times],
        }

        verdict = "VULNERABLE" if is_vulnerable else "not_vulnerable"

        return ToolResult(
            stdout=json.dumps(result_payload, ensure_ascii=False),
            exit_code=0,
            metadata={
                "is_vulnerable": is_vulnerable,
                "delta_ms": round(delta * 1000, 1),
                "verdict": verdict,
            },
        )

    @staticmethod
    def _sample(
        requester,
        url: str,
        method: str,
        param_name: str,
        param_value: str,
        inject_in: str,
        headers: Dict[str, str],
        timeout: float,
        samples: int,
    ) -> List[float]:
        times: List[float] = []
        for _ in range(samples):
            req_kwargs: Dict[str, Any] = {
                "method": method,
                "url": url,
                "headers": headers,
                "timeout": timeout,
                "allow_redirects": False,
            }
            if inject_in == "query":
                req_kwargs["params"] = {param_name: param_value}
            elif inject_in == "body":
                req_kwargs["data"] = {param_name: param_value}
            elif inject_in == "json":
                req_kwargs["json"] = {param_name: param_value}

            start = time.perf_counter()
            try:
                requester(**req_kwargs)
            except requests.RequestException:
                pass
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        return times
