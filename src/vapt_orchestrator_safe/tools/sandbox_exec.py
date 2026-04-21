"""RunPythonInSandboxTool — execute LLM-written Python in a throwaway Docker.

The dispatcher exposes this tool when a fixture needs code execution
(e.g. building an exploit, solving a crypto puzzle). The sandbox
defaults to ``--network=none`` so the script cannot reach anything
outside the container — agents that truly need network should request
``network="bridge"`` *and* the fixture scope must have a matching
``allow_hosts`` / ``allow_cidrs`` entry.

Tests mock the :class:`DockerSandbox` instance so CI can run without
docker installed. A real end-to-end run is gated behind an env flag
(see ``test_sandbox_exec_smoke.py``).
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional, Type

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from vapt_orchestrator_safe.sandbox.docker_sandbox import (
    DockerSandbox,
    SandboxError,
    SandboxResult,
)
from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


_MAX_SCRIPT_CHARS = 20_000


class _RunPyArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    script: str = Field(
        description="Python source to run. Executed inside an ephemeral container."
    )
    timeout: Optional[int] = Field(
        default=None, description="Override the default container timeout (seconds)."
    )
    env: Optional[Dict[str, str]] = Field(
        default=None,
        description="Extra environment variables to inject into the container.",
    )


class RunPythonInSandboxTool(BaseTool):
    name: str = "run_python_sandbox"
    description: str = (
        "Run a Python script in an ephemeral Docker sandbox "
        "(default network=none, read-only root, CPU/memory capped). "
        "Returns stdout / stderr / exit_code. Use to build exploits, parse "
        "payloads, or do crypto work. No persistent state between calls."
    )
    args_schema: Type[BaseModel] = _RunPyArgs

    _sandbox: DockerSandbox = PrivateAttr()

    def __init__(self, sandbox: Optional[DockerSandbox] = None, **data: Any):
        super().__init__(**data)
        self._sandbox = sandbox or DockerSandbox()

    def _invoke(self, **kwargs: Any) -> ToolResult:
        script = kwargs["script"]
        if not isinstance(script, str) or not script.strip():
            return ToolResult(stderr="script must be a non-empty string", exit_code=2)
        if len(script) > _MAX_SCRIPT_CHARS:
            return ToolResult(
                stderr=f"script too large ({len(script)} chars; max {_MAX_SCRIPT_CHARS})",
                exit_code=2,
            )

        try:
            result: SandboxResult = self._sandbox.run_python(
                script,
                timeout=kwargs.get("timeout"),
                env=kwargs.get("env"),
            )
        except SandboxError as exc:
            return ToolResult(stderr=f"SandboxError: {exc}", exit_code=-1)

        payload = {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_ms": result.duration_ms,
            "timed_out": result.timed_out,
            "container": result.container,
            "network": result.network,
        }
        # The wrapper's own stdout becomes the LLM-visible payload; the full
        # structured dict lives in artifacts via BaseTool._record(...).
        return ToolResult(
            stdout=json.dumps(payload, ensure_ascii=False),
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            metadata={"container": result.container, "network": result.network},
        )
