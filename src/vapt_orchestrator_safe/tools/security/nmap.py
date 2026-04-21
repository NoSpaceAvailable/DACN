"""NmapTool — TCP port scan, scope-gated.

Uses conservative defaults aligned with "local lab" use:

- ``-Pn`` (skip host discovery — the lab target is always up),
- ``-T4`` (sane timing — we're on localhost / docker bridge anyway),
- ``--top-ports 100`` (or explicit ``ports=`` list),
- ``-oX -`` XML to stdout so downstream agents can parse it if needed.

The target is always checked against the fixture's ``ScopeGuard`` before
the argv is returned — any host outside scope raises ``ScopeError``
(wrapped by :class:`BaseTool` into a ``ToolResult`` with ``exit_code=-1``
so the LLM sees a clear failure).
"""
from __future__ import annotations

from typing import Any, List, Optional, Sequence, Type

from pydantic import BaseModel, ConfigDict, Field

from vapt_orchestrator_safe.tools.shell import ShellTool


class _NmapArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target: str = Field(description="Host or IP to scan. Must be inside the fixture scope.")
    ports: Optional[List[int]] = Field(
        default=None,
        description="Explicit port list. If omitted, scans the top-100 common ports.",
    )
    version_scan: bool = Field(
        default=False,
        description="Add -sV for service/version detection (slower but useful).",
    )


class NmapTool(ShellTool):
    name: str = "nmap_scan"
    description: str = (
        "Run an nmap TCP port scan against one in-scope host. Returns XML output. "
        "Use for attack-surface enumeration when the fixture has an HTTP target."
    )
    args_schema: Type[BaseModel] = _NmapArgs
    binary: str = "nmap"
    default_timeout: int = 120  # nmap needs more time than curl/http

    def build_argv(self, **kwargs: Any) -> Sequence[str]:
        target = kwargs["target"]
        if self._scope is not None:
            self._scope.check_host(target)

        argv: List[str] = [self.binary, "-Pn", "-T4", "-oX", "-"]
        if kwargs.get("version_scan"):
            argv.append("-sV")

        ports = kwargs.get("ports")
        if ports:
            if self._scope is not None:
                for p in ports:
                    self._scope.check_port(int(p))
            argv.extend(["-p", ",".join(str(int(p)) for p in ports)])
        else:
            argv.extend(["--top-ports", "100"])

        argv.append(target)
        return argv
