"""ShellTool — subclass for any tool that shells out to a binary.

Wraps ``subprocess.run`` with:

- explicit argv construction (no ``shell=True`` — avoids injection),
- wall-clock timeout with clean kill,
- stdout/stderr capture into :class:`ToolResult` (truncation happens in
  the base class),
- optional working directory override,
- optional environment merge (default: inherits PATH but strips nothing).

Concrete tools (NmapTool, CurlTool, …) subclass this and only implement
:meth:`build_argv` — they don't have to deal with process lifecycle at
all. ShellTool never itself decides whether a target is legal — that's
always the job of the concrete tool, which should hold a
:class:`~vapt_orchestrator_safe.utils.scope.ScopeGuard` and call it
before returning the argv.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from abc import abstractmethod
from typing import Any, Dict, List, Optional, Sequence

from pydantic import PrivateAttr

from vapt_orchestrator_safe.tools.base import BaseTool, ToolError, ToolResult
from vapt_orchestrator_safe.utils.scope import ScopeGuard


_DEFAULT_TIMEOUT = 30  # seconds — concrete tools override per-run


class ShellTool(BaseTool):
    """Base for tools that shell out. Subclasses implement :meth:`build_argv`."""

    binary: str = "true"          # subclasses set this to "nmap", "curl", etc.
    default_timeout: int = _DEFAULT_TIMEOUT

    _scope: Optional[ScopeGuard] = PrivateAttr(default=None)

    def __init__(self, scope: Optional[ScopeGuard] = None, **data: Any):
        super().__init__(**data)
        self._scope = scope

    # ── subclass contract ────────────────────────────────────────────────
    @abstractmethod
    def build_argv(self, **kwargs: Any) -> Sequence[str]:
        """Return the argv to execute. Concrete tools must call
        ``self._scope.check_*(...)`` on any user-supplied target here
        before returning the command.
        """
        raise NotImplementedError

    # ── BaseTool hook ────────────────────────────────────────────────────
    def _invoke(self, **kwargs: Any) -> ToolResult:
        if shutil.which(self.binary) is None:
            raise ToolError(
                f"Binary {self.binary!r} not found on PATH; cannot run tool {self.name!r}."
            )

        argv = list(self.build_argv(**kwargs))
        timeout = int(kwargs.pop("_timeout", self.default_timeout))
        cwd = kwargs.pop("_cwd", None)

        started = time.perf_counter()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            return ToolResult(
                stdout=(exc.stdout or b"").decode("utf-8", "replace")
                if isinstance(exc.stdout, (bytes, bytearray))
                else (exc.stdout or ""),
                stderr=f"TIMEOUT after {timeout}s while running {argv[0]}",
                exit_code=124,  # conventional timeout exit
                duration_ms=duration_ms,
                metadata={"argv": argv, "timeout": timeout},
            )

        duration_ms = int((time.perf_counter() - started) * 1000)
        return ToolResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            duration_ms=duration_ms,
            metadata={"argv": argv},
        )
