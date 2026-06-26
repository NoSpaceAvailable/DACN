"""BaseTool — wraps LangChain ``BaseTool`` with a structured result + Blackboard write.

Concrete tools subclass :class:`BaseTool` and implement ``_invoke(**kwargs) ->
ToolResult``. The subclass does NOT override ``_run`` directly; the base
class handles:

- Wall-clock timing (``duration_ms``).
- Auto-truncation of stdout/stderr fed back to the LLM (full payload still
  goes to the Blackboard ``artifacts`` list so the run report keeps it).
- Loop-signature push so the anti-loop guard (Sprint 6) can detect repeats.
- Uniform error envelope: exceptions become ``ToolResult(exit_code=-1,
  stderr=...)`` so the LLM sees a regular tool failure instead of an
  exception bubbling up.

Sprint 2 only ships the base + a couple of trivial tools used by tests
(:class:`EchoTool`). Real tools (nmap, sqlmap, curl, etc.) come in Sprint 4.
"""
from __future__ import annotations

import hashlib
import time
from abc import abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, Dict, Optional, Type

from langchain_core.tools import BaseTool as LCBaseTool
from pydantic import BaseModel, ConfigDict, PrivateAttr


_TRUNCATE_DEFAULT = 2000


class ToolError(RuntimeError):
    """Raised by tools when an unrecoverable setup error happens.

    Note: routine tool failures (non-zero exit, network error, etc.) do
    NOT raise — they are returned as ``ToolResult(exit_code != 0)`` so the
    LLM sees a normal "tool failed" message and can react.
    """


@dataclass
class ToolResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: int = 0
    truncated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def summary_for_llm(self, limit: int = _TRUNCATE_DEFAULT) -> str:
        """LLM-facing rendering. ponytail: tool output sent in full — let the
        model read what it needs. The ``limit`` arg is kept for API stability
        but no longer trims. The ``truncated`` flag remains accurate (set by
        ``BaseTool._run`` against the original ``truncate_at`` value) so callers
        can still observe whether the size threshold was crossed."""
        head = f"[exit={self.exit_code} t={self.duration_ms}ms]"
        body = self.stdout if self.exit_code == 0 else (self.stderr or self.stdout)
        return f"{head}\n{body}"


class BaseTool(LCBaseTool):
    """Project base for all DACN tools.

    Subclasses MUST set ``name``, ``description`` and (optional)
    ``args_schema``, and implement ``_invoke(**kwargs) -> ToolResult``.
    """

    # Per-class output truncation limit fed back to the LLM
    truncate_at: ClassVar[int] = _TRUNCATE_DEFAULT

    # pydantic v2 config — allow stashing the blackboard reference at runtime
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Blackboard is injected via :meth:`bind_blackboard`. Kept as a
    # PrivateAttr so pydantic doesn't try to validate it.
    _blackboard: Any = PrivateAttr(default=None)

    def bind_blackboard(self, blackboard: Any) -> "BaseTool":
        """Attach the run-scoped Blackboard so tool results land in artifacts."""
        self._blackboard = blackboard
        return self

    # ── subclass contract ─────────────────────────────────────────────────
    @abstractmethod
    def _invoke(self, **kwargs: Any) -> ToolResult:
        """Do the actual work; return a ToolResult.

        Subclasses raise ``ToolError`` only for unrecoverable setup problems
        (missing binary, missing env). Routine failures (exit != 0, timeout,
        protocol error) should be reported via the ToolResult fields.
        """
        raise NotImplementedError

    # ── LangChain hook ────────────────────────────────────────────────────
    def _run(self, *args: Any, **kwargs: Any) -> str:
        # If the LangChain runtime passes positional args, fold them into
        # the args_schema field names when possible. Most callers will use
        # keyword arguments via tool-calling.
        started = time.perf_counter()
        try:
            result = self._invoke(**kwargs)
        except ToolError:
            raise
        except Exception as exc:  # noqa: BLE001 — tool errors must not crash agent
            duration_ms = int((time.perf_counter() - started) * 1000)
            result = ToolResult(
                stdout="",
                stderr=f"{type(exc).__name__}: {exc}",
                exit_code=-1,
                duration_ms=duration_ms,
                metadata={"tool": self.name, "kwargs": _safe_repr(kwargs)},
            )
        else:
            if not isinstance(result, ToolResult):
                raise ToolError(
                    f"{type(self).__name__}._invoke must return ToolResult, "
                    f"got {type(result).__name__}"
                )
            if result.duration_ms == 0:
                result.duration_ms = int((time.perf_counter() - started) * 1000)

        # Truncation accounting (do not mutate full stdout — only the LLM view).
        full_len = len(result.stdout) + len(result.stderr)
        result.truncated = full_len > self.truncate_at

        self._record(kwargs, result)
        return result.summary_for_llm(limit=self.truncate_at)

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        # Default async impl: just call sync. Concrete tools that benefit
        # from async (e.g. httpx-based) may override.
        return self._run(*args, **kwargs)

    # ── internals ─────────────────────────────────────────────────────────
    def _record(self, kwargs: Dict[str, Any], result: ToolResult) -> None:
        bb = self._blackboard
        if bb is None:
            return
        # Full payload to artifacts so the report agent has it.
        bb.add_artifact(
            kind=f"tool:{self.name}",
            payload={
                "kwargs": _safe_repr(kwargs),
                "result": result.to_dict(),
            },
        )
        # Loop signature so anti-loop guard can detect repeats.
        sig = _loop_sig(self.name, kwargs)
        bb.push_loop_signature(sig)


def _loop_sig(tool_name: str, kwargs: Dict[str, Any]) -> str:
    """Stable hash of (tool, kwargs) for anti-loop tracking."""
    payload = repr(sorted((str(k), _safe_repr(v)) for k, v in kwargs.items()))
    h = hashlib.sha256(f"{tool_name}|{payload}".encode("utf-8")).hexdigest()[:16]
    return f"{tool_name}:{h}"


def _safe_repr(value: Any, limit: int = 256) -> str:
    try:
        text = repr(value)
    except Exception:  # noqa: BLE001
        text = f"<unrepr {type(value).__name__}>"
    return text if len(text) <= limit else text[:limit] + "...(trunc)"


# ── trivial tool used by tests ─────────────────────────────────────────────
class _EchoArgs(BaseModel):
    text: str
    times: int = 1


class EchoTool(BaseTool):
    """Echoes ``text`` back N times. Used in unit tests for the base class."""
    name: str = "echo"
    description: str = "Echo a string back N times. For testing only."
    args_schema: Type[BaseModel] = _EchoArgs

    def _invoke(self, **kwargs: Any) -> ToolResult:
        text = kwargs.get("text", "")
        times = int(kwargs.get("times", 1))
        if times < 0:
            return ToolResult(stderr="times must be >= 0", exit_code=2)
        return ToolResult(stdout=(text + "\n") * times)
