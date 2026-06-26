"""grep_file — search saved scratch files for a regex pattern.

When a tool result (typically ``fetch_writeup`` on a large doc page) is
too big to keep re-reading in context, the result is also saved to a
scratch file under ``<run_dir>/scratch/``. The agent then uses this tool
to pull out only the lines that match a pattern, with surrounding
context — much cheaper than re-loading the whole doc.

Path safety: ``grep_file`` refuses paths outside ``<run_dir>/scratch/``.
The scratch dir is created on first write by the tool that saves it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, ClassVar, List, Optional, Type

from pydantic import BaseModel, ConfigDict, Field

from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


_DEFAULT_CONTEXT_LINES = 3
_DEFAULT_MAX_MATCHES = 30
_MAX_PATTERN_CHARS = 500


class _GrepFileArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    path: str = Field(
        description=(
            "Path to a scratch file (typically returned by fetch_writeup "
            "as `saved_to`). Must live under the run's scratch directory."
        )
    )
    pattern: str = Field(
        description=(
            "Python regex to match against each line. Case-insensitive by "
            "default. Anchor with ^ / $ if needed."
        )
    )
    context_lines: int = Field(
        default=_DEFAULT_CONTEXT_LINES,
        ge=0, le=20,
        description="Lines of surrounding context per match.",
    )
    max_matches: int = Field(
        default=_DEFAULT_MAX_MATCHES,
        ge=1, le=200,
        description="Stop after this many matches.",
    )
    case_sensitive: bool = Field(
        default=False,
        description="Default: case-insensitive matching.",
    )


class GrepFileTool(BaseTool):
    name: str = "grep_file"
    description: str = (
        "Search a scratch file (e.g. the full text of a fetched writeup "
        "saved to disk) for a regex pattern. Returns the matching line "
        "ranges with surrounding context. Use this when a fetched doc was "
        "too large to send inline — fetch_writeup tells you `saved_to=<path>` "
        "in that case. Cheaper than re-reading the whole page; you target "
        "exactly the section you need (e.g. pattern=`SCRIPT_NAME|HTTP_`)."
    )
    args_schema: Type[BaseModel] = _GrepFileArgs

    def _scratch_root(self) -> Optional[Path]:
        bb = self._blackboard
        if bb is None:
            return None
        run_dir = getattr(bb, "run_dir", None)
        if run_dir is None:
            return None
        return Path(run_dir) / "scratch"

    def _invoke(self, **kwargs: Any) -> ToolResult:
        raw_path = (kwargs.get("path") or "").strip()
        pattern = (kwargs.get("pattern") or "").strip()
        if not raw_path:
            return ToolResult(stderr="path is required.", exit_code=2)
        if not pattern:
            return ToolResult(stderr="pattern is required.", exit_code=2)
        if len(pattern) > _MAX_PATTERN_CHARS:
            return ToolResult(
                stderr=f"pattern too long ({len(pattern)} > {_MAX_PATTERN_CHARS})",
                exit_code=2,
            )

        scratch = self._scratch_root()
        if scratch is None:
            return ToolResult(
                stderr="grep_file requires a bound run scratch directory.",
                exit_code=1,
            )

        # Path safety: target must resolve under scratch root. Allow either
        # an absolute path or a relative-to-scratch one.
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = scratch / candidate
        try:
            target = candidate.resolve(strict=False)
            scratch_resolved = scratch.resolve(strict=False)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(stderr=f"Bad path {raw_path!r}: {exc}", exit_code=2)
        try:
            target.relative_to(scratch_resolved)
        except ValueError:
            return ToolResult(
                stderr=(
                    f"Path {raw_path!r} is outside the scratch root "
                    f"{scratch_resolved}. grep_file only reads scratch files."
                ),
                exit_code=2,
            )
        if not target.exists():
            return ToolResult(
                stderr=f"Scratch file not found: {target}", exit_code=2,
            )

        try:
            flags = 0 if kwargs.get("case_sensitive") else re.IGNORECASE
            rx = re.compile(pattern, flags)
        except re.error as exc:
            return ToolResult(stderr=f"Invalid regex: {exc}", exit_code=2)

        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return ToolResult(stderr=f"Read failed: {exc}", exit_code=1)

        lines = text.splitlines()
        ctx = int(kwargs.get("context_lines", _DEFAULT_CONTEXT_LINES))
        cap = int(kwargs.get("max_matches", _DEFAULT_MAX_MATCHES))

        # Find matches, merge overlapping windows.
        windows: List[tuple[int, int]] = []
        match_count = 0
        for i, line in enumerate(lines):
            if rx.search(line) is None:
                continue
            match_count += 1
            lo, hi = max(0, i - ctx), min(len(lines), i + ctx + 1)
            if windows and lo <= windows[-1][1]:
                windows[-1] = (windows[-1][0], max(windows[-1][1], hi))
            else:
                windows.append((lo, hi))
            if match_count >= cap:
                break

        if not windows:
            return ToolResult(
                stdout=f"No matches for {pattern!r} in {target.name}.",
                exit_code=0,
                metadata={"matches": 0, "path": str(target)},
            )

        blocks: List[str] = []
        for lo, hi in windows:
            block_lines = [f"{n + 1:>5}: {lines[n]}" for n in range(lo, hi)]
            blocks.append("\n".join(block_lines))

        body = "\n\n--- ---\n\n".join(blocks)
        head = (
            f"matches={match_count}{'+' if match_count >= cap else ''} "
            f"file={target.name} pattern={pattern!r}\n"
        )
        return ToolResult(
            stdout=head + body,
            exit_code=0,
            metadata={
                "matches": match_count,
                "windows": len(windows),
                "path": str(target),
            },
        )
