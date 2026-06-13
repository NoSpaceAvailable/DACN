"""Source-analysis tools — let the Dispatcher LLM genuinely detect bugs.

The legacy ``invoke_recon`` path runs rule-based heuristics (a handful of
regexes) and the exploit agent only knows IDOR/SSRF/SQLi. These two tools
instead put the *LLM* in the analysis loop:

- ``read_source`` — the model reads the actual target source code, so it can
  reason about vulnerabilities of ANY class (not just the three hardcoded
  families).
- ``record_finding`` — the model logs each vulnerability it discovers
  (class, location, why it is exploitable, severity, suggested PoC). Findings
  accumulate on the Blackboard and surface in ``run_summary.json``.

This is family-agnostic detection grounded by the HackTricks knowledge graph
(``query_kg``), as opposed to fixture-tuned pattern matching.
"""
from __future__ import annotations

import json
from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, ConfigDict, Field

from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


_MAX_FILE_CHARS = 6000


def _source_files(blackboard) -> List[Dict[str, Any]]:
    intake = blackboard.get_phase_context("intake") or {}
    return intake.get("source_files", []) or []


# ── read_source ────────────────────────────────────────────────────────────
_MAX_ALL_CHARS = 24000  # budget when returning every file at once


class _ReadSourceArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    path: Optional[str] = Field(
        default=None,
        description="Read ONE file in full. Omit to get ALL source files at once (preferred — "
                    "one call instead of many).",
    )
    max_chars: int = Field(
        default=_MAX_FILE_CHARS,
        description="Per-file truncation limit.",
    )


class ReadSourceTool(BaseTool):
    name: str = "read_source"
    description: str = (
        "Read the target application's source code to analyse it for vulnerabilities. "
        "Call with NO arguments to get ALL source files in one response (do this first — "
        "it is one call, not many). Optionally pass path=<file> to re-read a single file. "
        "Find bugs of ANY class by reading the code yourself."
    )
    args_schema: Type[BaseModel] = _ReadSourceArgs
    # Source must reach the model intact; BaseTool's 2000-char default would
    # clip it. Compaction shrinks the resent copies on later steps.
    truncate_at: ClassVar[int] = _MAX_ALL_CHARS + 4000

    def _invoke(self, **kwargs: Any) -> ToolResult:
        files = _source_files(self._blackboard)
        if not files:
            return ToolResult(stderr="No source files available for this target.", exit_code=2)

        path = kwargs.get("path")
        per_file = int(kwargs.get("max_chars", _MAX_FILE_CHARS))

        if not path:
            # Batch: return every file at once (fewer round-trips). Spread the
            # total budget across files so one huge file can't starve the rest.
            budget = _MAX_ALL_CHARS
            share = max(800, budget // max(1, len(files)))
            blocks = []
            for f in files:
                content = f.get("content", "")
                cap = min(per_file, share)
                truncated = len(content) > cap
                body = content[:cap] + ("\n... (truncated)" if truncated else "")
                blocks.append({"path": f.get("path", "?"), "truncated": truncated, "content": body})
            return ToolResult(stdout=json.dumps(
                {"files": blocks, "count": len(blocks), "mode": "all"}, ensure_ascii=False))

        # Single file (exact path or suffix match).
        match = next(
            (f for f in files if f.get("path") == path or str(f.get("path", "")).endswith(path)),
            None,
        )
        if match is None:
            avail = [f.get("path", "?") for f in files]
            return ToolResult(stderr=f"No source file matching {path!r}. Available: {avail}", exit_code=2)
        content = match.get("content", "")
        truncated = len(content) > per_file
        body = content[:per_file] + ("\n... (truncated)" if truncated else "")
        return ToolResult(stdout=json.dumps(
            {"path": match.get("path"), "truncated": truncated, "content": body}, ensure_ascii=False))


# ── record_finding ───────────────────────────────────────────────────────--
class _RecordFindingArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    vuln_class: str = Field(description="Vulnerability class, e.g. LFI, SSRF, SQLi, AuthBypass, RCE, XSS, SSTI.")
    location: str = Field(description="Where the bug is: file path and/or function/line, e.g. utils.py:filter.")
    description: str = Field(description="Concise explanation of the bug and why it is exploitable.")
    severity: str = Field(default="medium", description="critical | high | medium | low.")
    suggested_poc: str = Field(default="", description="Optional: the request/payload that would exploit it.")


class RecordFindingTool(BaseTool):
    name: str = "record_finding"
    description: str = (
        "Record ONE vulnerability you have found by analysing the source/traffic. "
        "Call it once per distinct bug, with the class, location, why it is "
        "exploitable, severity, and a suggested PoC. Findings are collected into "
        "the final report."
    )
    args_schema: Type[BaseModel] = _RecordFindingArgs

    def _invoke(self, **kwargs: Any) -> ToolResult:
        bb = self._blackboard
        ctx = bb.get_phase_context("findings") or {}
        items: List[Dict[str, Any]] = list(ctx.get("items", []))
        finding = {
            "vuln_class": kwargs.get("vuln_class", "Unknown"),
            "location": kwargs.get("location", ""),
            "description": kwargs.get("description", ""),
            "severity": kwargs.get("severity", "medium"),
            "suggested_poc": kwargs.get("suggested_poc", ""),
        }
        items.append(finding)
        bb.set_phase_context("findings", {"items": items})
        bb.log_event("analysis", "finding_recorded",
                     {"vuln_class": finding["vuln_class"], "location": finding["location"]})
        return ToolResult(stdout=json.dumps({"recorded": finding, "total_findings": len(items)}, ensure_ascii=False))
