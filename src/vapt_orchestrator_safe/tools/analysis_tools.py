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
from typing import Any, Dict, List, Optional, Type

from pydantic import BaseModel, ConfigDict, Field

from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


_MAX_FILE_CHARS = 6000


def _source_files(blackboard) -> List[Dict[str, Any]]:
    intake = blackboard.get_phase_context("intake") or {}
    return intake.get("source_files", []) or []


# ── read_source ────────────────────────────────────────────────────────────
class _ReadSourceArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    path: Optional[str] = Field(
        default=None,
        description="File path to read in full. Omit to list all available source files first.",
    )
    max_chars: int = Field(
        default=_MAX_FILE_CHARS,
        description="Truncate the returned file content to this many characters.",
    )


class ReadSourceTool(BaseTool):
    name: str = "read_source"
    description: str = (
        "Read the target application's source code so you can analyse it for "
        "vulnerabilities directly. Call with NO arguments to list every source "
        "file; then call with path=<file> to read one file's full contents. "
        "Use this to find bugs of ANY class by reading the code yourself."
    )
    args_schema: Type[BaseModel] = _ReadSourceArgs

    def _invoke(self, **kwargs: Any) -> ToolResult:
        files = _source_files(self._blackboard)
        if not files:
            return ToolResult(stderr="No source files available for this target.", exit_code=2)

        path = kwargs.get("path")
        if not path:
            index = [{"path": f.get("path", "?"), "bytes": len(f.get("content", ""))} for f in files]
            return ToolResult(stdout=json.dumps({"files": index, "count": len(index)}, ensure_ascii=False))

        # Match exact path or a suffix (model may pass just the file name).
        match = next(
            (f for f in files if f.get("path") == path or str(f.get("path", "")).endswith(path)),
            None,
        )
        if match is None:
            avail = [f.get("path", "?") for f in files]
            return ToolResult(
                stderr=f"No source file matching {path!r}. Available: {avail}",
                exit_code=2,
            )

        max_chars = int(kwargs.get("max_chars", _MAX_FILE_CHARS))
        content = match.get("content", "")
        truncated = len(content) > max_chars
        body = content[:max_chars] + ("\n... (truncated)" if truncated else "")
        payload = {"path": match.get("path"), "truncated": truncated, "content": body}
        return ToolResult(stdout=json.dumps(payload, ensure_ascii=False))


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
