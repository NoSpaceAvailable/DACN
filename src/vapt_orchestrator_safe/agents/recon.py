"""Recon agent.

Two execution paths:

1. **LLM-driven** (when the configured backend exposes ``generate``,
   currently :class:`OllamaModel`): renders ``prompts/recon.md`` with the
   transcript and a truncated source snapshot, asks the model for one
   structured JSON object describing the attack surface, and normalises
   the response into the legacy dict shape that downstream agents
   (Signature, Analyst) already consume.

2. **Heuristic fallback** (when the model can't generate, or the LLM call
   raises, or the JSON cannot be parsed): the original regex/keyword
   logic from the inherited scaffold runs unchanged. This guarantees the
   pipeline still completes if the VPS is unreachable or the model
   returns garbage, and keeps the existing pytest fixtures green.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from vapt_orchestrator_safe.agents.base import BaseAgent
from vapt_orchestrator_safe.memory.evidence import EvidenceItem
from vapt_orchestrator_safe.prompts import render_prompt
from vapt_orchestrator_safe.utils.llm_json import extract_json


# ── heuristic constants (unchanged from inherited scaffold) ────────────────
ROUTE_HINTS = {
    "authorization": ["/api/invoices/", "/api/users/", "/api/orders/"],
    "ssrf": ["preview", "fetch", "webhook", "import", "url"],
    "sqli": ["/login", "search", "query", "id="],
}

# How much input we feed the LLM to keep the prompt under the model's
# context window comfortably. gemma4:e2b nominally supports 131k tokens but
# CPU inference cost grows with prompt length, so we trim aggressively.
_MAX_TRANSCRIPT_CHARS = 4000
_MAX_SOURCE_CHARS_PER_FILE = 1500
_MAX_SOURCE_TOTAL_CHARS = 6000


class ReconAgent(BaseAgent):
    role = "recon"

    def run(self, transcript: Dict[str, Any], source_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.charge()
        discovered, source_used = self._dispatch(transcript, source_files)
        self.deps.memory.add_evidence(
            EvidenceItem(
                evidence_id="recon-surface",
                phase="recon",
                summary=(
                    f"Discovered {len(discovered['route_map'])} routes, "
                    f"parameters {', '.join(discovered['parameters']) or 'none'}, "
                    f"and {len(discovered['source_indicators'])} source indicators. "
                    f"(source={source_used})"
                ),
                details={**discovered, "_recon_source": source_used},
                tags=["recon", "surface", source_used],
            )
        )
        self.log("Recon complete", {**discovered, "_source": source_used})
        return discovered

    # ── dispatch ──────────────────────────────────────────────────────────
    def _dispatch(self, transcript, source_files):
        """Try LLM if available; on any failure, fall back to heuristic."""
        if hasattr(self.model, "generate"):
            try:
                return self._llm_recon(transcript, source_files), "llm"
            except Exception as exc:  # noqa: BLE001 — we want broad fallback
                self.log(
                    "LLM recon failed, falling back to heuristic",
                    {"error": type(exc).__name__, "message": str(exc)[:200]},
                )
        return self._heuristic_recon(transcript, source_files), "heuristic"

    # ── LLM path ──────────────────────────────────────────────────────────
    def _llm_recon(self, transcript, source_files):
        prompt = render_prompt(
            "recon",
            transcript_json=_truncate(json.dumps(transcript, indent=2), _MAX_TRANSCRIPT_CHARS),
            source_summary=self._format_source(source_files),
        )
        # Disable thinking tokens: structured-output recon does not benefit
        # from chain-of-thought, and skipping them roughly halves CPU time
        # on gemma4-class models.
        result = self.model.generate(
            prompt,
            options={"temperature": 0.1, "num_ctx": 8192},
            think=False,
        )
        parsed = extract_json(result.text)
        if not isinstance(parsed, dict):
            raise ValueError(
                f"Recon LLM did not return a JSON object. First 200 chars: {result.text[:200]!r}"
            )
        return self._normalise(parsed)

    def _format_source(self, source_files):
        if not source_files:
            return "(no source files provided)"
        parts: List[str] = []
        budget = _MAX_SOURCE_TOTAL_CHARS
        for sf in source_files:
            if budget <= 0:
                parts.append(f"... ({len(source_files) - len(parts)} more files truncated)")
                break
            content = _truncate(sf.get("content", ""), min(_MAX_SOURCE_CHARS_PER_FILE, budget))
            block = f"### {sf.get('path', '?')}\n```\n{content}\n```"
            parts.append(block)
            budget -= len(block)
        return "\n\n".join(parts)

    def _normalise(self, llm_out: Dict[str, Any]) -> Dict[str, Any]:
        """Convert rich LLM JSON into the legacy dict downstream agents expect."""
        endpoints = llm_out.get("endpoints", []) or []
        route_map: List[str] = []
        params: set[str] = set()
        for ep in endpoints:
            method = str(ep.get("method", "GET")).upper()
            path = str(ep.get("path", "")).strip()
            if path:
                route_map.append(f"{method} {path}")
            for p in ep.get("params", []) or []:
                if isinstance(p, str) and p:
                    params.add(p)
        auth_surface_kind = str(llm_out.get("auth_surface", "unknown")).lower()
        # legacy field is bool: True if any auth presence detected.
        auth_surface = auth_surface_kind not in {"none", "unknown", ""}

        suspicious = llm_out.get("suspicious_patterns", []) or []
        source_indicators: List[str] = []
        for item in suspicious:
            if isinstance(item, dict) and item.get("id"):
                source_indicators.append(str(item["id"]))
            elif isinstance(item, str):
                source_indicators.append(item)

        return {
            "route_map": route_map,
            "parameters": sorted(params),
            "auth_surface": auth_surface,
            "source_indicators": sorted(set(source_indicators)),
            # Keep the rich payload for debugging / downstream enrichment;
            # downstream agents that don't know about it simply ignore it.
            "_llm_raw": llm_out,
        }

    # ── heuristic fallback (unchanged behaviour) ──────────────────────────
    def _heuristic_recon(self, transcript: Dict[str, Any], source_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        routes = transcript.get("routes", [])
        route_map = [f"{route['method']} {route['path']}" for route in routes]
        auth_surface = any(
            "auth" in obs.lower() or "token" in obs.lower()
            for obs in transcript.get("observations", [])
        )
        parameters: List[str] = []
        endpoints_text = " ".join(route_map).lower()
        if "url" in endpoints_text or "url" in str(transcript).lower():
            parameters.append("url")
        if any("invoice" in item.lower() for item in route_map):
            parameters.append("invoice_id")
        if any("login" in item.lower() for item in route_map):
            parameters.extend(["username", "password"])

        source_indicators: List[str] = []
        for source in source_files:
            content = source["content"]
            if re.search(r"SELECT.+\{.+\}", content, re.IGNORECASE | re.DOTALL):
                source_indicators.append("unsafe_sql_formatting")
            if "requests.get(url" in content or "fetch(url" in content:
                source_indicators.append("server_side_fetch_of_user_url")
            if "owner_id" in content and "check" not in content.lower():
                source_indicators.append("missing_ownership_check")

        return {
            "route_map": route_map,
            "parameters": sorted(set(parameters)),
            "auth_surface": auth_surface,
            "source_indicators": sorted(set(source_indicators)),
        }


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 30)] + "\n... (truncated)"
