"""Agent-invoker tools — expose sub-agents as BaseTool instances for the Dispatcher.

The v2 Dispatcher does NOT hold references to each concrete sub-agent
directly. Instead, every sub-agent is wrapped as a :class:`BaseTool` that
the Dispatcher can discover and call like any other tool (nmap, curl, …).
That gives the supervisor a single uniform interface and lets Sprint 6 add
tool-call gating without touching the sub-agents themselves.

Conventions:

- Every tool reads upstream state from ``Blackboard.phase_context`` (which
  the runner pre-populates during intake) and writes its output back into
  the same dict so later tools can consume it.
- The value the dispatcher receives (as ``ToolMessage.content``) is a
  short summary, never the full object. Full detail lives on the
  blackboard (artifacts / evidence) so the report agent has everything.
- Failures return a non-zero ``exit_code`` ToolResult — they do NOT raise.
  The dispatcher LLM is expected to read the error and pivot.

The tools do NOT instantiate the sub-agent classes themselves. A small
:class:`AgentInvoker` closure is passed in at construction time so tests
can drop in fakes without touching dependency wiring.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Type

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult
from vapt_orchestrator_safe.types import CandidatePoC, Hypothesis, ValidationResult


# A callable that, given a phase-context dict, produces a result. Using a
# plain callable (not the BaseAgent type) keeps the tool classes
# framework-agnostic and trivial to mock in unit tests.
AgentInvoker = Callable[[Dict[str, Any]], Any]


# ── Shared helper ─────────────────────────────────────────────────────────
def _intake_ctx(blackboard) -> Dict[str, Any]:
    """Return the intake slice of phase_context (manifest/transcript/...)."""
    return blackboard.get_phase_context("intake")


def _phase(blackboard, name: str) -> Dict[str, Any]:
    return blackboard.get_phase_context(name)


# ── Recon ─────────────────────────────────────────────────────────────────
class _ReconArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    focus: Optional[str] = Field(
        default=None,
        description="Optional free-text hint on what the dispatcher wants the recon agent to emphasise (e.g. 'authorization')."
    )


class InvokeReconTool(BaseTool):
    """Run the Recon sub-agent over the fixture loaded at intake.

    Reads transcript + source files from ``phase_context['intake']``,
    writes the recon output into ``phase_context['recon']`` so downstream
    tools (signature / analyst) can pick it up.
    """
    name: str = "invoke_recon"
    description: str = (
        "Enumerate the attack surface of the fixture under test: routes, "
        "parameters, auth surface, source-level indicators. Call this first."
    )
    args_schema: Type[BaseModel] = _ReconArgs

    _invoker: AgentInvoker = PrivateAttr()

    def __init__(self, invoker: AgentInvoker, **data: Any):
        super().__init__(**data)
        self._invoker = invoker

    def _invoke(self, **kwargs: Any) -> ToolResult:
        bb = self._blackboard
        intake = _intake_ctx(bb)
        if not intake:
            return ToolResult(
                stderr="Intake has not been loaded yet; blackboard phase_context['intake'] is empty.",
                exit_code=2,
            )
        recon = self._invoker({
            "transcript": intake["transcript"],
            "source_files": intake["source_files"],
            "focus": kwargs.get("focus"),
        })
        bb.set_phase_context("recon", recon)
        summary = {
            "routes": len(recon.get("route_map", [])),
            "parameters": recon.get("parameters", []),
            "auth_surface": recon.get("auth_surface", False),
            "source_indicators": recon.get("source_indicators", []),
        }
        return ToolResult(stdout=json.dumps(summary))


# ── Signature (keyword RAG over the compressed KB) ───────────────────────
class _SignatureArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    extra_terms: Optional[List[str]] = Field(
        default=None,
        description="Optional extra query terms to mix into the RAG search."
    )


class InvokeSignatureTool(BaseTool):
    name: str = "invoke_signature"
    description: str = (
        "Retrieve compressed signature cards from the knowledge base that "
        "match the current recon output. Run AFTER invoke_recon."
    )
    args_schema: Type[BaseModel] = _SignatureArgs

    _invoker: AgentInvoker = PrivateAttr()

    def __init__(self, invoker: AgentInvoker, **data: Any):
        super().__init__(**data)
        self._invoker = invoker

    def _invoke(self, **kwargs: Any) -> ToolResult:
        bb = self._blackboard
        intake = _intake_ctx(bb)
        recon = _phase(bb, "recon")
        if not recon:
            return ToolResult(
                stderr="Recon has not been run; call invoke_recon first.",
                exit_code=2,
            )
        sig = self._invoker({
            "recon": recon,
            "transcript": intake.get("transcript", {}),
            "extra_terms": kwargs.get("extra_terms") or [],
        })
        bb.set_phase_context("signature", sig)
        return ToolResult(stdout=json.dumps({
            "cards": [
                {"family": c.get("attack_family"), "score": c.get("score")}
                for c in sig.get("cards", [])
            ]
        }))


# ── Analyst (ranked hypotheses) ──────────────────────────────────────────
class _AnalystArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")


class InvokeAnalystTool(BaseTool):
    name: str = "invoke_analyst"
    description: str = (
        "Produce a ranked list of attack hypotheses from the recon + signature "
        "outputs. Run AFTER invoke_recon and invoke_signature."
    )
    args_schema: Type[BaseModel] = _AnalystArgs

    _invoker: AgentInvoker = PrivateAttr()

    def __init__(self, invoker: AgentInvoker, **data: Any):
        super().__init__(**data)
        self._invoker = invoker

    def _invoke(self, **kwargs: Any) -> ToolResult:
        bb = self._blackboard
        intake = _intake_ctx(bb)
        recon = _phase(bb, "recon")
        signature = _phase(bb, "signature")
        if not recon or not signature:
            return ToolResult(
                stderr="Missing prerequisite phase context (recon/signature).",
                exit_code=2,
            )
        hypotheses: List[Hypothesis] = self._invoker({
            "manifest": intake.get("manifest", {}),
            "recon": recon,
            "signature": signature,
        })
        bb.set_phase_context("analysis", {"hypotheses": list(hypotheses)})
        return ToolResult(stdout=json.dumps([
            {"attack_family": h.attack_family, "confidence": h.confidence}
            for h in hypotheses
        ]))


# ── Exploit + Validator (paired, per hypothesis) ─────────────────────────
class _ExploitArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    attack_family: str = Field(
        description="Which attack family to attempt from the analyst's hypothesis list (e.g. IDOR, SSRF, SQLi)."
    )


class InvokeExploitTool(BaseTool):
    name: str = "invoke_exploit"
    description: str = (
        "Generate a candidate PoC for ONE attack family picked from the analyst "
        "hypotheses, then immediately validate it against the fixture's oracle."
    )
    args_schema: Type[BaseModel] = _ExploitArgs

    _exploit: AgentInvoker = PrivateAttr()
    _validator: AgentInvoker = PrivateAttr()

    def __init__(
        self,
        exploit_invoker: AgentInvoker,
        validator_invoker: AgentInvoker,
        **data: Any,
    ):
        super().__init__(**data)
        self._exploit = exploit_invoker
        self._validator = validator_invoker

    def _invoke(self, **kwargs: Any) -> ToolResult:
        bb = self._blackboard
        intake = _intake_ctx(bb)
        analysis = _phase(bb, "analysis")
        hypotheses: List[Hypothesis] = analysis.get("hypotheses") or []
        if not hypotheses:
            return ToolResult(
                stderr="No hypotheses on blackboard; call invoke_analyst first.",
                exit_code=2,
            )

        target_family = kwargs["attack_family"]
        match = next((h for h in hypotheses if h.attack_family == target_family), None)
        if match is None:
            available = [h.attack_family for h in hypotheses]
            return ToolResult(
                stderr=f"No hypothesis for {target_family!r}. Available: {available}",
                exit_code=2,
            )

        poc: Optional[CandidatePoC] = self._exploit({
            "hypothesis": match,
            "manifest": intake.get("manifest", {}),
        })
        validation: ValidationResult = self._validator({
            "poc": poc,
            "ground_truth": intake.get("ground_truth", {}),
            "manifest": intake.get("manifest", {}),
        })

        existing = _phase(bb, "exploit").setdefault("validations", [])
        existing.append(validation)
        bb.set_phase_context("exploit", {"validations": existing})

        return ToolResult(stdout=json.dumps({
            "attack_family": validation.attack_family,
            "status": validation.status,
            "severity": validation.severity,
            "confidence": validation.confidence,
            "reasoning": validation.reasoning,
        }))


# ── Report ────────────────────────────────────────────────────────────────
class _ReportArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")


class InvokeReportTool(BaseTool):
    name: str = "invoke_report"
    description: str = (
        "Write the final markdown + JSON report from all validations accumulated "
        "so far. Call this last, when no more attacks are worth attempting."
    )
    args_schema: Type[BaseModel] = _ReportArgs

    _invoker: AgentInvoker = PrivateAttr()

    def __init__(self, invoker: AgentInvoker, **data: Any):
        super().__init__(**data)
        self._invoker = invoker

    def _invoke(self, **kwargs: Any) -> ToolResult:
        bb = self._blackboard
        intake = _intake_ctx(bb)
        exploit = _phase(bb, "exploit")
        validations = exploit.get("validations") or []
        report = self._invoker({
            "manifest": intake.get("manifest", {}),
            "validations": validations,
        })
        bb.set_phase_context("report", report)
        return ToolResult(stdout=json.dumps({
            "findings": len(report.get("findings", [])),
            "fixture_id": report.get("fixture_id"),
        }))


# ── Pivot (stub — full anti-loop wiring in Sprint 6) ─────────────────────
class _PivotArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    reason: str = Field(description="Short explanation of why the dispatcher is pivoting.")


class PivotTool(BaseTool):
    """Sentinel tool the dispatcher calls to abandon the current branch.

    Sprint 6 wires this to the anti-loop guard (C2): on pivot, the guard
    trims recent context, picks a different attack family, and resets the
    loop-signature buffer. Sprint 3 only ships the hook; calling it just
    logs and returns.
    """
    name: str = "pivot"
    description: str = (
        "Abandon the current line of attack and pick a different hypothesis. "
        "Call this when a strategy keeps failing or you detect you're looping."
    )
    args_schema: Type[BaseModel] = _PivotArgs

    def _invoke(self, **kwargs: Any) -> ToolResult:
        bb = self._blackboard
        reason = kwargs.get("reason", "unspecified")
        bb.reset_loop_signatures()
        bb.log_event("pivot", reason, {"source": "dispatcher"})
        return ToolResult(stdout=json.dumps({"pivoted": True, "reason": reason}))
