"""DispatcherRunner — end-to-end wiring: intake → Dispatcher → final summary.

Analogous to :class:`vapt_orchestrator_safe.engine.orchestrator.Orchestrator`
but built on the LLM-driven Dispatcher (v2 architecture). The legacy
``Orchestrator`` is kept in place as ``engine/orchestrator.py`` for
regression; both can coexist during the transition.

Responsibilities:

- Build the Blackboard for this run (pre-populated with intake payloads).
- Instantiate each existing sub-agent (reusing Sprint 1 ``BaseAgent``
  implementations) and wrap them as :class:`AgentInvoker` closures so the
  dispatcher tools can call them without knowing the concrete types.
- Resolve an LLM backend via :mod:`llm.backend_factory` (LangChain
  abstraction so Ollama / OpenAI / Anthropic / OpenRouter are swappable
  through a single env var).
- Run the dispatcher on a natural-language goal and write run_summary.json.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from vapt_orchestrator_safe.agents.analyst import AnalystAgent
from vapt_orchestrator_safe.agents.base import AgentDependencies
from vapt_orchestrator_safe.agents.exploit import ExploitAgent
from vapt_orchestrator_safe.agents.intake import IntakeAgent
from vapt_orchestrator_safe.agents.recon import ReconAgent
from vapt_orchestrator_safe.agents.report import ReportAgent
from vapt_orchestrator_safe.agents.signature import SignatureAgent
from vapt_orchestrator_safe.agents.validator import ValidatorAgent
from vapt_orchestrator_safe.config import DEFAULT_KB, DEFAULT_OUTPUTS, ROOT, load_profiles
from vapt_orchestrator_safe.engine.budget import BudgetTracker
from vapt_orchestrator_safe.engine.anti_loop import AntiLoopHook
from vapt_orchestrator_safe.engine.dispatcher import (
    Dispatcher,
    DispatcherHook,
    DispatcherResult,
)
from vapt_orchestrator_safe.engine.watchdogs import (
    DriftWatchdog,
    LoopWatchdog,
    ScopeWatchdog,
    Watchdog,
)
from vapt_orchestrator_safe.engine.router import ModelRouter
from vapt_orchestrator_safe.llm.registry import ModelRegistry, OllamaConfig
from vapt_orchestrator_safe.memory.rag import CompressedRAG
from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.prompts import load_prompt
from vapt_orchestrator_safe.sandbox.local_lab import LocalLabAdapter
from vapt_orchestrator_safe.dataset import Distiller
from vapt_orchestrator_safe.kg import InMemoryKG, build_default_kg
from vapt_orchestrator_safe.sandbox.docker_sandbox import DockerSandbox
from vapt_orchestrator_safe.tools.agent_tools import (
    InvokeAnalystTool,
    InvokeExploitTool,
    InvokeReconTool,
    InvokeReportTool,
    InvokeSignatureTool,
    PivotTool,
)
from vapt_orchestrator_safe.tools.analysis_tools import ReadSourceTool, RecordFindingTool
from vapt_orchestrator_safe.tools.cve_tool import QueryCveTool
from vapt_orchestrator_safe.tools.ghsa_tool import QueryGhsaTool
from vapt_orchestrator_safe.tools.kg_tools import QueryKGTool, QueryRAGTool
from vapt_orchestrator_safe.tools.sandbox_exec import RunPythonInSandboxTool
from vapt_orchestrator_safe.tools.security import (
    BlindTimingSampler,
    CurlTool,
    HashcatTool,
    HttpProbeTool,
    NmapTool,
    Z3ConstraintSolver,
)
from vapt_orchestrator_safe.utils.scope import Scope, ScopeGuard
from vapt_orchestrator_safe.types import ModelProfile
from vapt_orchestrator_safe.utils.io import ensure_dir, write_json


_DEFAULT_GOAL = (
    "Find and validate a web vulnerability in the fixture loaded in shared memory. "
    "Follow the recon → signature → analyst → exploit → report pipeline."
)


class DispatcherRunner:
    """Wires intake + sub-agents + dispatcher for a single fixture run."""

    def __init__(
        self,
        *,
        profile_set_name: str = "mixed_default",
        profiles_path: Optional[Path] = None,
        outputs_root: Optional[Path] = None,
        backend: str = "rule",
        ollama_config: Optional[OllamaConfig] = None,
        max_steps: int = 20,
        chat_model: Any = None,
        chat_model_backend_spec: Optional[str] = None,
        hook: Optional[DispatcherHook] = None,
        enable_security_tools: bool = True,
        enable_sandbox: bool = True,
        enable_anti_loop: bool = True,
        anti_loop_threshold: int = 3,
        enable_kg: bool = True,
        kg: Optional[Any] = None,
        enable_specialized_tools: bool = True,
        enable_mid_thinking: bool = False,
        mid_thinking_focus: Optional[List[str]] = None,
        mid_thinking_max_drift_chars: int = 1200,
        require_report: bool = True,
        enable_source_analysis: bool = True,
        call_delay_s: float = 0.0,
        require_source_read: bool = False,
    ):
        loaded = load_profiles(profiles_path)
        if profile_set_name not in loaded.profile_sets:
            raise ValueError(
                f"Unknown profile set {profile_set_name!r}; "
                f"available: {sorted(loaded.profile_sets)}"
            )
        self.outputs_root = ensure_dir(outputs_root or DEFAULT_OUTPUTS)
        self.profile_set_name = profile_set_name
        self.profile_set = loaded.profile_sets[profile_set_name]
        self.profiles: Dict[str, ModelProfile] = {
            name: ModelProfile(name=name, **values) for name, values in loaded.profiles.items()
        }
        self.router = ModelRouter(self.profiles, self.profile_set)
        self.model_registry = ModelRegistry(
            self.profiles, backend=backend, ollama_config=ollama_config
        )
        self.rag = CompressedRAG(DEFAULT_KB)
        self.lab = LocalLabAdapter(ROOT)
        self.max_steps = max_steps
        self.hook = hook

        self._chat_model = chat_model
        self._chat_model_backend_spec = chat_model_backend_spec or "injected"
        self.enable_security_tools = enable_security_tools
        self.enable_sandbox = enable_sandbox
        self.enable_anti_loop = enable_anti_loop
        self.anti_loop_threshold = anti_loop_threshold
        self.enable_kg = enable_kg
        self._kg_override = kg
        self.enable_specialized_tools = enable_specialized_tools
        self.enable_mid_thinking = enable_mid_thinking
        self.require_report = require_report
        self.enable_source_analysis = enable_source_analysis
        self.call_delay_s = call_delay_s
        self.require_source_read = require_source_read
        self.mid_thinking_focus = mid_thinking_focus or []
        self.mid_thinking_max_drift_chars = mid_thinking_max_drift_chars

    # ── public API ───────────────────────────────────────────────────────
    def run_fixture(self, fixture_dir: Path, *, goal: Optional[str] = None) -> Dict[str, Any]:
        fixture_dir = fixture_dir.resolve()
        started_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = ensure_dir(
            self.outputs_root / f"{fixture_dir.name}_dispatcher_{self.profile_set_name}_{started_at}"
        )
        budget = BudgetTracker()
        budget.start()

        blackboard = Blackboard(run_id=run_dir.name, run_dir=run_dir)
        deps = AgentDependencies(
            router=self.router,
            model_registry=self.model_registry,
            memory=blackboard,
            budget=budget,
        )

        # Intake still runs procedurally — it only loads files, no LLM needed.
        intake = IntakeAgent(deps, self.lab).run(fixture_dir)
        blackboard.set_phase_context("intake", intake)
        limits = intake["manifest"].get("budget", {})
        budget.max_tool_calls = int(limits.get("tool_calls", budget.max_tool_calls))
        budget.max_time_seconds = int(limits.get("time_seconds", budget.max_time_seconds))
        budget.max_simulated_cost = float(limits.get("simulated_usd", budget.max_simulated_cost))
        blackboard.set_budget(budget.to_dict())

        # Instantiate sub-agents once; wrap as AgentInvoker closures.
        recon_agent = ReconAgent(deps)
        signature_agent = SignatureAgent(deps, self.rag)
        analyst_agent = AnalystAgent(deps)
        exploit_agent = ExploitAgent(deps)
        validator_agent = ValidatorAgent(deps)
        report_agent = ReportAgent(deps)

        tools: List[Any] = [
            InvokeReconTool(
                lambda p: recon_agent.run(p["transcript"], p["source_files"]),
            ),
            InvokeSignatureTool(
                lambda p: signature_agent.run(p["recon"], p["transcript"]),
            ),
            InvokeAnalystTool(
                lambda p: analyst_agent.run(p["manifest"], p["recon"], p["signature"]),
            ),
            InvokeExploitTool(
                exploit_invoker=lambda p: exploit_agent.run(p["hypothesis"], p["manifest"]),
                validator_invoker=lambda p: validator_agent.run(
                    p["poc"], p["ground_truth"], p["manifest"],
                ),
            ),
            InvokeReportTool(
                lambda p: report_agent.run(p["manifest"], p["validations"], run_dir),
            ),
            PivotTool(),
        ]

        # LLM-driven source analysis (family-agnostic detection). Lets the
        # dispatcher read the real source and record findings of any class,
        # instead of relying on the 3 hardcoded heuristic families.
        if self.enable_source_analysis:
            tools.append(ReadSourceTool())
            tools.append(RecordFindingTool())

        # Only attach security tools when the fixture opts in via a manifest scope
        # block. Static source-only fixtures (challenge_idor_01 etc.) never need
        # nmap/curl/http_probe — the dispatcher plans purely over the loaded files.
        scope_declared = bool(intake["manifest"].get("scope"))
        if self.enable_security_tools and scope_declared:
            scope_guard = ScopeGuard(Scope.from_manifest(intake["manifest"]))
            tools.extend([
                NmapTool(scope=scope_guard),
                CurlTool(scope=scope_guard),
                HttpProbeTool(scope=scope_guard),
            ])
            blackboard.log_event(
                "dispatcher_runner", "security_tools.enabled",
                {"tools": ["nmap_scan", "curl_request", "http_probe"]},
            )

        # Specialized tools (Sprint 7): blind timing, Z3 solver, hashcat.
        # Attached when enabled — Z3 and hashcat don't need scope; timing
        # does (it sends HTTP requests).
        if self.enable_specialized_tools:
            specialized_names = []
            if scope_declared:
                tools.append(BlindTimingSampler(scope=scope_guard if scope_declared else None))
                specialized_names.append("blind_timing")
            tools.append(Z3ConstraintSolver())
            specialized_names.append("z3_solve")
            tools.append(HashcatTool())
            specialized_names.append("hashcat_crack")
            if specialized_names:
                blackboard.log_event(
                    "dispatcher_runner", "specialized_tools.enabled",
                    {"tools": specialized_names},
                )

        # Sandbox runs offline by default; attach unconditionally so the LLM can
        # always do crypto / parsing work without a network target.
        if self.enable_sandbox:
            tools.append(RunPythonInSandboxTool(sandbox=DockerSandbox()))

        # Knowledge-graph + vector RAG tools (C3). The KG defaults to
        # InMemoryKG seeded by build_default_kg so the dispatcher has
        # something useful to query out-of-the-box; Sprint 8 loads a real
        # corpus. Real Neo4j is opt-in: pass `kg=Neo4jKG(...)` explicitly.
        if self.enable_kg:
            kg = self._kg_override
            if kg is None:
                kg = InMemoryKG()
                build_default_kg(kg)
                distiller = Distiller.from_seed()
                # Auto-merge a distilled external corpus (e.g. HackTricks via
                # scripts/distill_hacktricks.py) when present. Absent = no-op,
                # so eval still works out-of-the-box on the seed corpus alone.
                corpus_path = ROOT / "data" / "corpus" / "hacktricks.jsonl"
                if corpus_path.exists():
                    distiller = distiller.merge(Distiller.from_jsonl(corpus_path))
                distiller.populate_kg(kg)
            blackboard.kg_handle = kg
            nodes, edges = kg.size()
            blackboard.log_event("dispatcher_runner", "kg.enabled",
                                 {"nodes": nodes, "edges": edges})
            tools.append(QueryKGTool(kg))
            tools.append(QueryRAGTool(self.rag))
            # Online CVE lookup (NVD API). Cached on disk so repeat bench runs
            # are deterministic. Closes the gap where a fixture pins a specific
            # component+version (e.g. nginx 1.17.6) and the local KG/RAG has no
            # CVE row for that exact (component, version range).
            tools.append(QueryCveTool())
            # GitHub Advisory Database — strong for package-ecosystem vulns
            # (npm/pip/maven/etc) where the package@version → patched-version
            # mapping is cleaner than NVD's CPE rows.
            tools.append(QueryGhsaTool())

        chat_model = self._chat_model
        if chat_model is None:
            chat_model, backend_spec = _build_dispatcher_chat_model()
            self._chat_model_backend_spec = backend_spec

        # Compose the supervisor hook: caller-supplied hook (if any) takes
        # precedence over the anti-loop hook. Sprint 5 ablation (`enable_anti_loop
        # =False`) lets the eval matrix compare loop rates with/without C2.
        effective_hook = self.hook
        if effective_hook is None and self.enable_anti_loop:
            effective_hook = AntiLoopHook(blackboard, threshold=self.anti_loop_threshold)
            blackboard.log_event(
                "dispatcher_runner", "anti_loop.enabled",
                {"threshold": self.anti_loop_threshold},
            )

        # C1 mid-thinking watchdogs (opt-in — requires a streaming-capable
        # chat model). Default OFF so the non-streaming test backends keep
        # working; benchmark / thesis demo enable it via the CLI flag.
        watchdogs: List[Watchdog] = []
        if self.enable_mid_thinking:
            focus = list(self.mid_thinking_focus) or self._default_focus(intake)
            watchdogs.append(DriftWatchdog(
                focus_keywords=focus,
                max_drift_chars=self.mid_thinking_max_drift_chars,
            ))
            if scope_declared:
                watchdogs.append(ScopeWatchdog(ScopeGuard(Scope.from_manifest(intake["manifest"]))))
            watchdogs.append(LoopWatchdog(blackboard, threshold=self.anti_loop_threshold))
            blackboard.log_event(
                "dispatcher_runner", "mid_thinking.enabled",
                {"watchdogs": [w.name for w in watchdogs], "focus": focus},
            )

        dispatcher = Dispatcher(
            chat_model=chat_model,
            tools=tools,
            blackboard=blackboard,
            system_prompt=load_prompt("dispatcher"),
            max_steps=self.max_steps,
            hook=effective_hook,
            watchdogs=watchdogs or None,
            require_report=self.require_report,
            call_delay_s=self.call_delay_s,
            require_source_read=(
                self.require_source_read
                and self.enable_source_analysis
                and bool(intake.get("source_files"))
            ),
        )
        result: DispatcherResult = dispatcher.run(goal or _DEFAULT_GOAL)

        return self._finalise(
            blackboard=blackboard,
            run_dir=run_dir,
            intake=intake,
            result=result,
            budget=budget,
            watchdog_trips=list(dispatcher.watchdog_trips),
        )

    @staticmethod
    def _default_focus(intake: Dict[str, Any]) -> List[str]:
        """Derive a sensible default focus keyword list from the fixture manifest."""
        manifest = intake.get("manifest", {}) or {}
        skills = manifest.get("skills", []) or []
        tags: List[str] = [manifest.get("id", ""), manifest.get("title", "")]
        tags.extend(str(s) for s in skills)
        scope_block = manifest.get("scope") or {}
        tags.extend(scope_block.get("allow_hosts") or [])
        return [t for t in tags if t]

    # ── helpers ──────────────────────────────────────────────────────────
    def _finalise(
        self,
        *,
        blackboard: Blackboard,
        run_dir: Path,
        intake: Dict[str, Any],
        result: DispatcherResult,
        budget: BudgetTracker,
        watchdog_trips: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        report_ctx = blackboard.get_phase_context("report")
        exploit_ctx = blackboard.get_phase_context("exploit")
        findings_ctx = blackboard.get_phase_context("findings") or {}
        llm_findings = findings_ctx.get("items", [])
        validations = exploit_ctx.get("validations") or []
        validated = [v for v in validations if v.status in {"verified", "supported"}]
        overall = (
            "validated" if any(v.status == "verified" for v in validations)
            else "supported" if any(v.status == "supported" for v in validations)
            else "no_validated_findings"
        )
        blackboard.set_budget(budget.to_dict())
        blackboard.persist()
        summary = {
            "fixture_id": intake["manifest"]["id"],
            "title": intake["manifest"]["title"],
            "profile_set": self.profile_set_name,
            "backend": self._chat_model_backend_spec,
            "pipeline": "dispatcher",
            "status": overall,
            "stop_reason": result.stop_reason,
            "steps": result.steps,
            "tool_invocations": result.tool_invocations,
            "watchdog_trips": watchdog_trips or [],
            "llm_findings": llm_findings,
            "final_text": result.final_text,
            "validated_findings": [
                {
                    "attack_family": v.attack_family,
                    "severity": v.severity,
                    "status": v.status,
                    "confidence": v.confidence,
                }
                for v in validated
            ],
            "budget": budget.to_dict(),
            "output_dir": str(run_dir),
            "report": report_ctx or None,
        }
        write_json(run_dir / "run_summary.json", summary)
        return summary


def _build_dispatcher_chat_model():
    """Resolve the dispatcher's chat model from env (LLM_BACKEND_DISPATCHER / _DEFAULT)."""
    from vapt_orchestrator_safe.llm.backend_factory import build_for_role

    spec, model = build_for_role("dispatcher")
    return model, spec
