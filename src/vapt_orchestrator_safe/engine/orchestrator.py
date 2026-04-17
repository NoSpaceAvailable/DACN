from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

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
from vapt_orchestrator_safe.engine.router import ModelRouter
from vapt_orchestrator_safe.llm.registry import ModelRegistry
from vapt_orchestrator_safe.memory.rag import CompressedRAG
from vapt_orchestrator_safe.memory.shared_memory import SharedMemory
from vapt_orchestrator_safe.sandbox.local_lab import LocalLabAdapter
from vapt_orchestrator_safe.types import ModelProfile
from vapt_orchestrator_safe.utils.io import ensure_dir, write_json


class Orchestrator:
    def __init__(self, profile_set_name: str, profiles_path: Path | None = None, outputs_root: Path | None = None):
        loaded = load_profiles(profiles_path)
        if profile_set_name not in loaded.profile_sets:
            available = ", ".join(sorted(loaded.profile_sets))
            raise ValueError(f"Unknown profile set '{profile_set_name}'. Available: {available}")
        self.outputs_root = ensure_dir(outputs_root or DEFAULT_OUTPUTS)
        self.profile_set_name = profile_set_name
        self.profile_set = loaded.profile_sets[profile_set_name]
        self.profiles: Dict[str, ModelProfile] = {
            name: ModelProfile(name=name, **values) for name, values in loaded.profiles.items()
        }
        self.router = ModelRouter(self.profiles, self.profile_set)
        self.model_registry = ModelRegistry(self.profiles)
        self.rag = CompressedRAG(DEFAULT_KB)
        self.lab = LocalLabAdapter(ROOT)

    def _build_deps(self, run_dir: Path, budget: BudgetTracker) -> AgentDependencies:
        memory = SharedMemory(run_id=run_dir.name, run_dir=run_dir)
        memory.set_budget(budget.to_dict())
        return AgentDependencies(
            router=self.router,
            model_registry=self.model_registry,
            memory=memory,
            budget=budget,
        )

    def run_fixture(self, fixture_dir: Path) -> Dict:
        fixture_dir = fixture_dir.resolve()
        started_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = ensure_dir(self.outputs_root / f"{fixture_dir.name}_{self.profile_set_name}_{started_at}")
        budget = BudgetTracker()
        budget.start()
        deps = self._build_deps(run_dir, budget)
        deps.memory.add_task("intake", "pending")
        deps.memory.add_task("recon", "pending")
        deps.memory.add_task("signature", "pending")
        deps.memory.add_task("analysis", "pending")
        deps.memory.add_task("exploit", "pending")
        deps.memory.add_task("validation", "pending")
        deps.memory.add_task("report", "pending")

        intake_agent = IntakeAgent(deps, self.lab)
        recon_agent = ReconAgent(deps)
        signature_agent = SignatureAgent(deps, self.rag)
        analyst_agent = AnalystAgent(deps)
        exploit_agent = ExploitAgent(deps)
        validator_agent = ValidatorAgent(deps)
        report_agent = ReportAgent(deps)

        deps.memory.update_task("intake", "running")
        intake = intake_agent.run(fixture_dir)
        deps.memory.update_task("intake", "done")

        manifest = intake["manifest"]
        limits = manifest.get("budget", {})
        budget.max_tool_calls = int(limits.get("tool_calls", budget.max_tool_calls))
        budget.max_time_seconds = int(limits.get("time_seconds", budget.max_time_seconds))
        budget.max_simulated_cost = float(limits.get("simulated_usd", budget.max_simulated_cost))
        deps.memory.set_budget(budget.to_dict())

        if budget.limits_exceeded():
            return self._finalize_early(deps.memory, manifest, run_dir, "budget_exceeded_after_intake")

        deps.memory.update_task("recon", "running")
        recon = recon_agent.run(intake["transcript"], intake["source_files"])
        deps.memory.update_task("recon", "done")

        deps.memory.update_task("signature", "running")
        signature = signature_agent.run(recon, intake["transcript"])
        deps.memory.update_task("signature", "done")

        deps.memory.update_task("analysis", "running")
        hypotheses = analyst_agent.run(manifest, recon, signature)
        deps.memory.update_task("analysis", "done", {"hypotheses": len(hypotheses)})

        validations = []
        validated_findings = []
        deps.memory.update_task("exploit", "running")
        deps.memory.update_task("validation", "running")
        for hypothesis in hypotheses:
            if budget.limits_exceeded():
                deps.memory.log_event("orchestrator", "Budget exceeded; stopping further hypotheses")
                break
            poc = exploit_agent.run(hypothesis, manifest)
            result = validator_agent.run(poc, intake["ground_truth"], manifest)
            validations.append(result)
            if result.status in {"verified", "supported"}:
                validated_findings.append(
                    {
                        "attack_family": result.attack_family,
                        "severity": result.severity,
                        "status": result.status,
                        "confidence": result.confidence,
                    }
                )
                if result.status == "verified":
                    break

        deps.memory.update_task("exploit", "done")
        deps.memory.update_task("validation", "done", {"results": len(validations)})

        deps.memory.update_task("report", "running")
        report_json = report_agent.run(manifest, validations, run_dir)
        deps.memory.update_task("report", "done")
        deps.memory.set_budget(budget.to_dict())
        deps.memory.persist()

        status = "validated" if any(item.status == "verified" for item in validations) else (
            "supported" if any(item.status == "supported" for item in validations) else "no_validated_findings"
        )
        summary = {
            "fixture_id": manifest["id"],
            "title": manifest["title"],
            "profile_set": self.profile_set_name,
            "status": status,
            "validated_findings": validated_findings,
            "budget": budget.to_dict(),
            "output_dir": str(run_dir),
            "report": report_json,
        }
        write_json(run_dir / "run_summary.json", summary)
        return summary

    def _finalize_early(self, memory: SharedMemory, manifest: Dict, run_dir: Path, reason: str) -> Dict:
        memory.log_event("orchestrator", f"Early stop: {reason}")
        memory.persist()
        summary = {
            "fixture_id": manifest.get("id", "unknown"),
            "title": manifest.get("title", "unknown"),
            "profile_set": self.profile_set_name,
            "status": "stopped",
            "reason": reason,
            "validated_findings": [],
            "budget": memory.budget,
            "output_dir": str(run_dir),
        }
        write_json(run_dir / "run_summary.json", summary)
        return summary
