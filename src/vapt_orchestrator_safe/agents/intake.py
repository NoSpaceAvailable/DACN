from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from vapt_orchestrator_safe.agents.base import AgentDependencies, BaseAgent
from vapt_orchestrator_safe.memory.evidence import EvidenceItem
from vapt_orchestrator_safe.sandbox.local_lab import LocalLabAdapter


class IntakeAgent(BaseAgent):
    role = "coordinator"

    def __init__(self, deps: AgentDependencies, lab: LocalLabAdapter):
        super().__init__(deps)
        self.lab = lab

    def run(self, fixture_dir: Path) -> Dict[str, Any]:
        self.charge()
        manifest = self.lab.load_manifest(fixture_dir)
        transcript = self.lab.load_http_transcript(fixture_dir)
        source_files = self.lab.load_source_files(fixture_dir)
        ground_truth = self.lab.load_ground_truth(fixture_dir)

        summary = {
            "fixture_id": manifest["id"],
            "title": manifest["title"],
            "mode": manifest["mode"],
            "route_count": len(transcript.get("routes", [])),
            "source_files": len(source_files),
            "difficulty": manifest.get("difficulty", 0.5),
        }
        self.deps.memory.add_evidence(
            EvidenceItem(
                evidence_id="intake-summary",
                phase="intake",
                summary=f"Loaded fixture {manifest['id']} with {summary['route_count']} routes and {summary['source_files']} source files.",
                details=summary,
                tags=["intake", manifest["mode"]],
            )
        )
        self.log("Fixture loaded", summary)
        return {
            "manifest": manifest,
            "transcript": transcript,
            "source_files": source_files,
            "ground_truth": ground_truth,
        }
