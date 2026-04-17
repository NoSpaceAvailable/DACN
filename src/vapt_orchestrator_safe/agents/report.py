from __future__ import annotations

from typing import Any, Dict, List

from vapt_orchestrator_safe.agents.base import BaseAgent
from vapt_orchestrator_safe.types import ValidationResult
from vapt_orchestrator_safe.utils.io import write_json, write_text


class ReportAgent(BaseAgent):
    role = "report"

    def run(self, manifest: Dict[str, Any], validations: List[ValidationResult], output_dir) -> Dict[str, Any]:
        self.charge()
        validated = [item for item in validations if item.status in {"verified", "supported"}]
        lines = [
            f"# Report: {manifest['title']}",
            "",
            f"Fixture ID: `{manifest['id']}`",
            f"Mode: `{manifest['mode']}`",
            "",
            "## Findings",
        ]
        if not validated:
            lines.append("No validated findings.")
        else:
            for idx, finding in enumerate(validated, start=1):
                lines.extend(
                    [
                        f"### {idx}. {finding.attack_family} ({finding.status})",
                        f"- Severity: {finding.severity}",
                        f"- Confidence: {finding.confidence}",
                        f"- Reasoning: {finding.reasoning}",
                        f"- Evidence: {'; '.join(finding.evidence)}",
                        "",
                    ]
                )
                if finding.poc:
                    lines.append("#### Candidate PoC")
                    for step in finding.poc.steps:
                        lines.append(f"- {step}")
                    lines.append("")

        report_md = "\n".join(lines)
        report_json = {
            "fixture_id": manifest["id"],
            "title": manifest["title"],
            "findings": [
                {
                    "status": item.status,
                    "attack_family": item.attack_family,
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "reasoning": item.reasoning,
                    "evidence": item.evidence,
                    "poc": None if item.poc is None else {
                        "title": item.poc.title,
                        "steps": item.poc.steps,
                        "oracle": item.poc.oracle,
                    },
                }
                for item in validated
            ],
        }
        write_text(output_dir / "report.md", report_md)
        write_json(output_dir / "report.json", report_json)
        self.log("Report written", {"findings": len(validated)})
        return report_json
