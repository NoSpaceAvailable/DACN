from __future__ import annotations

from typing import Any, Dict, List

from vapt_orchestrator_safe.agents.base import BaseAgent
from vapt_orchestrator_safe.memory.evidence import EvidenceItem
from vapt_orchestrator_safe.types import CandidatePoC, ValidationResult


class ValidatorAgent(BaseAgent):
    role = "validator"

    def run(self, poc: CandidatePoC | None, ground_truth: Dict[str, Any], manifest: Dict[str, Any]) -> ValidationResult:
        self.charge()
        if poc is None:
            result = ValidationResult(
                status="fail",
                attack_family=None,
                severity=None,
                confidence=0.0,
                evidence=[],
                reasoning="No candidate PoC was produced.",
            )
            self.log("Validation failed: missing PoC")
            return result

        capability = self.deps.router.capability_for_role(self.role)
        difficulty = float(manifest.get("difficulty", 0.5))
        expected_family = ground_truth.get("expected_vulnerability")
        expected_oracle = ground_truth.get("oracle")
        is_match = poc.attack_family == expected_family and poc.oracle == expected_oracle
        confidence = round(min(0.99, (poc.confidence + capability) / 2), 4)

        if is_match and capability + 0.10 >= difficulty:
            result = ValidationResult(
                status="verified",
                attack_family=poc.attack_family,
                severity=ground_truth.get("severity"),
                confidence=confidence,
                evidence=[f"validator matched oracle {expected_oracle}"],
                reasoning="Candidate PoC matches fixture ground truth and validation threshold.",
                poc=poc,
            )
        elif is_match:
            result = ValidationResult(
                status="supported",
                attack_family=poc.attack_family,
                severity=ground_truth.get("severity"),
                confidence=round(confidence - 0.1, 4),
                evidence=[f"oracle {expected_oracle} matched but validator capability threshold not fully met"],
                reasoning="Evidence supports the finding, but validation confidence is limited.",
                poc=poc,
            )
        else:
            result = ValidationResult(
                status="fail",
                attack_family=poc.attack_family,
                severity=None,
                confidence=round(confidence - 0.2, 4),
                evidence=["PoC did not match expected attack family or oracle"],
                reasoning="Candidate PoC does not align with fixture ground truth.",
                poc=poc,
            )

        self.deps.memory.add_evidence(
            EvidenceItem(
                evidence_id=f"validation-{(poc.attack_family or 'none').lower()}",
                phase="validation",
                summary=f"Validation result: {result.status} for {poc.attack_family}.",
                details={
                    "status": result.status,
                    "attack_family": result.attack_family,
                    "severity": result.severity,
                    "confidence": result.confidence,
                    "evidence": result.evidence,
                    "reasoning": result.reasoning,
                },
                tags=["validation", result.status],
            )
        )
        self.log("Validation complete", {"status": result.status, "attack_family": result.attack_family})
        return result
