from __future__ import annotations

from typing import Any, Dict, List

from vapt_orchestrator_safe.agents.base import BaseAgent
from vapt_orchestrator_safe.memory.evidence import EvidenceItem
from vapt_orchestrator_safe.types import Hypothesis


class AnalystAgent(BaseAgent):
    role = "analyst"

    def run(self, manifest: Dict[str, Any], recon: Dict[str, Any], signature: Dict[str, Any]) -> List[Hypothesis]:
        self.charge()
        difficulty = float(manifest.get("difficulty", 0.5))
        capability = self.deps.router.capability_for_role(self.role)
        route_map = " ".join(recon.get("route_map", [])).lower()
        source_indicators = set(recon.get("source_indicators", []))
        cards = signature.get("cards", [])
        ranked_families = [card["attack_family"] for card in cards]

        hypotheses: List[Hypothesis] = []
        if "missing_ownership_check" in source_indicators or "invoice" in route_map:
            confidence = round(min(0.95, 0.55 + capability - difficulty / 3), 4)
            hypotheses.append(
                Hypothesis(
                    attack_family="IDOR",
                    confidence=confidence,
                    rationale="Route patterns and source evidence suggest object-level authorization is missing.",
                    evidence_ids=["recon-surface", "sig-card-1"],
                    required_skill="authorization",
                )
            )
        if "server_side_fetch_of_user_url" in source_indicators or "webhook/preview" in route_map:
            confidence = round(min(0.95, 0.58 + capability - difficulty / 4), 4)
            hypotheses.append(
                Hypothesis(
                    attack_family="SSRF",
                    confidence=confidence,
                    rationale="User-controlled URL appears to reach a server-side fetch sink.",
                    evidence_ids=["recon-surface", "sig-card-1"],
                    required_skill="ssrf",
                )
            )
        if "unsafe_sql_formatting" in source_indicators or "login" in route_map:
            confidence = round(min(0.95, 0.52 + capability - difficulty / 5), 4)
            hypotheses.append(
                Hypothesis(
                    attack_family="SQLi",
                    confidence=confidence,
                    rationale="Source evidence suggests attacker input is formatted directly into an SQL query.",
                    evidence_ids=["recon-surface", "sig-card-1"],
                    required_skill="sqli",
                )
            )

        hypotheses.sort(key=lambda item: item.confidence, reverse=True)
        summary = [
            {"attack_family": h.attack_family, "confidence": h.confidence, "rationale": h.rationale}
            for h in hypotheses
        ]
        self.deps.memory.add_evidence(
            EvidenceItem(
                evidence_id="analyst-hypotheses",
                phase="analysis",
                summary=f"Generated {len(hypotheses)} ranked hypotheses.",
                details={"hypotheses": summary, "ranked_families": ranked_families},
                tags=["analysis"],
            )
        )
        self.log("Analyst produced hypotheses", {"count": len(hypotheses)})
        return hypotheses
