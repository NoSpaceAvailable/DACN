from __future__ import annotations

from typing import Any, Dict, List

from vapt_orchestrator_safe.agents.base import BaseAgent
from vapt_orchestrator_safe.memory.evidence import EvidenceItem
from vapt_orchestrator_safe.memory.rag import CompressedRAG


class SignatureAgent(BaseAgent):
    role = "signature"

    def __init__(self, deps, rag: CompressedRAG):
        super().__init__(deps)
        self.rag = rag

    def run(self, recon: Dict[str, Any], transcript: Dict[str, Any]) -> Dict[str, Any]:
        self.charge()
        query = " ".join(
            recon.get("route_map", [])
            + recon.get("parameters", [])
            + recon.get("source_indicators", [])
            + transcript.get("observations", [])
        )
        cards = self.rag.retrieve(query, top_k=4)
        evidence_cards = []
        for idx, card in enumerate(cards, start=1):
            evidence_id = f"sig-card-{idx}"
            evidence_cards.append(
                {
                    "evidence_id": evidence_id,
                    "attack_family": card.attack_family,
                    "score": round(card.score, 4),
                    "card_text": card.card_text,
                }
            )
            self.deps.memory.add_evidence(
                EvidenceItem(
                    evidence_id=evidence_id,
                    phase="signature",
                    summary=f"Retrieved signature card for {card.attack_family} with score {card.score:.2f}.",
                    details={"attack_family": card.attack_family, "score": card.score, "card_text": card.card_text},
                    tags=["signature", card.attack_family.lower()],
                )
            )
        result = {"query": query, "cards": evidence_cards}
        self.log("Signature retrieval complete", {"cards": len(evidence_cards)})
        return result
