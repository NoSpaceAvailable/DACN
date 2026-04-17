from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

from vapt_orchestrator_safe.utils.io import read_jsonl
from vapt_orchestrator_safe.utils.text import compact, keyword_overlap_score, tokenize


@dataclass
class RetrievedCard:
    doc_id: str
    attack_family: str
    score: float
    card_text: str
    raw: Dict[str, Any]


class CompressedRAG:
    def __init__(self, kb_dir: Path):
        self.documents: List[Dict[str, Any]] = []
        for path in sorted(kb_dir.glob("*.jsonl")):
            self.documents.extend(read_jsonl(path))

    def retrieve(self, query: str, top_k: int = 3) -> List[RetrievedCard]:
        q_terms = tokenize(query)
        scored: List[RetrievedCard] = []
        for doc in self.documents:
            text = " ".join(str(v) for v in doc.values())
            score = keyword_overlap_score(q_terms, text)
            if score <= 0:
                continue
            scored.append(
                RetrievedCard(
                    doc_id=str(doc.get("id", "unknown")),
                    attack_family=str(doc.get("attack_family", "Unknown")),
                    score=score,
                    card_text=self._compress(doc, q_terms),
                    raw=doc,
                )
            )
        scored.sort(key=lambda x: x.score, reverse=True)
        return scored[:top_k]

    def _compress(self, doc: Dict[str, Any], query_terms: Iterable[str]) -> str:
        pieces = [
            f"Family: {doc.get('attack_family', 'Unknown')}",
            f"Title: {doc.get('title', doc.get('id', 'Unknown'))}",
            f"Indicators: {compact(', '.join(doc.get('indicators', [])), 120)}",
            f"Preconditions: {compact(', '.join(doc.get('preconditions', [])), 100)}",
            f"Oracle: {compact(', '.join(doc.get('validation_oracle', [])), 100)}",
            f"Remediation: {compact(str(doc.get('remediation', '')), 120)}",
        ]
        return " | ".join(pieces)
