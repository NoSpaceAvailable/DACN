"""query_kg / query_rag tools — C3 token-efficient retrieval.

The dispatcher's Analyst step historically paid ~5000 tokens per RAG
call because we dumped raw signature cards into the prompt. The KG
tool returns a small set of structured triples (typically 50-200 tokens
for the same question), which is the C3 token-efficiency contribution.

We expose two tools side-by-side so Sprint 8 ablation can compare them:

- ``query_kg`` — structured, triple-returning, preferred.
- ``query_rag`` — unstructured, chunk-returning, fallback.

Both record a ``token_cost`` estimate in :class:`ToolResult.metadata`
so the eval harness can compute the per-question savings directly.
"""
from __future__ import annotations

import json
from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from vapt_orchestrator_safe.kg.knowledge_graph import KG, KGFact
from vapt_orchestrator_safe.memory.rag import CompressedRAG
from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


# Very rough tokens-per-char heuristic (~4 chars/token on English text).
_APPROX_CHARS_PER_TOKEN = 4


def _approx_tokens(text: str) -> int:
    return max(1, len(text) // _APPROX_CHARS_PER_TOKEN)


# ── query_kg ─────────────────────────────────────────────────────────────
class _KGArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    attack_family: Optional[str] = Field(
        default=None,
        description="If set, return payload / sink / CWE triples for this family (IDOR, SSRF, SQLi, …).",
    )
    framework: Optional[str] = Field(
        default=None,
        description="If set, return triples touching this framework (flask, express, spring, …).",
    )
    subject: Optional[str] = Field(
        default=None,
        description="Optional exact subject id (e.g. 'Payload:sqli_auth_bypass') for a pinpoint lookup.",
    )
    limit: int = Field(default=10, description="Max triples to return.")


class QueryKGTool(BaseTool):
    name: str = "query_kg"
    description: str = (
        "Query the offensive knowledge graph for attack-family payloads, "
        "framework-specific sinks, or a specific entity by id. Returns a "
        "compact list of subject-predicate-object triples (10-20× cheaper "
        "than querying the raw RAG for the same question)."
    )
    args_schema: Type[BaseModel] = _KGArgs
    # The stdout is a JSON document callers parse; BaseTool's 2000-char default
    # would cut it mid-object (esp. with the richer disambiguator props), so
    # raise the cap to keep the JSON intact.
    truncate_at: ClassVar[int] = 12000

    _kg: KG = PrivateAttr()

    def __init__(self, kg: KG, **data: Any):
        super().__init__(**data)
        self._kg = kg

    def _invoke(self, **kwargs: Any) -> ToolResult:
        limit = int(kwargs.get("limit", 10))
        facts: List[KGFact] = []

        if kwargs.get("subject"):
            facts = self._kg.neighbours(kwargs["subject"], depth=1, limit=limit)
        elif kwargs.get("attack_family"):
            facts = self._kg.query_by_family(kwargs["attack_family"], limit=limit)
        elif kwargs.get("framework"):
            facts = self._kg.query_by_framework(kwargs["framework"], limit=limit)
        else:
            return ToolResult(
                stderr="Pass at least one of: attack_family, framework, subject.",
                exit_code=2,
            )

        text_view = [f.to_text() for f in facts]
        payload_text = "\n".join(text_view) if text_view else "(no matching triples)"
        token_estimate = _approx_tokens(payload_text)

        payload = {
            "count": len(facts),
            "triples": [
                {"subject": f.subject, "predicate": f.predicate, "obj": f.obj, "props": f.props}
                for f in facts
            ],
            "text": payload_text,
            "approx_tokens": token_estimate,
        }
        return ToolResult(
            stdout=json.dumps(payload, ensure_ascii=False),
            exit_code=0,
            metadata={"approx_tokens": token_estimate, "count": len(facts), "mode": "kg"},
        )


# ── query_rag ────────────────────────────────────────────────────────────
class _RAGArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    query: str = Field(description="Free-text question / keyword mix.")
    top_k: int = Field(default=4, description="Number of chunks to return.")


class QueryRAGTool(BaseTool):
    name: str = "query_rag"
    description: str = (
        "Retrieve raw compressed signature cards from the knowledge base. "
        "Prefer query_kg when the question is about payloads / sinks / "
        "frameworks — this tool returns much more text for the same question."
    )
    args_schema: Type[BaseModel] = _RAGArgs

    _rag: CompressedRAG = PrivateAttr()

    def __init__(self, rag: CompressedRAG, **data: Any):
        super().__init__(**data)
        self._rag = rag

    def _invoke(self, **kwargs: Any) -> ToolResult:
        cards = self._rag.retrieve(kwargs["query"], top_k=int(kwargs.get("top_k", 4)))
        text_view = [
            f"[{c.attack_family} score={c.score:.2f}] {c.card_text}" for c in cards
        ]
        payload_text = "\n".join(text_view) if text_view else "(no matching cards)"
        token_estimate = _approx_tokens(payload_text)

        payload = {
            "count": len(cards),
            "cards": [
                {"attack_family": c.attack_family, "score": c.score, "text": c.card_text}
                for c in cards
            ],
            "approx_tokens": token_estimate,
        }
        return ToolResult(
            stdout=json.dumps(payload, ensure_ascii=False),
            exit_code=0,
            metadata={"approx_tokens": token_estimate, "count": len(cards), "mode": "rag"},
        )
