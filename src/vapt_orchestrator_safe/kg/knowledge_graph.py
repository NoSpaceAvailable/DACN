"""KG protocol + fact schema + default graph builder.

The rest of the codebase talks to the KG through the :class:`KG`
Protocol (a typing Protocol, so we don't need inheritance). Both
:class:`InMemoryKG` and :class:`Neo4jKG` satisfy it.

We model the graph using a deliberately small, vulnerability-centric
schema (taken from :file:`infra/neo4j/init/001_schema.cypher`):

- Nodes: ``CVE``, ``Framework``, ``Sink``, ``Source``, ``Payload``,
  ``Endpoint``, ``Parameter``, ``CWE``.
- Edges: ``AFFECTS``, ``CLASSIFIED_AS``, ``EXPLOITS``, ``TARGETS``,
  ``HAS_PARAM``, ``FLOWS_TO``, ``READS``, ``RUNS_ON``.

Each node has an ``id`` string (unique per node type) and arbitrary
string/number properties. Each edge carries its verb in ``rel`` and
optional metadata as properties.

The :func:`build_default_kg` helper seeds the in-memory graph with a
tiny corpus of CVE / payload / framework triples derived from the
three scaffold fixtures (IDOR, SSRF, SQLi). Real datasets land in
Sprint 8 (corpus distillation); the default builder exists so the
Dispatcher's `query_kg` tool has something useful to return today.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple


@dataclass(frozen=True)
class KGFact:
    """A single subject-predicate-object triple with metadata."""
    subject: str                 # "CVE:CVE-2023-12345"
    predicate: str               # "EXPLOITS"
    obj: str                     # "Sink:unsafe_sql_format"
    props: Dict[str, Any] = field(default_factory=dict)

    def to_text(self, max_prop_chars: int = 120) -> str:
        if not self.props:
            return f"{self.subject} -[{self.predicate}]-> {self.obj}"
        prop_text = ", ".join(
            f"{k}={_short(v, max_prop_chars)}" for k, v in self.props.items()
        )
        return f"{self.subject} -[{self.predicate} {{{prop_text}}}]-> {self.obj}"


class KG(Protocol):
    """Minimal interface every KG implementation must satisfy."""

    def add_node(self, node_type: str, node_id: str, **props: Any) -> None: ...
    def add_edge(self, src: str, rel: str, dst: str, **props: Any) -> None: ...
    def query_by_family(self, attack_family: str, limit: int = 10) -> List[KGFact]: ...
    def query_by_framework(self, framework: str, limit: int = 10) -> List[KGFact]: ...
    def query_triples(
        self,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        obj: Optional[str] = None,
        limit: int = 10,
    ) -> List[KGFact]: ...
    def neighbours(self, node_id: str, *, depth: int = 1, limit: int = 20) -> List[KGFact]: ...
    def size(self) -> Tuple[int, int]: ...
    def close(self) -> None: ...


def build_default_kg(kg: KG) -> None:
    """Seed ``kg`` with a minimal IDOR/SSRF/SQLi corpus.

    Keeps the Dispatcher's ``query_kg`` tool useful out-of-the-box when
    no real corpus has been loaded yet (Sprint 8 brings the ~5k-entry
    CVE + writeup corpus per the plan).
    """
    # Frameworks
    kg.add_node("Framework", "Framework:flask", language="python")
    kg.add_node("Framework", "Framework:express", language="node")
    kg.add_node("Framework", "Framework:spring", language="java")

    # CWEs
    kg.add_node("CWE", "CWE:639", label="Authorization Bypass Through User-Controlled Key")
    kg.add_node("CWE", "CWE:918", label="Server-Side Request Forgery")
    kg.add_node("CWE", "CWE:89", label="SQL Injection")

    # Sinks
    kg.add_node("Sink", "Sink:unsafe_sql_format", lang="python", kind="raw_sql")
    kg.add_node("Sink", "Sink:server_side_fetch", lang="python", kind="http_out")
    kg.add_node("Sink", "Sink:direct_object_lookup", lang="python", kind="dao")

    # Payloads
    kg.add_node(
        "Payload", "Payload:idor_sibling_id",
        vuln_class="IDOR", template="GET /api/<resource>/<sibling_id>",
        oracle="response_contains_other_user_email",
    )
    kg.add_node(
        "Payload", "Payload:ssrf_metadata",
        vuln_class="SSRF", template="POST {url: 'http://169.254.169.254/latest/meta-data/'}",
        oracle="server_fetches_internal_resource",
    )
    kg.add_node(
        "Payload", "Payload:sqli_auth_bypass",
        vuln_class="SQLi", template="username=admin' --",
        oracle="auth_bypass_or_query_tampering",
    )

    # Relations
    kg.add_edge("Payload:idor_sibling_id", "TARGETS", "Sink:direct_object_lookup")
    kg.add_edge("Payload:idor_sibling_id", "CLASSIFIED_AS", "CWE:639")
    kg.add_edge("Payload:ssrf_metadata", "TARGETS", "Sink:server_side_fetch")
    kg.add_edge("Payload:ssrf_metadata", "CLASSIFIED_AS", "CWE:918")
    kg.add_edge("Payload:sqli_auth_bypass", "TARGETS", "Sink:unsafe_sql_format")
    kg.add_edge("Payload:sqli_auth_bypass", "CLASSIFIED_AS", "CWE:89")

    # Cross-framework hints
    kg.add_edge("Sink:unsafe_sql_format", "OBSERVED_IN", "Framework:flask")
    kg.add_edge("Sink:server_side_fetch", "OBSERVED_IN", "Framework:flask")
    kg.add_edge("Sink:direct_object_lookup", "OBSERVED_IN", "Framework:express")


def _short(value: Any, limit: int) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."
