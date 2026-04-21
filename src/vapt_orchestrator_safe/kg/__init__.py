"""Knowledge graph layer — C3 contribution.

Two interchangeable implementations of the same protocol:

- :class:`InMemoryKG` — plain dict-of-dict graph. Zero deps, used by
  default in tests and for local dev runs.
- :class:`Neo4jKG` — wraps the official ``neo4j`` driver. Activated when
  ``NEO4J_URI`` + ``NEO4J_USER`` + ``NEO4J_PASSWORD`` env vars are set.

Both honour the same :class:`KG` protocol so the rest of the codebase
(tools, hooks, agents) never knows which one it is talking to.
"""
from vapt_orchestrator_safe.kg.in_memory import InMemoryKG
from vapt_orchestrator_safe.kg.knowledge_graph import KG, KGFact, build_default_kg

__all__ = ["KG", "KGFact", "InMemoryKG", "build_default_kg"]
