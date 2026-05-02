"""Dataset package — CVE distillation pipeline + corpus model.

Sprint 8 deliverable: a structured, token-efficient CVE corpus that
feeds the Knowledge Graph and RAG layers. The corpus is designed to be
small (~200 curated entries for the seed, scaling to ~5k with NVD bulk
ingest) but high-signal: each entry carries exactly the fields the
dispatcher needs to choose an attack family, pick payloads, and
validate findings.
"""
from vapt_orchestrator_safe.dataset.cve_entry import CveEntry
from vapt_orchestrator_safe.dataset.distiller import Distiller
from vapt_orchestrator_safe.dataset.seed import load_seed_corpus

__all__ = ["CveEntry", "Distiller", "load_seed_corpus"]
