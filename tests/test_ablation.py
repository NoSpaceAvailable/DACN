"""Ablation runner — covers all 5 configs over all 3 scaffold fixtures."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest
from langchain_core.messages import AIMessage

from vapt_orchestrator_safe.engine.ablation import (
    DEFAULT_CONFIGS,
    AblationConfig,
    AblationReport,
    run_ablation,
)


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "data" / "fixtures"
FIXTURE_FAMILY = {
    "challenge_idor_01": "IDOR",
    "challenge_ssrf_01": "SSRF",
    "challenge_sqli_01": "SQLi",
    "challenge_sqli_02": "SQLi",
    "challenge_lfi_01": "LFI",
    "challenge_nosqli_01": "NoSQLi",
    "challenge_pathtraversal_01": "PathTraversal",
}


class _Scripted:
    def __init__(self, script):
        self._s = iter(script)
    def bind_tools(self, _t): return self
    def invoke(self, _m, **_k): return next(self._s)


def _factory_idor_path(fixture_name: str, _config_name: str):
    family = FIXTURE_FAMILY.get(fixture_name, "IDOR")
    return _Scripted([
        AIMessage(content="", tool_calls=[{"id": "r1", "name": "invoke_recon", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "s1", "name": "invoke_signature", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "a1", "name": "invoke_analyst", "args": {}}]),
        AIMessage(content="", tool_calls=[{"id": "k1", "name": "query_kg",
                                           "args": {"attack_family": family}}]),
        AIMessage(content="", tool_calls=[{"id": "e1", "name": "invoke_exploit",
                                           "args": {"attack_family": family}}]),
        AIMessage(content="", tool_calls=[{"id": "rp", "name": "invoke_report", "args": {}}]),
        AIMessage(content=f"done {family}", tool_calls=[]),
    ])


def test_ablation_runs_all_configs_on_all_fixtures(tmp_path):
    fixtures = sorted(p for p in FIXTURES_DIR.iterdir() if p.is_dir())
    assert fixtures, "scaffold should ship at least one fixture"

    report = run_ablation(
        fixtures=fixtures,
        chat_model_factory=_factory_idor_path,
        outputs_root=tmp_path,
        max_steps=15,
    )

    # Runs = fixtures × configs.
    assert len(report.rows) == len(fixtures) * len(DEFAULT_CONFIGS)
    # Every row has the expected columns populated.
    for row in report.rows:
        assert row.fixture in FIXTURE_FAMILY
        assert row.config in {c.name for c in DEFAULT_CONFIGS}
        assert row.status in {"validated", "supported", "no_validated_findings", "stopped"}
        assert row.steps > 0


def test_ablation_summary_counts_validated_per_config(tmp_path):
    fixtures = sorted(p for p in FIXTURES_DIR.iterdir() if p.is_dir())
    report = run_ablation(
        fixtures=fixtures,
        chat_model_factory=_factory_idor_path,
        outputs_root=tmp_path,
    )
    summary = report.to_dict()["summary"]
    for cfg_name in [c.name for c in DEFAULT_CONFIGS]:
        assert cfg_name in summary
        assert summary[cfg_name]["runs"] == len(fixtures)


def test_ablation_c3_only_accumulates_kg_tokens(tmp_path):
    fixtures = sorted(p for p in FIXTURES_DIR.iterdir() if p.is_dir())
    report = run_ablation(
        fixtures=fixtures,
        chat_model_factory=_factory_idor_path,
        outputs_root=tmp_path,
    )
    # Rows where KG was enabled: C3_only + all.
    kg_rows = [r for r in report.rows if r.config in {"C3_only", "all"}]
    no_kg_rows = [r for r in report.rows if r.config in {"baseline", "C2_only", "C1_only"}]
    # KG calls happened in the KG-enabled configs — the script issues query_kg.
    assert any(r.approx_kg_tokens > 0 for r in kg_rows)
    # Without KG, the query_kg tool isn't attached so no tokens attributed.
    assert all(r.approx_kg_tokens == 0 for r in no_kg_rows)


def test_ablation_markdown_renders_summary_and_detail(tmp_path):
    fixtures = sorted(p for p in FIXTURES_DIR.iterdir() if p.is_dir())[:1]  # keep MD short
    report = run_ablation(
        fixtures=fixtures,
        chat_model_factory=_factory_idor_path,
        outputs_root=tmp_path,
    )
    md = report.to_markdown()
    assert "Ablation report" in md
    assert "config | runs | validated" in md
    # Each fixture row exists.
    assert fixtures[0].name in md


def test_ablation_configs_cover_each_contribution():
    """Sanity: DEFAULT_CONFIGS must include baseline, the three solo configs, and all-on."""
    names = {c.name for c in DEFAULT_CONFIGS}
    assert {"baseline", "C2_only", "C3_only", "C1_only", "all"}.issubset(names)
