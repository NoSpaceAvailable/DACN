"""Ablation runner — compares DACN configurations on the fixture set.

Sprint 8 deliverable: given a set of fixtures and a scripted (or real
LLM) chat model, runs the DispatcherRunner in each of the following
configurations and emits a comparison table:

- ``baseline`` — no C1, no C2, no C3 (plain dispatcher + sub-agents).
- ``C2_only`` — anti-loop guard enabled.
- ``C3_only`` — KG RAG enabled (the default).
- ``C1_only`` — mid-thinking watchdogs enabled.
- ``all`` — C1 + C2 + C3 on (DACN's intended production config).

Metric columns per (fixture × config):

- ``status`` — validated / supported / no_validated_findings / stopped
- ``steps`` — dispatcher iterations
- ``tool_calls`` — total tool invocations
- ``loop_detected`` — number of anti-loop interventions
- ``watchdog_trips`` — number of mid-thinking interventions
- ``approx_tokens`` — sum of ``approx_tokens`` from query_kg/query_rag calls
  (proxy for knowledge-retrieval cost).

The runner does NOT call a real LLM. Callers pass a
:func:`ChatModelFactory` that returns a fresh scripted chat model per
fixture × config — the same seed deck can then be re-used across
configs so numbers are directly comparable. That keeps Sprint 8 fully
reproducible without API cost.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from vapt_orchestrator_safe.engine.dispatcher_runner import DispatcherRunner


ChatModelFactory = Callable[[str, str], Any]
"""(fixture_name, config_name) → a fresh chat model for that run."""


# ── configs ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class AblationConfig:
    name: str
    enable_anti_loop: bool
    enable_kg: bool
    enable_mid_thinking: bool
    description: str = ""

    def runner_kwargs(self) -> Dict[str, Any]:
        return {
            "enable_anti_loop": self.enable_anti_loop,
            "enable_kg": self.enable_kg,
            "enable_mid_thinking": self.enable_mid_thinking,
            # Sandbox attached everywhere; disabled to keep ablation offline.
            "enable_sandbox": False,
        }


DEFAULT_CONFIGS: List[AblationConfig] = [
    AblationConfig("baseline", False, False, False,
                   "No C1 / C2 / C3. Plain dispatcher + sub-agents."),
    AblationConfig("C2_only", True, False, False,
                   "Anti-loop guard only. Measures C2's contribution."),
    AblationConfig("C3_only", False, True, False,
                   "KG RAG only. Measures C3's token savings."),
    AblationConfig("C1_only", False, False, True,
                   "Mid-thinking watchdogs only. Measures C1's impact."),
    AblationConfig("all", True, True, True,
                   "C1 + C2 + C3 enabled. DACN's intended production config."),
]


# ── results ──────────────────────────────────────────────────────────────
@dataclass
class AblationRow:
    fixture: str
    config: str
    status: str
    stop_reason: str
    steps: int
    tool_calls: int
    loop_detected: int
    watchdog_trips: int
    approx_kg_tokens: int
    approx_rag_tokens: int
    validated_findings: int
    wall_ms: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AblationReport:
    rows: List[AblationRow] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "rows": [r.to_dict() for r in self.rows],
            "summary": self._summary(),
        }

    def _summary(self) -> Dict[str, Dict[str, Any]]:
        by_config: Dict[str, Dict[str, Any]] = {}
        for row in self.rows:
            agg = by_config.setdefault(row.config, {
                "runs": 0, "validated": 0, "supported_or_validated": 0,
                "total_tool_calls": 0, "total_loop_detected": 0,
                "total_watchdog_trips": 0, "total_kg_tokens": 0,
                "total_rag_tokens": 0, "total_wall_ms": 0,
            })
            agg["runs"] += 1
            if row.status == "validated":
                agg["validated"] += 1
            if row.status in {"validated", "supported"}:
                agg["supported_or_validated"] += 1
            agg["total_tool_calls"] += row.tool_calls
            agg["total_loop_detected"] += row.loop_detected
            agg["total_watchdog_trips"] += row.watchdog_trips
            agg["total_kg_tokens"] += row.approx_kg_tokens
            agg["total_rag_tokens"] += row.approx_rag_tokens
            agg["total_wall_ms"] += row.wall_ms
        return by_config

    def to_markdown(self) -> str:
        summary = self._summary()
        lines: List[str] = [
            "# Ablation report", "",
            "| config | runs | validated | total tool calls | loops detected | watchdog trips | KG tokens | RAG tokens |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for cfg, agg in summary.items():
            lines.append(
                f"| `{cfg}` | {agg['runs']} | {agg['validated']} | "
                f"{agg['total_tool_calls']} | {agg['total_loop_detected']} | "
                f"{agg['total_watchdog_trips']} | {agg['total_kg_tokens']} | "
                f"{agg['total_rag_tokens']} |"
            )
        lines.append("")
        lines.append("## Per-fixture detail")
        lines.append("")
        lines.append("| fixture | config | status | steps | tool calls | loops | watchdogs | KG tok | RAG tok | wall ms |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|")
        for r in self.rows:
            lines.append(
                f"| {r.fixture} | `{r.config}` | {r.status} | {r.steps} | {r.tool_calls} | "
                f"{r.loop_detected} | {r.watchdog_trips} | {r.approx_kg_tokens} | "
                f"{r.approx_rag_tokens} | {r.wall_ms} |"
            )
        return "\n".join(lines) + "\n"


# ── runner ───────────────────────────────────────────────────────────────
def run_ablation(
    fixtures: Iterable[Path],
    *,
    chat_model_factory: ChatModelFactory,
    outputs_root: Path,
    configs: Optional[List[AblationConfig]] = None,
    profile_set_name: str = "mixed_default",
    backend: str = "rule",
    max_steps: int = 20,
) -> AblationReport:
    configs = list(configs or DEFAULT_CONFIGS)
    report = AblationReport()

    for fixture in fixtures:
        fixture_name = fixture.name
        for cfg in configs:
            chat_model = chat_model_factory(fixture_name, cfg.name)
            runner = DispatcherRunner(
                profile_set_name=profile_set_name,
                outputs_root=outputs_root / cfg.name,
                backend=backend,
                chat_model=chat_model,
                chat_model_backend_spec=f"ablation:{cfg.name}",
                max_steps=max_steps,
                **cfg.runner_kwargs(),
            )
            started = time.perf_counter()
            summary = runner.run_fixture(fixture)
            wall_ms = int((time.perf_counter() - started) * 1000)
            row = _row_from_summary(fixture_name, cfg.name, summary, wall_ms)
            report.rows.append(row)

    return report


def _row_from_summary(
    fixture: str, config: str, summary: Dict[str, Any], wall_ms: int,
) -> AblationRow:
    # Read event-level counters out of the run's memory.json (written by the runner).
    memory_path = Path(summary["output_dir"]) / "memory.json"
    events: List[Dict[str, Any]] = []
    if memory_path.exists():
        events = json.loads(memory_path.read_text()).get("events", [])
    loop_detected = sum(1 for e in events if e.get("message") == "loop_detected")

    # Aggregate approx_tokens from query_kg / query_rag artifacts.
    artifacts: List[Dict[str, Any]] = []
    if memory_path.exists():
        artifacts = json.loads(memory_path.read_text()).get("artifacts", [])
    kg_tokens = sum(
        (a.get("payload", {}).get("result", {}).get("metadata", {}) or {}).get("approx_tokens", 0)
        for a in artifacts if a.get("kind") == "tool:query_kg"
    )
    rag_tokens = sum(
        (a.get("payload", {}).get("result", {}).get("metadata", {}) or {}).get("approx_tokens", 0)
        for a in artifacts if a.get("kind") == "tool:query_rag"
    )

    return AblationRow(
        fixture=fixture,
        config=config,
        status=summary["status"],
        stop_reason=summary.get("stop_reason", "?"),
        steps=summary.get("steps", 0),
        tool_calls=len(summary.get("tool_invocations", [])),
        loop_detected=loop_detected,
        watchdog_trips=len(summary.get("watchdog_trips", [])),
        approx_kg_tokens=int(kg_tokens),
        approx_rag_tokens=int(rag_tokens),
        validated_findings=len(summary.get("validated_findings", [])),
        wall_ms=wall_ms,
    )
