from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from vapt_orchestrator_safe.engine.orchestrator import Orchestrator
from vapt_orchestrator_safe.utils.io import write_json


class BenchmarkRunner:
    def __init__(self, orchestrator_factory):
        self.orchestrator_factory = orchestrator_factory

    def run(self, fixtures: List[Path], profile_set_names: List[str], out_path: Path) -> Dict[str, Any]:
        results: Dict[str, Any] = {"runs": []}
        aggregates: Dict[str, Dict[str, Any]] = {}

        for profile_set_name in profile_set_names:
            aggregates[profile_set_name] = {
                "fixtures": 0,
                "validated_findings": 0,
                "successful_validations": 0,
                "simulated_cost": 0.0,
                "simulated_tokens": 0,
                "tool_calls": 0,
            }
            for fixture in fixtures:
                orchestrator: Orchestrator = self.orchestrator_factory(profile_set_name)
                summary = orchestrator.run_fixture(fixture)
                results["runs"].append(summary)
                agg = aggregates[profile_set_name]
                agg["fixtures"] += 1
                agg["validated_findings"] += len(summary.get("validated_findings", []))
                if summary.get("status") == "validated":
                    agg["successful_validations"] += 1
                budget = summary.get("budget", {})
                agg["simulated_cost"] += float(budget.get("simulated_cost", 0.0))
                agg["simulated_tokens"] += int(budget.get("simulated_tokens", 0))
                agg["tool_calls"] += int(budget.get("tool_calls", 0))

        for name, agg in aggregates.items():
            fixtures_count = max(agg["fixtures"], 1)
            agg["success_rate"] = round(agg["successful_validations"] / fixtures_count, 4)
            agg["avg_cost"] = round(agg["simulated_cost"] / fixtures_count, 4)
            agg["avg_tool_calls"] = round(agg["tool_calls"] / fixtures_count, 2)
            agg["avg_tokens"] = round(agg["simulated_tokens"] / fixtures_count, 2)

        results["aggregates"] = aggregates
        write_json(out_path, results)
        return results
