from pathlib import Path

from vapt_orchestrator_safe.engine.benchmark import BenchmarkRunner
from vapt_orchestrator_safe.engine.orchestrator import Orchestrator


def test_benchmark_runs(tmp_path):
    fixtures = [
        Path("data/fixtures/challenge_idor_01").resolve(),
        Path("data/fixtures/challenge_ssrf_01").resolve(),
    ]

    def factory(name: str):
        return Orchestrator(profile_set_name=name, outputs_root=tmp_path)

    runner = BenchmarkRunner(factory)
    out = tmp_path / "benchmark.json"
    result = runner.run(fixtures, ["all_4b", "mixed_default"], out)
    assert out.exists()
    assert "aggregates" in result
    assert "all_4b" in result["aggregates"]
