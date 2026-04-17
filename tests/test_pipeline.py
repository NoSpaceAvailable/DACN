from pathlib import Path

from vapt_orchestrator_safe.engine.orchestrator import Orchestrator


def test_idor_fixture_validates(tmp_path):
    fixture = Path("data/fixtures/challenge_idor_01").resolve()
    orch = Orchestrator(profile_set_name="mixed_default", outputs_root=tmp_path)
    summary = orch.run_fixture(fixture)
    assert summary["status"] in {"validated", "supported"}
    assert any(item["attack_family"] == "IDOR" for item in summary.get("validated_findings", []))
