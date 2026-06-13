"""Pretty-print what the dispatcher found for a fixture's latest run.

Usage:
    python scripts/show_findings.py <fixture_id> [--provider-model TAG]
    python scripts/show_findings.py challenge_cornhub_01

Shows the run status, the tools the LLM called, the LLM-recorded findings
(record_finding — family-agnostic detection), and any oracle-validated
findings. Picks the most recent matching run under outputs/runs_*/.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    fixture = sys.argv[1]

    runs = sorted(
        ROOT.glob(f"outputs/runs_*/{fixture}_*/run_summary.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not runs:
        print(f"No runs found for {fixture!r} under outputs/runs_*/. Run the bench script first.")
        return 1

    summary = json.loads(runs[0].read_text(encoding="utf-8"))
    print(f"Run:    {runs[0].parent.name}")
    print(f"Backend:{summary.get('backend')}")
    print(f"Status: {summary.get('status')}  (stop_reason={summary.get('stop_reason')}, steps={summary.get('steps')})")
    print(f"Tools:  {[t.get('name') for t in summary.get('tool_invocations', [])]}")

    findings = summary.get("llm_findings", [])
    print(f"\n=== LLM-detected findings ({len(findings)}) ===")
    if not findings:
        print("  (none recorded — the model did not call record_finding)")
    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f.get('vuln_class')} ({f.get('severity')}) @ {f.get('location')}")
        print(f"    {f.get('description', '')}")
        if f.get("suggested_poc"):
            print(f"    PoC: {f.get('suggested_poc')}")

    validated = summary.get("validated_findings", [])
    print(f"\n=== oracle-validated findings ({len(validated)}) ===")
    for v in validated:
        print(f"  {v.get('attack_family')} ({v.get('severity')}) status={v.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
