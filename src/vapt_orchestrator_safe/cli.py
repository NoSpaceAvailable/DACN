from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

from vapt_orchestrator_safe.config import DEFAULT_FIXTURES, DEFAULT_OUTPUTS, DEFAULT_PROFILES, load_profiles
from vapt_orchestrator_safe.engine.benchmark import BenchmarkRunner
from vapt_orchestrator_safe.engine.orchestrator import Orchestrator
from vapt_orchestrator_safe.utils.io import ensure_dir


def cmd_profiles(args: argparse.Namespace) -> int:
    loaded = load_profiles(Path(args.profiles))
    print("Profiles:")
    for name, values in loaded.profiles.items():
        print(f"  - {name}: {values['label']}")
    print("\nProfile sets:")
    for name, mapping in loaded.profile_sets.items():
        print(f"  - {name}")
        for role, profile in mapping.items():
            print(f"      {role}: {profile}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    fixture = Path(args.fixture)
    orchestrator = Orchestrator(
        profile_set_name=args.profile_set,
        profiles_path=Path(args.profiles),
        outputs_root=Path(args.outputs_root),
    )
    summary = orchestrator.run_fixture(fixture)
    print(f"Run complete: {summary['status']}")
    print(f"Output dir: {summary['output_dir']}")
    print(f"Validated findings: {len(summary.get('validated_findings', []))}")
    return 0


def _collect_fixtures(fixtures_dir: Path) -> List[Path]:
    return sorted(path for path in fixtures_dir.iterdir() if path.is_dir())


def cmd_benchmark(args: argparse.Namespace) -> int:
    profiles_path = Path(args.profiles)
    loaded = load_profiles(profiles_path)
    if args.profile_sets:
        profile_set_names = args.profile_sets.split(",")
    else:
        profile_set_names = sorted(loaded.profile_sets)

    outputs_root = ensure_dir(Path(args.outputs_root))
    fixtures_dir = Path(args.fixtures_dir)
    fixtures = _collect_fixtures(fixtures_dir)

    def factory(profile_set_name: str) -> Orchestrator:
        return Orchestrator(
            profile_set_name=profile_set_name,
            profiles_path=profiles_path,
            outputs_root=outputs_root,
        )

    runner = BenchmarkRunner(factory)
    out_path = Path(args.out)
    results = runner.run(fixtures=fixtures, profile_set_names=profile_set_names, out_path=out_path)
    print(f"Benchmark written to: {out_path}")
    for name, agg in results["aggregates"].items():
        print(
            f"- {name}: success_rate={agg['success_rate']}, avg_cost={agg['avg_cost']}, avg_tool_calls={agg['avg_tool_calls']}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VAPT Orchestrator Safe Lab CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Run a single offline fixture")
    run_parser.add_argument("--fixture", required=True, help="Path to fixture directory")
    run_parser.add_argument("--profile-set", default="mixed_default", help="Profile set name")
    run_parser.add_argument("--profiles", default=str(DEFAULT_PROFILES), help="Path to profile config JSON")
    run_parser.add_argument("--outputs-root", default=str(DEFAULT_OUTPUTS), help="Directory for run outputs")
    run_parser.set_defaults(func=cmd_run)

    bench_parser = sub.add_parser("benchmark", help="Run benchmark across all fixtures")
    bench_parser.add_argument("--fixtures-dir", default=str(DEFAULT_FIXTURES), help="Directory containing fixtures")
    bench_parser.add_argument("--profiles", default=str(DEFAULT_PROFILES), help="Path to profile config JSON")
    bench_parser.add_argument("--profile-sets", default="", help="Comma-separated subset of profile set names")
    bench_parser.add_argument("--outputs-root", default=str(DEFAULT_OUTPUTS), help="Directory for run outputs")
    bench_parser.add_argument("--out", required=True, help="Path to benchmark JSON output")
    bench_parser.set_defaults(func=cmd_benchmark)

    profiles_parser = sub.add_parser("profiles", help="List available profiles and profile sets")
    profiles_parser.add_argument("--profiles", default=str(DEFAULT_PROFILES), help="Path to profile config JSON")
    profiles_parser.set_defaults(func=cmd_profiles)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
