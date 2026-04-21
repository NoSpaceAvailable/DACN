from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from vapt_orchestrator_safe.config import (
    DEFAULT_FIXTURES,
    DEFAULT_OUTPUTS,
    DEFAULT_PROFILES,
    get_ollama_env,
    load_profiles,
)
from vapt_orchestrator_safe.engine.benchmark import BenchmarkRunner
from vapt_orchestrator_safe.engine.dispatcher_runner import DispatcherRunner
from vapt_orchestrator_safe.engine.orchestrator import Orchestrator
from vapt_orchestrator_safe.llm.registry import OllamaConfig, parse_backend
from vapt_orchestrator_safe.utils.io import ensure_dir


# ── helpers ──────────────────────────────────────────────────────────────────
def _resolve_ollama_config(backend: str) -> OllamaConfig | None:
    """Build an OllamaConfig from env, or return None for non-ollama backends.

    Raises with a clear message if backend=ollama:* but env is incomplete.
    """
    kind, _ = parse_backend(backend)
    if kind != "ollama":
        return None
    env = get_ollama_env()
    base_url = env["base_url"]
    if not base_url:
        raise SystemExit(
            "OLLAMA_BASE_URL is not set. Add it to .env.local or your shell, e.g.:\n"
            "  export OLLAMA_BASE_URL=http://157.245.195.74"
        )
    timeout_raw = env.get("timeout") or "180"
    try:
        timeout = int(timeout_raw)
    except ValueError:
        raise SystemExit(f"OLLAMA_TIMEOUT must be an integer, got: {timeout_raw!r}")
    return OllamaConfig(base_url=base_url, token=env.get("token"), timeout=timeout)


# ── subcommand handlers ──────────────────────────────────────────────────────
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
    ollama_config = _resolve_ollama_config(args.llm)
    orchestrator = Orchestrator(
        profile_set_name=args.profile_set,
        profiles_path=Path(args.profiles),
        outputs_root=Path(args.outputs_root),
        backend=args.llm,
        ollama_config=ollama_config,
    )
    summary = orchestrator.run_fixture(fixture)
    print(f"Run complete: {summary['status']}")
    print(f"Backend:      {summary.get('backend', '?')}")
    print(f"Output dir:   {summary['output_dir']}")
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
    ollama_config = _resolve_ollama_config(args.llm)

    def factory(profile_set_name: str) -> Orchestrator:
        return Orchestrator(
            profile_set_name=profile_set_name,
            profiles_path=profiles_path,
            outputs_root=outputs_root,
            backend=args.llm,
            ollama_config=ollama_config,
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


def cmd_dispatch(args: argparse.Namespace) -> int:
    """Run a fixture through the v2 LLM-driven Dispatcher (Claude-CLI style).

    Routes the supervisor LLM via the LangChain backend factory — set
    ``LLM_BACKEND_DISPATCHER`` (or ``LLM_BACKEND_DEFAULT``) in the env,
    e.g. ``ollama:gemma4:e2b`` / ``openai:gpt-5-mini`` / ``anthropic:claude-sonnet-4-5``.
    Sub-agents still use the legacy --llm backend for now (that will
    migrate to LangChain in later sprints).
    """
    fixture = Path(args.fixture)
    ollama_config = _resolve_ollama_config(args.llm)
    runner = DispatcherRunner(
        profile_set_name=args.profile_set,
        profiles_path=Path(args.profiles),
        outputs_root=Path(args.outputs_root),
        backend=args.llm,
        ollama_config=ollama_config,
        max_steps=args.max_steps,
    )
    summary = runner.run_fixture(fixture, goal=args.goal)
    print(f"Dispatcher run complete: {summary['status']}")
    print(f"Supervisor backend: {summary.get('backend', '?')}")
    print(f"Sub-agent backend:  {runner.model_registry.backend_label}")
    print(f"Steps taken:        {summary['steps']} (stop_reason={summary['stop_reason']})")
    print(f"Tool invocations:   {len(summary['tool_invocations'])}")
    print(f"Output dir:         {summary['output_dir']}")
    print(f"Validated findings: {len(summary.get('validated_findings', []))}")
    return 0


def cmd_ablation(args: argparse.Namespace) -> int:
    """Run the DACN ablation matrix — baseline × C2 × C3 × C1 × all.

    Uses a canned scripted chat model per fixture so runs are
    reproducible without API cost. For a real-LLM ablation, wire a
    different factory via the programmatic API (not exposed on CLI yet).
    """
    from langchain_core.messages import AIMessage
    from vapt_orchestrator_safe.engine.ablation import run_ablation

    fixtures_dir = Path(args.fixtures_dir)
    out_dir = ensure_dir(Path(args.outputs_root))
    fixtures = sorted(p for p in fixtures_dir.iterdir() if p.is_dir())
    if not fixtures:
        raise SystemExit(f"No fixtures found in {fixtures_dir!r}")

    # Canned script — tries the highest-confidence family for each fixture.
    fixture_family = {
        "challenge_idor_01": "IDOR",
        "challenge_ssrf_01": "SSRF",
        "challenge_sqli_01": "SQLi",
    }

    def factory(fixture_name: str, config_name: str):
        family = fixture_family.get(fixture_name, "IDOR")
        script = [
            AIMessage(content="", tool_calls=[{"id": "r1", "name": "invoke_recon", "args": {}}]),
            AIMessage(content="", tool_calls=[{"id": "s1", "name": "invoke_signature", "args": {}}]),
            AIMessage(content="", tool_calls=[{"id": "a1", "name": "invoke_analyst", "args": {}}]),
            AIMessage(content="", tool_calls=[{"id": "k1", "name": "query_kg",
                                               "args": {"attack_family": family}}]),
            AIMessage(content="", tool_calls=[{"id": "e1", "name": "invoke_exploit",
                                               "args": {"attack_family": family}}]),
            AIMessage(content="", tool_calls=[{"id": "rp", "name": "invoke_report", "args": {}}]),
            AIMessage(content=f"Confirmed {family}.", tool_calls=[]),
        ]
        return _ScriptedChatModel(script)

    report = run_ablation(
        fixtures=fixtures,
        chat_model_factory=factory,
        outputs_root=out_dir,
        max_steps=args.max_steps,
    )
    report_path = out_dir / "ablation_report.json"
    report_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    md_path = out_dir / "ablation_report.md"
    md_path.write_text(report.to_markdown(), encoding="utf-8")
    print(f"Ablation done. {len(report.rows)} runs across {len(fixtures)} fixtures.")
    print(f"  JSON: {report_path}")
    print(f"  MD:   {md_path}")
    return 0


class _ScriptedChatModel:
    """Minimal scripted chat model shared between CLI + tests."""

    def __init__(self, script):
        self._script = iter(script)

    def bind_tools(self, _tools):
        return self

    def invoke(self, _messages, **_kwargs):
        return next(self._script)


def cmd_llm_test(args: argparse.Namespace) -> int:
    """Probe the configured Ollama backend without running a full pipeline.

    Useful as a smoke test after running infra/vps-setup.sh.
    """
    from vapt_orchestrator_safe.llm.ollama_model import OllamaError, OllamaModel
    from vapt_orchestrator_safe.types import ModelProfile

    ollama_config = _resolve_ollama_config(args.llm)
    if ollama_config is None:
        raise SystemExit("llm-test only supports the ollama:* backend (got: %s)" % args.llm)
    _, model_tag = parse_backend(args.llm)
    if not model_tag:
        raise SystemExit("Backend must be ollama:<model_tag> (e.g. ollama:gemma4:e2b)")

    # Throwaway profile — only the label is read back in summarize().
    dummy_profile = ModelProfile(
        name="probe", label="probe",
        reasoning=0.0, analysis=0.0, coding=0.0, reporting=0.0, recon=0.0, validation=0.0,
        cost_per_step=0.0, simulated_tokens_per_step=0,
    )
    model = OllamaModel(
        profile=dummy_profile,
        base_url=ollama_config.base_url,
        model_name=model_tag,
        token=ollama_config.token,
        timeout=ollama_config.timeout,
    )

    print(f"-> {ollama_config.base_url}  (model={model_tag}, timeout={ollama_config.timeout}s)")
    try:
        tags = model.list_tags()
    except OllamaError as exc:
        print(f"FAIL list_tags: {exc}")
        return 2
    print(f"  /api/tags OK — {len(tags)} model(s) available: {', '.join(tags) or '(none)'}")
    if model_tag not in tags:
        print(f"  WARN: '{model_tag}' is not in the server's model list; pull it on the VPS first.")

    prompt = args.prompt or "Reply with the single word OK."
    try:
        result = model.generate(prompt, options={"temperature": 0.0})
    except OllamaError as exc:
        print(f"FAIL generate: {exc}")
        return 3
    print(
        f"  /api/generate OK — prompt_tokens={result.prompt_tokens}, "
        f"completion_tokens={result.completion_tokens}, "
        f"duration_ms={result.total_duration_ns // 1_000_000}"
    )
    print("  -- response --")
    print(result.text.strip()[:1000])
    return 0


# ── parser ───────────────────────────────────────────────────────────────────
def _add_llm_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--llm",
        default="rule",
        help="LLM backend: 'rule' (default offline) or 'ollama:<model_tag>' "
             "(e.g. ollama:gemma4:e2b). Reads OLLAMA_BASE_URL/OLLAMA_TOKEN/OLLAMA_TIMEOUT "
             "from env or .env.local.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VAPT Orchestrator Safe Lab CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Run a single offline fixture")
    run_parser.add_argument("--fixture", required=True, help="Path to fixture directory")
    run_parser.add_argument("--profile-set", default="mixed_default", help="Profile set name")
    run_parser.add_argument("--profiles", default=str(DEFAULT_PROFILES), help="Path to profile config JSON")
    run_parser.add_argument("--outputs-root", default=str(DEFAULT_OUTPUTS), help="Directory for run outputs")
    _add_llm_arg(run_parser)
    run_parser.set_defaults(func=cmd_run)

    bench_parser = sub.add_parser("benchmark", help="Run benchmark across all fixtures")
    bench_parser.add_argument("--fixtures-dir", default=str(DEFAULT_FIXTURES), help="Directory containing fixtures")
    bench_parser.add_argument("--profiles", default=str(DEFAULT_PROFILES), help="Path to profile config JSON")
    bench_parser.add_argument("--profile-sets", default="", help="Comma-separated subset of profile set names")
    bench_parser.add_argument("--outputs-root", default=str(DEFAULT_OUTPUTS), help="Directory for run outputs")
    bench_parser.add_argument("--out", required=True, help="Path to benchmark JSON output")
    _add_llm_arg(bench_parser)
    bench_parser.set_defaults(func=cmd_benchmark)

    profiles_parser = sub.add_parser("profiles", help="List available profiles and profile sets")
    profiles_parser.add_argument("--profiles", default=str(DEFAULT_PROFILES), help="Path to profile config JSON")
    profiles_parser.set_defaults(func=cmd_profiles)

    dispatch_parser = sub.add_parser(
        "dispatch",
        help="Run a fixture through the LLM-driven Dispatcher (v2 pipeline)",
    )
    dispatch_parser.add_argument("--fixture", required=True, help="Path to fixture directory")
    dispatch_parser.add_argument(
        "--profile-set", default="mixed_default",
        help="Sub-agent profile set (for legacy BaseAgents)",
    )
    dispatch_parser.add_argument(
        "--profiles", default=str(DEFAULT_PROFILES),
        help="Path to profile config JSON",
    )
    dispatch_parser.add_argument(
        "--outputs-root", default=str(DEFAULT_OUTPUTS),
        help="Directory for run outputs",
    )
    dispatch_parser.add_argument(
        "--max-steps", type=int, default=20,
        help="Hard cap on dispatcher tool-use iterations (default: 20)",
    )
    dispatch_parser.add_argument(
        "--goal", default=None,
        help="Natural-language goal for the dispatcher (default: built-in).",
    )
    _add_llm_arg(dispatch_parser)
    dispatch_parser.set_defaults(func=cmd_dispatch)

    ablation_parser = sub.add_parser(
        "ablation",
        help="Run the DACN ablation matrix (baseline × C2 × C3 × C1 × all) offline",
    )
    ablation_parser.add_argument("--fixtures-dir", default=str(DEFAULT_FIXTURES),
                                 help="Directory of fixture dirs")
    ablation_parser.add_argument("--outputs-root", default=str(DEFAULT_OUTPUTS / "ablation"),
                                 help="Where to write run dirs + ablation_report.{json,md}")
    ablation_parser.add_argument("--max-steps", type=int, default=15)
    ablation_parser.set_defaults(func=cmd_ablation)

    llm_test_parser = sub.add_parser(
        "llm-test", help="Probe the configured Ollama backend (list tags + 1 generate call)"
    )
    _add_llm_arg(llm_test_parser)
    llm_test_parser.add_argument(
        "--prompt", default=None, help="Prompt to send (default: 'Reply with the single word OK.')"
    )
    llm_test_parser.set_defaults(func=cmd_llm_test)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
