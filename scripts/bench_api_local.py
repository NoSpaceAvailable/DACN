"""Local benchmark — run the eval matrix against ANY chat-completions API.

The script wraps any OpenAI-compatible endpoint (Mistral, Groq, OpenRouter,
DeepSeek, Together, Fireworks, Cerebras, SambaNova, Hyperbolic, vLLM, LM Studio,
self-hosted, ...) plus the native OpenAI and Anthropic providers. You only need
three things:

    1. --provider  : a registered provider key (see PROVIDERS below) OR
                     a raw backend kind: `custom`, `openai`, `anthropic`, `openrouter`
    2. --model     : the model id the provider expects (e.g. mistral-large-latest,
                     llama-3.3-70b-versatile, gpt-4o, claude-sonnet-4-5)
    3. --api-key   : the API token (or set the corresponding env var)

Run `python scripts/bench_api_local.py --list-providers` to see every alias
registered (mistral, groq, gemini, anthropic, openai, openrouter, deepseek,
together, fireworks, cerebras, sambanova, hyperbolic, xai, perplexity, cohere,
vllm, lmstudio, ollama_oai, custom, ...).

Examples (PowerShell)::

    # Mistral free tier
    python scripts/bench_api_local.py `
        --provider mistral --model mistral-large-latest --api-key $env:MISTRAL_API_KEY

    # Gemini (OpenAI-compat endpoint — no extra dep, just langchain-openai)
    python scripts/bench_api_local.py `
        --provider gemini --model gemini-2.5-flash --api-key $env:GEMINI_API_KEY

    # Anthropic — claude-sonnet (advisor-target reference model for DACN ≥80% goal).
    # Requires `pip install langchain-anthropic` once.
    python scripts/bench_api_local.py `
        --provider anthropic --model claude-sonnet-4-5 --api-key $env:ANTHROPIC_API_KEY `
        --fixtures live_gatekeeping --configs all --live --max-steps 40

    # OpenAI — gpt-5-mini (the other advisor-target reference model). Use this
    # alongside the claude-sonnet run to isolate "harness limit vs model limit"
    # on a hard logic-bug fixture (e.g. live_gatekeeping).
    python scripts/bench_api_local.py `
        --provider openai --model gpt-5-mini --api-key $env:OPENAI_API_KEY `
        --fixtures live_gatekeeping --configs all --live --max-steps 40

    # Groq free tier (fast Llama 3.3 70B)
    python scripts/bench_api_local.py `
        --provider groq --model llama-3.3-70b-versatile --api-key $env:GROQ_API_KEY

    # OpenRouter free tier — pass any model slug they host
    python scripts/bench_api_local.py `
        --provider openrouter --model meta-llama/llama-3.3-70b-instruct:free `
        --api-key $env:OPENROUTER_API_KEY

    # Self-hosted vLLM / LM Studio — pass the base URL explicitly
    python scripts/bench_api_local.py `
        --provider vllm --base-url http://localhost:8000/v1 `
        --model Qwen/Qwen2.5-Coder-7B-Instruct --api-key EMPTY

    # Subset for a quick smoke test (2 fixtures × 2 configs = 4 runs)
    python scripts/bench_api_local.py --provider mistral --model mistral-small-latest `
        --api-key $env:MISTRAL_API_KEY `
        --fixtures challenge_idor_01 challenge_ssrf_01 `
        --configs baseline all

Outputs (resume-safe):
    outputs/bench_local_<provider>_<model>.jsonl
    outputs/bench_local_<provider>_<model>.csv
    outputs/bench_local_<provider>_<model>.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.exists() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vapt_orchestrator_safe.engine.eval_case import ABLATION_CONFIGS, run_eval_case  # noqa: E402
from vapt_orchestrator_safe.config import _load_dotenv_if_present  # noqa: E402

# Pull .env into os.environ so keys (MISTRAL_API_KEY, GEMINI_API_KEY, ...) and
# MISTRAL_MODEL_ID are picked up without passing --api-key on the CLI.
_load_dotenv_if_present()


_DEFAULT_FIXTURES = [f"web-{i:03d}" for i in range(1, 21)]


# ── Provider registry ─────────────────────────────────────────────────────
#
# Each entry maps a friendly provider alias → (backend kind, base URL, env var
# the API key should land in). The script copies the supplied --api-key into
# the right env var so backend_factory.build_chat_model() finds it.
#
# `backend_kind` is one of: openai, anthropic, openrouter, custom — matching
# what backend_factory.parse_spec() understands.

@dataclass(frozen=True)
class ProviderEntry:
    backend_kind: str
    base_url: Optional[str]
    api_key_env: str
    key_lookup_envs: tuple = ()  # extra envs to scan for the key when --api-key not given


PROVIDERS: Dict[str, ProviderEntry] = {
    # ── Native SDKs (no base_url; requires langchain-openai / -anthropic) ──
    "openai":     ProviderEntry("openai", None, "OPENAI_API_KEY"),
    "anthropic":  ProviderEntry("anthropic", None, "ANTHROPIC_API_KEY"),
    "openrouter": ProviderEntry("openrouter", None, "OPENROUTER_API_KEY"),

    # ── OpenAI-compatible HTTP endpoints (ride on `custom` kind) ──
    "mistral":    ProviderEntry("custom", "https://api.mistral.ai/v1",
                                "LLM_CUSTOM_API_KEY", ("MISTRAL_API_KEY",)),
    "groq":       ProviderEntry("custom", "https://api.groq.com/openai/v1",
                                "LLM_CUSTOM_API_KEY", ("GROQ_API_KEY",)),
    "deepseek":   ProviderEntry("custom", "https://api.deepseek.com/v1",
                                "LLM_CUSTOM_API_KEY", ("DEEPSEEK_API_KEY",)),
    "together":   ProviderEntry("custom", "https://api.together.xyz/v1",
                                "LLM_CUSTOM_API_KEY", ("TOGETHER_API_KEY",)),
    "fireworks":  ProviderEntry("custom", "https://api.fireworks.ai/inference/v1",
                                "LLM_CUSTOM_API_KEY", ("FIREWORKS_API_KEY",)),
    "cerebras":   ProviderEntry("custom", "https://api.cerebras.ai/v1",
                                "LLM_CUSTOM_API_KEY", ("CEREBRAS_API_KEY",)),
    "sambanova":  ProviderEntry("custom", "https://api.sambanova.ai/v1",
                                "LLM_CUSTOM_API_KEY", ("SAMBANOVA_API_KEY",)),
    "hyperbolic": ProviderEntry("custom", "https://api.hyperbolic.xyz/v1",
                                "LLM_CUSTOM_API_KEY", ("HYPERBOLIC_API_KEY",)),
    "nebius":     ProviderEntry("custom", "https://api.studio.nebius.ai/v1",
                                "LLM_CUSTOM_API_KEY", ("NEBIUS_API_KEY",)),
    "novita":     ProviderEntry("custom", "https://api.novita.ai/v3/openai",
                                "LLM_CUSTOM_API_KEY", ("NOVITA_API_KEY",)),
    "gemini":     ProviderEntry("custom",
                                "https://generativelanguage.googleapis.com/v1beta/openai/",
                                "LLM_CUSTOM_API_KEY",
                                ("GEMINI_API_KEY", "GOOGLE_API_KEY")),
    "xai":        ProviderEntry("custom", "https://api.x.ai/v1",
                                "LLM_CUSTOM_API_KEY", ("XAI_API_KEY",)),
    "perplexity": ProviderEntry("custom", "https://api.perplexity.ai",
                                "LLM_CUSTOM_API_KEY", ("PERPLEXITY_API_KEY",)),
    "cohere":     ProviderEntry("custom", "https://api.cohere.com/compatibility/v1",
                                "LLM_CUSTOM_API_KEY", ("COHERE_API_KEY",)),

    # ── Self-hosted / generic OpenAI-compatible. --base-url is REQUIRED. ──
    "vllm":      ProviderEntry("custom", None, "LLM_CUSTOM_API_KEY"),
    "lmstudio":  ProviderEntry("custom", "http://localhost:1234/v1", "LLM_CUSTOM_API_KEY"),
    "ollama_oai": ProviderEntry("custom", "http://localhost:11434/v1", "LLM_CUSTOM_API_KEY"),
    "custom":    ProviderEntry("custom", None, "LLM_CUSTOM_API_KEY"),
}


def _resolve_provider(name: str) -> ProviderEntry:
    entry = PROVIDERS.get(name.lower())
    if entry is None:
        registered = ", ".join(sorted(PROVIDERS))
        raise SystemExit(
            f"Unknown --provider '{name}'. Registered: {registered}. "
            f"For something not in this list, use '--provider custom --base-url <url>'."
        )
    return entry


def _find_api_key(cli_value: Optional[str], entry: ProviderEntry) -> Optional[str]:
    """Pick the API key from: --api-key flag → primary env → fallback envs."""
    if cli_value:
        return cli_value
    for env in (entry.api_key_env, *entry.key_lookup_envs):
        v = os.environ.get(env)
        if v:
            return v
    return None


def _configure_env(
    provider_name: str,
    entry: ProviderEntry,
    api_key: Optional[str],
    base_url: Optional[str],
) -> None:
    """Materialise env vars that backend_factory expects for the resolved backend."""
    kind = entry.backend_kind

    # Resolve base URL (CLI overrides registry default).
    final_base_url = base_url or entry.base_url

    if kind == "custom":
        if not final_base_url:
            raise SystemExit(
                f"Provider '{provider_name}' has no default base URL. "
                f"Pass --base-url explicitly."
            )
        os.environ["LLM_CUSTOM_BASE_URL"] = final_base_url
        if not api_key:
            raise SystemExit(
                f"No API key found. Pass --api-key or set one of: "
                f"{', '.join((entry.api_key_env, *entry.key_lookup_envs))}"
            )
        os.environ["LLM_CUSTOM_API_KEY"] = api_key

    elif kind == "openai":
        if not api_key:
            raise SystemExit("Set OPENAI_API_KEY or pass --api-key.")
        os.environ["OPENAI_API_KEY"] = api_key
        if final_base_url:
            os.environ["OPENAI_BASE_URL"] = final_base_url

    elif kind == "anthropic":
        if not api_key:
            raise SystemExit("Set ANTHROPIC_API_KEY or pass --api-key.")
        os.environ["ANTHROPIC_API_KEY"] = api_key

    elif kind == "openrouter":
        if not api_key:
            raise SystemExit("Set OPENROUTER_API_KEY or pass --api-key.")
        os.environ["OPENROUTER_API_KEY"] = api_key

    else:
        raise SystemExit(f"Unsupported backend kind {kind!r}")


def _safe_tag(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--provider",
                        help=f"Provider alias. Registered: {', '.join(sorted(PROVIDERS))}")
    parser.add_argument("--model",
                        help="Model id as the provider expects (e.g. mistral-large-latest)")
    parser.add_argument("--api-key", default=None,
                        help="API key. If omitted, read from the provider's env var.")
    parser.add_argument("--base-url", default=None,
                        help="Override base URL. Required for vllm/lmstudio/custom without preset.")
    parser.add_argument("--fixtures", nargs="*", default=_DEFAULT_FIXTURES,
                        help="Fixture names under data/fixtures/")
    parser.add_argument("--configs", nargs="*", default=list(ABLATION_CONFIGS),
                        help=f"Ablation configs (any of {sorted(ABLATION_CONFIGS)})")
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--request-timeout-s", type=int, default=120)
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--num-ctx", type=int, default=8192)
    parser.add_argument("--sleep-between", type=float, default=1.5,
                        help="Seconds to sleep between runs (avoid rate limits).")
    parser.add_argument("--call-delay", type=float, default=None,
                        help="Seconds to pace EACH dispatcher LLM call within a run. "
                             "Default depends on provider — 2.0 for mistral (1 RPS free "
                             "tier), 10.0 for openai/anthropic (TPM-bound reasoning models "
                             "where a single call can be 30-50k tokens), 6.0 for "
                             "openrouter/gemini/groq (10-RPM tiers), 0 for paid/unlimited. "
                             "Auto-bumps up to 30s after each rate-limit hit "
                             "(adaptive throttling).")
    parser.add_argument("--reasoning-effort", choices=("low", "medium", "high"), default=None,
                        help="Enable reasoning / thinking mode for models that support it. "
                             "Forwarded as `reasoning_effort` in the request body — works for "
                             "OpenAI o-series/gpt-5, Gemini (maps to thinking_budget via the "
                             "OpenAI-compat endpoint), and any OpenAI-compatible provider that "
                             "accepts the param. Anthropic's `thinking` block uses a different "
                             "shape and is not handled here.")
    parser.add_argument("--require-source-read", action="store_true",
                        help="Force the model to read the source before finishing "
                             "(completion guard for genuine source analysis).")
    parser.add_argument("--live", action="store_true",
                        help="Live-exploit mode: boot each fixture's docker-compose "
                             "(manifest 'live' block) and let the agent capture the flag. "
                             "Metric becomes solve-rate.")
    parser.add_argument("--trace", action="store_true",
                        help="Print the agent's per-step thinking, tool calls, and tool "
                             "outputs to stdout as the run progresses (sets DACN_TRACE=1).")
    parser.add_argument("--outputs-dir", default=str(ROOT / "outputs"))
    parser.add_argument("--list-providers", action="store_true",
                        help="Print the registered providers and exit.")
    args = parser.parse_args()

    if args.trace:
        os.environ["DACN_TRACE"] = "1"

    if args.list_providers:
        for name in sorted(PROVIDERS):
            p = PROVIDERS[name]
            url = p.base_url or "(needs --base-url)"
            envs = "/".join((p.api_key_env, *p.key_lookup_envs))
            print(f"  {name:12s}  kind={p.backend_kind:10s}  base={url}  key_env={envs}")
        return 0

    if not args.provider or not args.model:
        parser.error("--provider and --model are required (or use --list-providers).")

    entry = _resolve_provider(args.provider)
    api_key = _find_api_key(args.api_key, entry)
    _configure_env(args.provider, entry, api_key, args.base_url)

    # backend_factory consumes `provider:model` (e.g. custom:mistral-large-latest).
    eval_case_provider = entry.backend_kind

    # Provider-aware default for per-call pacing. OpenAI / Anthropic tier-1 are
    # TPM-bound and one dispatcher call can be 30-50k tokens — 2s pacing burns
    # the quota in a few seconds. Honour the user's --call-delay if they passed
    # it explicitly.
    if args.call_delay is None:
        kind = entry.backend_kind
        if kind in ("openai", "anthropic"):
            args.call_delay = 10.0
        elif args.provider in ("openrouter", "gemini", "groq"):
            args.call_delay = 6.0
        else:
            args.call_delay = 2.0
        print(f"call_delay (auto, provider={args.provider}): {args.call_delay}s")

    outputs_dir = Path(args.outputs_dir)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    tag = f"{_safe_tag(args.provider)}_{_safe_tag(args.model)}"
    jsonl_path = outputs_dir / f"bench_local_{tag}.jsonl"
    csv_path = outputs_dir / f"bench_local_{tag}.csv"
    json_path = outputs_dir / f"bench_local_{tag}.json"

    results: List[dict] = []
    completed: set = set()
    if jsonl_path.exists():
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                results.append(row)
                completed.add((row["model"], row["fixture"], row["config"]))
        print(f"Resumed {len(results)} rows from {jsonl_path}")

    fixture_dirs = [ROOT / "data" / "fixtures" / name for name in args.fixtures]
    for fd in fixture_dirs:
        if not fd.exists():
            raise SystemExit(f"Fixture not found: {fd}")

    total = len(fixture_dirs) * len(args.configs)
    idx = 0
    bench_t0 = time.perf_counter()

    print(f"\nProvider: {args.provider}  →  backend_kind={entry.backend_kind}")
    print(f"Model:    {args.model}")
    print(f"Matrix:   {len(fixture_dirs)} fixtures × {len(args.configs)} configs = {total} runs\n")

    for fixture in fixture_dirs:
        for cfg in args.configs:
            idx += 1
            key = (args.model, fixture.name, cfg)
            print(f"[{idx}/{total}] {args.provider}:{args.model}  fixture={fixture.name}  config={cfg}")

            if key in completed:
                print("  SKIP: already present in jsonl")
                continue

            t0 = time.perf_counter()
            try:
                row = run_eval_case(
                    model=args.model,
                    provider=eval_case_provider,
                    fixture=fixture,
                    config_name=cfg,
                    base_url="",  # not used by non-ollama providers
                    outputs_root=outputs_dir / f"runs_{tag}",
                    max_steps=args.max_steps,
                    request_timeout_s=args.request_timeout_s,
                    temperature=args.temperature,
                    num_ctx=args.num_ctx,
                    call_delay_s=args.call_delay,
                    require_source_read=args.require_source_read,
                    enable_live_exploit=args.live,
                    reasoning_effort=args.reasoning_effort,
                )
            except Exception as exc:
                wall_s = time.perf_counter() - t0
                row = {
                    "model": args.model,
                    "fixture": fixture.name,
                    "config": cfg,
                    "status": f"error:{type(exc).__name__}",
                    "stop_reason": "?",
                    "steps": 0,
                    "tool_calls": 0,
                    "validated_findings": 0,
                    "llm_findings": 0,
                    "solved": False,
                    "expected_vuln": "",
                    "detected": 0,
                    "loop_detected": 0,
                    "watchdog_trips": 0,
                    "wall_s": round(wall_s, 2),
                    "budget_tokens": 0,
                    "budget_cost": 0,
                    "error": str(exc)[:1000],
                }

            results.append(row)
            completed.add(key)
            with open(jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

            flag = "S" if row.get("solved") else ("D" if row.get("detected") else "-")
            elapsed = time.perf_counter() - bench_t0
            eta = (elapsed / idx) * (total - idx)
            print(f"  [{flag}] {row['status']}  steps={row['steps']}  tools={row['tool_calls']}  "
                  f"findings={row.get('llm_findings', 0)} (exp={row.get('expected_vuln','?')})  wall={row['wall_s']:.1f}s")
            print(f"  Elapsed {elapsed/60:.1f}m | ETA {eta/60:.1f}m")
            if row.get("error"):
                print(f"  ERROR: {row['error'][:300]}")

            if args.sleep_between > 0 and idx < total:
                time.sleep(args.sleep_between)

    # Export CSV + final JSON
    summary: Dict[str, object] = {}
    try:
        import pandas as pd
        df = pd.DataFrame(results)
        # "detected" is computed per-row in eval_case (record_finding matches
        # ground truth, OR oracle-validated, OR solved). Fall back for old rows.
        if "detected" not in df.columns:
            df["detected"] = df["status"].isin(["solved", "validated", "supported"]).astype(int)
        df["detected"] = df["detected"].fillna(0).astype(int)
        # Đảm bảo cột token mới luôn có (CSV cũ thiếu) để aggregate không crash.
        for col in ("llm_tokens_in", "llm_tokens_out", "llm_calls", "wall_s"):
            if col not in df.columns:
                df[col] = 0
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        df.to_csv(csv_path, index=False)

        total_tok_in = int(df["llm_tokens_in"].sum())
        total_tok_out = int(df["llm_tokens_out"].sum())
        total_tok = total_tok_in + total_tok_out
        total_calls = int(df["llm_calls"].sum())
        total_wall_s = float(df["wall_s"].sum())

        summary = {
            "by_config": df.groupby("config")["detected"].mean().round(3).to_dict(),
            "by_fixture": df.groupby("fixture")["detected"].mean().round(3).to_dict(),
            "overall_detection_rate": round(float(df["detected"].mean()), 3),
            # Tổng kết token + thời gian cho toàn bộ phiên bench, dùng để so
            # cost giữa các model sau cùng (gemini-flash vs claude vs gpt-5-mini).
            "total_llm_tokens_in": total_tok_in,
            "total_llm_tokens_out": total_tok_out,
            "total_llm_tokens": total_tok,
            "total_llm_calls": total_calls,
            "total_wall_s": round(total_wall_s, 1),
            "avg_tokens_per_run": round(total_tok / max(1, len(df)), 1),
            "by_model_tokens": df.groupby("model")[
                ["llm_tokens_in", "llm_tokens_out"]
            ].sum().to_dict("index"),
        }
    except ImportError:
        pass

    json_path.write_text(json.dumps({
        "provider": args.provider,
        "backend_kind": entry.backend_kind,
        "model": args.model,
        "fixtures": [fd.name for fd in fixture_dirs],
        "configs": args.configs,
        "runs": results,
        "summary": summary,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n{'='*60}")
    print(f"Done: {len(results)} rows")
    print(f"  JSONL: {jsonl_path}")
    print(f"  CSV:   {csv_path}")
    print(f"  JSON:  {json_path}")
    if summary:
        print(f"  Overall detection rate: {summary['overall_detection_rate']}")
        print(f"  Total LLM tokens:  in={summary['total_llm_tokens_in']:,}  "
              f"out={summary['total_llm_tokens_out']:,}  "
              f"total={summary['total_llm_tokens']:,} "
              f"({summary['total_llm_calls']} calls, "
              f"{summary['avg_tokens_per_run']:.0f} tok/run avg)")
        print(f"  Total wall time:   {summary['total_wall_s']:.0f}s "
              f"({summary['total_wall_s']/60:.1f}m)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
