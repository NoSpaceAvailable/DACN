"""Single-case real-LLM eval runner.

This module is intentionally process-friendly: the Kaggle/Colab notebook can
run one fixture/config case in a child Python process and enforce a wall-clock
timeout from the parent. If an Ollama generation stalls, the notebook records a
timeout row and continues the benchmark instead of blocking the whole matrix.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict

from vapt_orchestrator_safe.engine.dispatcher_runner import DispatcherRunner
from vapt_orchestrator_safe.llm.backend_factory import build_chat_model
from vapt_orchestrator_safe.llm.registry import OllamaConfig


ABLATION_CONFIGS: Dict[str, Dict[str, bool]] = {
    "baseline": {"enable_anti_loop": False, "enable_kg": False, "enable_mid_thinking": False},
    "C2_only": {"enable_anti_loop": True, "enable_kg": False, "enable_mid_thinking": False},
    "C3_only": {"enable_anti_loop": False, "enable_kg": True, "enable_mid_thinking": False},
    "C1_only": {"enable_anti_loop": False, "enable_kg": False, "enable_mid_thinking": True},
    "all": {"enable_anti_loop": True, "enable_kg": True, "enable_mid_thinking": True},
}


def run_eval_case(
    *,
    model: str,
    fixture: Path,
    config_name: str,
    base_url: str,
    outputs_root: Path,
    max_steps: int,
    request_timeout_s: int,
    temperature: float,
    num_ctx: int,
    provider: str = "ollama",
    call_delay_s: float = 0.0,
    require_source_read: bool = False,
) -> Dict[str, Any]:
    if config_name not in ABLATION_CONFIGS:
        raise ValueError(f"Unknown config {config_name!r}; expected one of {sorted(ABLATION_CONFIGS)}")

    backend_spec = f"{provider}:{model}"

    if provider == "ollama":
        chat_model = build_chat_model(
            backend_spec,
            base_url=base_url,
            temperature=temperature,
            num_ctx=num_ctx,
            timeout=request_timeout_s,
        )
        ollama_config: OllamaConfig | None = OllamaConfig(
            base_url=base_url,
            timeout=request_timeout_s,
            default_options={"temperature": temperature, "num_ctx": num_ctx},
        )
    else:
        chat_model = build_chat_model(
            backend_spec,
            temperature=temperature,
            timeout=request_timeout_s,
            max_retries=5,
        )
        ollama_config = None

    runner = DispatcherRunner(
        outputs_root=outputs_root,
        backend=backend_spec,
        ollama_config=ollama_config,
        chat_model=chat_model,
        chat_model_backend_spec=backend_spec,
        max_steps=max_steps,
        enable_sandbox=False,
        call_delay_s=call_delay_s,
        require_source_read=require_source_read,
        **ABLATION_CONFIGS[config_name],
    )

    fixture = fixture.resolve()
    t0 = time.perf_counter()
    try:
        summary = runner.run_fixture(fixture)
        wall_s = time.perf_counter() - t0
        status = summary["status"]
        error = ""
    except Exception as exc:
        wall_s = time.perf_counter() - t0
        summary = {}
        status = f"error:{type(exc).__name__}"
        error = str(exc)

    loop_detected = 0
    out_dir = summary.get("output_dir", "")
    if out_dir:
        mem_path = Path(out_dir) / "memory.json"
        if mem_path.exists():
            events = json.loads(mem_path.read_text(encoding="utf-8")).get("events", [])
            loop_detected = sum(1 for e in events if e.get("message") == "loop_detected")

    row: Dict[str, Any] = {
        "model": model,
        "fixture": fixture.name,
        "config": config_name,
        "status": status,
        "stop_reason": summary.get("stop_reason", "?"),
        "steps": summary.get("steps", 0),
        "tool_calls": len(summary.get("tool_invocations", [])),
        "validated_findings": len(summary.get("validated_findings", [])),
        "loop_detected": loop_detected,
        "watchdog_trips": len(summary.get("watchdog_trips", [])),
        "wall_s": round(wall_s, 2),
        "budget_tokens": summary.get("budget", {}).get("simulated_tokens", 0),
        "budget_cost": summary.get("budget", {}).get("simulated_cost", 0),
        "output_dir": out_dir,
    }
    if error:
        row["error"] = error[:1000]
    return row


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one real-LLM eval case and emit one JSON row.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--config", required=True, choices=sorted(ABLATION_CONFIGS))
    parser.add_argument("--base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--provider", default="ollama", help="Backend provider: ollama, custom, openai, anthropic, openrouter")
    parser.add_argument("--outputs-root", required=True)
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--request-timeout-s", type=int, default=300)
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--num-ctx", type=int, default=8192)
    parser.add_argument("--row-out", default=None, help="Optional path to write the JSON row.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    row = run_eval_case(
        model=args.model,
        fixture=Path(args.fixture),
        config_name=args.config,
        base_url=args.base_url,
        outputs_root=Path(args.outputs_root),
        max_steps=args.max_steps,
        request_timeout_s=args.request_timeout_s,
        temperature=args.temperature,
        num_ctx=args.num_ctx,
        provider=args.provider,
    )
    text = json.dumps(row, ensure_ascii=False)
    if args.row_out:
        Path(args.row_out).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
