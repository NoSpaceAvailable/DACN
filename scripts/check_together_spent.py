"""Tính USD đã tiêu trên Together.ai từ jsonl bench (token thật).

Together.ai không expose endpoint balance public — chỉ dashboard web mới xem
được. Script này tính tổng spent từ các CSV/JSONL bench đã chạy, dùng pricing
trong scripts/plot_bench.py. Trừ vào credit ban đầu để estimate remaining.

Dùng:
    python scripts/check_together_spent.py
    python scripts/check_together_spent.py --initial-usd 25
    python scripts/check_together_spent.py outputs/together_*/bench_local_*.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Giữ bảng giá đồng bộ với scripts/plot_bench.py — nhưng inline để script này
# không phụ thuộc pandas (chạy được trên VPS không có pandas).
PROVIDER_PRICING_USD_PER_MTOK = {
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-3.1-flash-lite": (0.10, 0.40),
    "gpt-5-mini": (0.25, 2.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "mistral-medium-latest": (2.70, 8.10),
    "mistral-small-latest": (0.20, 0.60),
    "gemma-4-31b-it": (0.0, 0.0),
    "anthropic/claude-sonnet-4.5": (3.00, 15.00),
    "anthropic/claude-sonnet-4-5": (3.00, 15.00),
    "openai/gpt-5-mini": (0.25, 2.00),
    "openai/gpt-5": (1.25, 10.00),
    # Together.ai serverless
    "deepseek-ai/DeepSeek-V3.1": (0.60, 1.70),
    "deepseek-ai/DeepSeek-R1-0528": (3.00, 7.00),
    "deepseek-ai/DeepSeek-V4-Pro": (1.74, 3.48),
    "openai/gpt-oss-120b": (0.15, 0.60),
    "openai/gpt-oss-20b": (0.05, 0.20),
    "Qwen/Qwen3-235B-A22B-Instruct-2507-tput": (0.20, 0.60),
    "Qwen/Qwen3-235B-A22B-Instruct-2507-FP8": (0.0, 0.0),
    "meta-llama/Llama-3.3-70B-Instruct-Turbo": (1.04, 1.04),
    "moonshotai/Kimi-K2.6": (1.20, 4.50),
}


def cost_for_row(row: dict) -> float:
    model = row.get("model", "")
    pricing = PROVIDER_PRICING_USD_PER_MTOK.get(model)
    if not pricing:
        return 0.0
    p_in, p_out = pricing
    t_in = float(row.get("llm_tokens_in", 0) or 0)
    t_out = float(row.get("llm_tokens_out", 0) or 0)
    return (t_in * p_in + t_out * p_out) / 1_000_000


def infer_provider(model: str) -> str:
    """Đoán provider từ model id để group total — không hoàn hảo nhưng đủ
    để thấy 'Together vs Mistral vs Gemini' tốn bao nhiêu mỗi nhánh."""
    m = model.lower()
    if "/" in model:  # có namespace prefix → Together / OpenRouter style
        ns = model.split("/", 1)[0].lower()
        if ns in ("anthropic", "openai") and "claude" not in m and "gpt-5" not in m.replace("gpt-5-", ""):
            # OpenRouter trộn cả anthropic/ + openai/ — nhưng trên Together
            # cũng có openai/gpt-oss-*. Phân biệt: openai/gpt-5* = OpenRouter,
            # còn openai/gpt-oss-* = Together. Claude family = OpenRouter.
            return "together" if "gpt-oss" in m else "openrouter"
        if ns in ("qwen", "deepseek-ai", "meta-llama", "moonshotai", "openai", "anthropic"):
            return "together" if ns != "anthropic" else "openrouter"
        return ns
    if m.startswith("gemma") or m.startswith("gemini"):
        return "gemini"
    if m.startswith("mistral"):
        return "mistral"
    if "claude" in m:
        return "anthropic"
    return "?"


def collect(paths: list[Path]) -> tuple[dict[str, dict], float]:
    by_model: dict[str, dict] = {}
    total = 0.0
    for p in paths:
        if not p.exists():
            print(f"  SKIP: {p}")
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            m = row.get("model", "?")
            cost = cost_for_row(row)
            agg = by_model.setdefault(m, {
                "runs": 0, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0,
                "unpriced": False,
            })
            agg["runs"] += 1
            agg["tokens_in"] += int(row.get("llm_tokens_in", 0) or 0)
            agg["tokens_out"] += int(row.get("llm_tokens_out", 0) or 0)
            agg["cost_usd"] += cost
            if m not in PROVIDER_PRICING_USD_PER_MTOK and (agg["tokens_in"] + agg["tokens_out"]) > 0:
                agg["unpriced"] = True
            total += cost
    return by_model, total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", help="jsonl files (default: outputs/**/bench_local_*.jsonl)")
    parser.add_argument("--initial-usd", type=float, default=None,
                        help="Credit ban đầu của key (USD) — nếu biết, in luôn estimate remaining.")
    args = parser.parse_args()

    paths = [Path(p) for p in args.paths] if args.paths else sorted(
        (ROOT / "outputs").rglob("bench_local_*.jsonl")
    )
    if not paths:
        sys.exit("Không tìm thấy jsonl nào.")

    by_model, total = collect(paths)

    print(f"\n{'Model':<55s}  {'Provider':<10s}  {'Runs':>5s}  {'Tok in':>10s}  {'Tok out':>10s}  {'USD':>8s}")
    print("-" * 107)
    for m in sorted(by_model):
        a = by_model[m]
        mark = " ⚠️ no-pricing" if a["unpriced"] else ""
        print(f"{m:<55s}  {infer_provider(m):<10s}  {a['runs']:>5d}  {a['tokens_in']:>10,}  {a['tokens_out']:>10,}  ${a['cost_usd']:>7.4f}{mark}")
    print("-" * 107)

    # Subtotal theo provider — để thấy Together tốn bao nhiêu so với các key khác
    by_prov: dict[str, dict] = {}
    for m, a in by_model.items():
        prov = infer_provider(m)
        agg = by_prov.setdefault(prov, {"runs": 0, "cost": 0.0})
        agg["runs"] += a["runs"]
        agg["cost"] += a["cost_usd"]
    print(f"\n{'Provider':<15s}  {'Runs':>5s}  {'USD':>10s}")
    print("-" * 35)
    for prov in sorted(by_prov, key=lambda k: -by_prov[k]["cost"]):
        a = by_prov[prov]
        print(f"{prov:<15s}  {a['runs']:>5d}  ${a['cost']:>9.4f}")
    print("-" * 35)
    print(f"{'TOTAL':<15s}  {sum(a['runs'] for a in by_prov.values()):>5d}  ${total:>9.4f}")

    if args.initial_usd is not None:
        remaining = args.initial_usd - total
        print(f"\nInitial credit:  ${args.initial_usd:.2f}")
        print(f"Spent (est):     ${total:.4f}")
        print(f"Remaining (est): ${remaining:.4f}")
        if remaining < 5:
            print("  ⚠️  Sắp hết credit, kiểm tra dashboard https://api.together.ai/settings/billing")

    # Hint cho user kiểm tra balance thật
    unpriced = [m for m, a in by_model.items() if a["unpriced"]]
    if unpriced:
        print(f"\nModel chưa có trong PROVIDER_PRICING_USD_PER_MTOK (cost=0): {unpriced}")
        print("  → Bổ sung vào scripts/plot_bench.py để tính chính xác.")

    print("\nBalance thật: chỉ xem được trên dashboard https://api.together.ai/settings/billing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
