"""Phân tích kết quả bench → bảng + biểu đồ cho report.

Đọc các file outputs/**/bench_local_*.csv (sinh ra bởi bench_api_local.py),
xuất bảng số + nhiều biểu đồ PNG sẵn sàng để chèn vào LaTeX. Các phân tích
được thiết kế để khớp với các metric mà các paper trước (PentestGPT, Red-MIRROR,
MAPTA, VulnBot) báo cáo, để Chương 4 có thể tham chiếu trực tiếp.

Cách dùng (tự pick mọi CSV trong outputs/):
    python scripts/plot_bench.py

Hoặc chỉ định file cụ thể:
    python scripts/plot_bench.py outputs/bench_local_gemini_gemini-2.5-flash.csv

Output:
    outputs/plots/detection_by_model.png         — bar: tỷ lệ phát hiện theo mô hình
    outputs/plots/detection_by_config.png        — bar: tỷ lệ phát hiện theo cấu hình
    outputs/plots/detection_by_vuln_class.png    — bar: tỷ lệ phát hiện theo lớp lỗ hổng (style MAPTA)
    outputs/plots/wall_time_distribution.png     — boxplot wall time theo cấu hình
    outputs/plots/failure_taxonomy.png           — pie phân loại failure (style VulnBot)
    outputs/plots/cost_vs_detection.png          — Pareto frontier cost vs detection
    outputs/plots/correlation_matrix.png         — heatmap correlation (style MAPTA)
    outputs/plots/ablation_table.csv             — bảng ablation gọn cho LaTeX
    outputs/plots/per_class_table.csv            — bảng per-vuln-class cho LaTeX
    outputs/plots/cost_breakdown.csv             — bảng cost solved vs failed
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "outputs" / "plots"
CONFIG_ORDER = ["baseline", "C2_only", "C3_only", "C1_only", "all"]
CONFIG_COLORS = ["#cccccc", "#4daf4a", "#377eb8", "#ff7f00", "#e41a1c"]

# Giá API tham khảo (USD per 1M token, input/output). Dùng cho phép tính cost
# khi `budget_cost` trong row = 0 (provider không tự log). Cập nhật khi giá đổi.
PROVIDER_PRICING_USD_PER_MTOK = {
    # input, output (USD per 1M token). Cập nhật khi giá đổi.
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-pro": (1.25, 10.00),
    "gpt-5-mini": (0.25, 2.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "mistral-medium-latest": (2.70, 8.10),
    "mistral-small-latest": (0.20, 0.60),
    "gemma-4-31b-it": (0.0, 0.0),  # free via Gemini OpenAI-compat
    # OpenRouter slug (giá Anthropic/OpenAI gốc + ~5% markup OR)
    "anthropic/claude-sonnet-4.5": (3.00, 15.00),
    "anthropic/claude-sonnet-4-5": (3.00, 15.00),
    "openai/gpt-5-mini": (0.25, 2.00),
    "openai/gpt-5": (1.25, 10.00),
    # Together.ai (open-source, cho học thuật)
    "deepseek-ai/DeepSeek-V3.1": (0.60, 1.70),
    "deepseek-ai/DeepSeek-R1-0528": (3.00, 7.00),
    "openai/gpt-oss-120b": (0.15, 0.60),
    "openai/gpt-oss-20b": (0.05, 0.20),
    "Qwen/Qwen3-235B-A22B-Instruct-2507-tput": (0.20, 0.60),
    "meta-llama/Llama-3.3-70B-Instruct-Turbo": (1.04, 1.04),
    "moonshotai/Kimi-K2.6": (1.20, 4.50),
}


# ── I/O ───────────────────────────────────────────────────────────────────
def load_results(paths: list[Path]) -> pd.DataFrame:
    frames = []
    for p in paths:
        if not p.exists():
            print(f"  SKIP (missing): {p}")
            continue
        df = pd.read_csv(p)
        df["source_file"] = p.name
        frames.append(df)
        print(f"  loaded {len(df)} rows from {p.name}")
    if not frames:
        sys.exit("Không tìm thấy CSV nào — chạy bench_api_local.py trước.")
    df = pd.concat(frames, ignore_index=True)
    if "detected" not in df.columns:
        df["detected"] = df["status"].isin(["validated", "supported", "solved"]).astype(int)
    df["detected"] = df["detected"].fillna(0).astype(int)
    # Đảm bảo các cột số tồn tại để các phép pivot không crash khi CSV cũ.
    for col in ["budget_tokens", "budget_cost", "tool_calls", "wall_s", "steps",
                "loop_detected", "watchdog_trips", "validated_findings",
                "llm_findings",
                # Cột mới: token thật từ LLM provider (LangChain usage_metadata).
                # CSV bench cũ không có → fillna(0), tính cost sẽ rơi vào nhánh
                # estimate dựa trên budget_tokens (heuristic) làm fallback.
                "llm_tokens_in", "llm_tokens_out", "llm_calls"]:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    if "expected_vuln" not in df.columns:
        df["expected_vuln"] = ""
    return df


def _classify_failure(row: pd.Series) -> str:
    """Phân loại từng run thành một category cho failure-mode taxonomy.

    Khớp tinh thần các phân tích của paper trước (VulnBot Table 1, PentestGPT
    Sec 4.4) — mỗi run rơi vào đúng một nhóm.
    """
    if row["detected"] == 1:
        if row["status"] in ("solved",):
            return "solved (live exploit)"
        if row["status"] in ("validated", "supported"):
            return "detected + oracle-validated"
        return "detected (oracle gap)"
    status = str(row["status"])
    if "RateLimit" in status or "rate_limit" in status.lower():
        return "rate_limit"
    if "Timeout" in status or status == "timeout":
        return "timeout"
    if "error" in status.lower():
        return "api_error"
    if status == "max_steps":
        return "max_steps_no_finding"
    if status == "no_validated_findings":
        # detected=0 here means model produced findings but none matched
        return "finding_wrong_class"
    return "other"


def _enrich_cost(df: pd.DataFrame) -> pd.DataFrame:
    """Tính cost USD ưu tiên dùng `llm_tokens_in/out` (token thật do LLM
    provider báo về qua usage_metadata). Khi cột này = 0 (CSV cũ chưa có),
    fall back sang `budget_tokens` (heuristic) và giả định 70/30 input/output."""
    df = df.copy()
    df["est_cost_usd"] = df["budget_cost"].astype(float)

    has_real_usage = (df["llm_tokens_in"] + df["llm_tokens_out"]) > 0

    # Nhánh 1: có token thật → tính chính xác theo pricing input/output.
    for model, (p_in, p_out) in PROVIDER_PRICING_USD_PER_MTOK.items():
        mask = has_real_usage & (df["model"] == model)
        if mask.any():
            tin = df.loc[mask, "llm_tokens_in"].astype(float)
            tout = df.loc[mask, "llm_tokens_out"].astype(float)
            df.loc[mask, "est_cost_usd"] = (tin * p_in + tout * p_out) / 1_000_000

    # Nhánh 2: không có token thật và est_cost_usd còn 0 → fallback heuristic.
    needs_estimate = (~has_real_usage) & (df["est_cost_usd"] <= 0)
    if needs_estimate.any() and "budget_tokens" in df.columns:
        for model, (p_in, p_out) in PROVIDER_PRICING_USD_PER_MTOK.items():
            mask = needs_estimate & (df["model"] == model)
            if mask.any():
                tok = df.loc[mask, "budget_tokens"].astype(float)
                df.loc[mask, "est_cost_usd"] = (tok * 0.7 * p_in + tok * 0.3 * p_out) / 1_000_000
    return df


# ── Tables ────────────────────────────────────────────────────────────────
def print_tables(df: pd.DataFrame, out_dir: Path) -> pd.DataFrame:
    print("\n" + "=" * 70)
    print("BẢNG 1 — Tỷ lệ phát hiện theo mô hình (có token + cost USD)")
    print("=" * 70)
    df_cost1 = _enrich_cost(df)
    t1 = df_cost1.groupby("model").agg(
        runs=("detected", "count"),
        detected=("detected", "sum"),
        detection_rate=("detected", "mean"),
        avg_steps=("steps", "mean"),
        avg_tool_calls=("tool_calls", "mean"),
        avg_wall_s=("wall_s", "mean"),
        total_tok_in=("llm_tokens_in", "sum"),
        total_tok_out=("llm_tokens_out", "sum"),
        avg_tok_per_run=("llm_tokens_in", lambda s: (s + df_cost1.loc[s.index, "llm_tokens_out"]).mean()),
        total_cost_usd=("est_cost_usd", "sum"),
        avg_cost_usd=("est_cost_usd", "mean"),
    ).round(4)
    print(t1.to_string())
    t1.to_csv(out_dir / "per_model_summary.csv")

    print("\n" + "=" * 70)
    print("BẢNG 2 — Tỷ lệ phát hiện theo Mô hình × Cấu hình (ablation)")
    print("=" * 70)
    t2 = df.pivot_table(
        index="model", columns="config", values="detected",
        aggfunc="mean", margins=True, margins_name="Overall",
    ).round(3)
    col_order = [c for c in CONFIG_ORDER + ["Overall"] if c in t2.columns]
    print(t2[col_order].to_string())

    print("\n" + "=" * 70)
    print("BẢNG 3 — Tỷ lệ phát hiện theo lớp lỗ hổng (style MAPTA)")
    print("=" * 70)
    t3 = df.pivot_table(
        index="expected_vuln", columns="config", values="detected",
        aggfunc="mean", margins=True, margins_name="Overall",
    ).round(3)
    cols = [c for c in CONFIG_ORDER + ["Overall"] if c in t3.columns]
    t3 = t3[cols]
    # Thêm cột đếm số fixture / lớp để biết sample size.
    counts = df.groupby("expected_vuln")["detected"].count().rename("n_runs")
    t3 = t3.join(counts, how="left")
    print(t3.to_string())
    t3.to_csv(out_dir / "per_class_table.csv")

    print("\n" + "=" * 70)
    print("BẢNG 4 — Delta ablation so với baseline (theo mô hình)")
    print("=" * 70)
    baseline = df[df["config"] == "baseline"].groupby("model")["detected"].mean()
    delta_rows = []
    for cfg in [c for c in ["C2_only", "C3_only", "C1_only", "all"] if c in df["config"].unique()]:
        cfg_rate = df[df["config"] == cfg].groupby("model")["detected"].mean()
        delta = (cfg_rate - baseline).round(3)
        print(f"\n  {cfg} − baseline:")
        for model, d in delta.items():
            sign = "+" if d >= 0 else ""
            print(f"    {model}: {sign}{d}")
            delta_rows.append({"model": model, "config": cfg, "delta": d})
    pd.DataFrame(delta_rows).to_csv(out_dir / "ablation_delta.csv", index=False)

    print("\n" + "=" * 70)
    print("BẢNG 5 — Loop / Watchdog events theo cấu hình")
    print("=" * 70)
    t5 = df.groupby("config").agg(
        total_loops=("loop_detected", "sum"),
        total_watchdogs=("watchdog_trips", "sum"),
        avg_steps=("steps", "mean"),
        avg_tools=("tool_calls", "mean"),
    ).round(2)
    rows = [c for c in CONFIG_ORDER if c in t5.index]
    print(t5.loc[rows].to_string())

    print("\n" + "=" * 70)
    print("BẢNG 6 — Cost / Time breakdown (style MAPTA: solved vs failed)")
    print("=" * 70)
    df_cost = _enrich_cost(df)
    grouped = df_cost.groupby(df_cost["detected"].map({1: "detected", 0: "failed"}))
    cost_table = grouped.agg(
        n=("detected", "count"),
        median_tokens=("budget_tokens", "median"),
        median_cost_usd=("est_cost_usd", "median"),
        median_wall_s=("wall_s", "median"),
        median_tool_calls=("tool_calls", "median"),
    ).round(4)
    print(cost_table.to_string())
    cost_table.to_csv(out_dir / "cost_breakdown.csv")

    print("\n" + "=" * 70)
    print("BẢNG 7 — Tương quan giữa nguồn lực và kết quả (style MAPTA)")
    print("=" * 70)
    numeric_cols = ["tool_calls", "wall_s", "steps", "budget_tokens", "detected"]
    corr = df_cost[numeric_cols].corr().round(3)
    print(corr.to_string())
    corr.to_csv(out_dir / "correlation_matrix.csv")

    print("\n" + "=" * 70)
    print("BẢNG 8 — Phân loại lỗi (failure taxonomy, style VulnBot)")
    print("=" * 70)
    df["failure_class"] = df.apply(_classify_failure, axis=1)
    fail_counts = df["failure_class"].value_counts()
    fail_pct = (fail_counts / fail_counts.sum() * 100).round(1)
    fail_df = pd.DataFrame({"count": fail_counts, "pct": fail_pct})
    print(fail_df.to_string())
    fail_df.to_csv(out_dir / "failure_taxonomy.csv")

    return t2  # ablation table for export


# ── Charts ────────────────────────────────────────────────────────────────
def plot_charts(df: pd.DataFrame, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    cfgs = [c for c in CONFIG_ORDER if c in df["config"].unique()]

    # ── Chart 1: detection by model ────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    rates = df.groupby("model")["detected"].mean().sort_values()
    rates.plot(kind="barh", ax=ax, color="steelblue", edgecolor="black")
    ax.set_title("Tỷ lệ phát hiện theo mô hình")
    ax.set_xlabel("Detection rate")
    ax.set_xlim(0, 1.05)
    ax.axvline(x=0.8, color="red", linestyle="--", label="Mục tiêu 80%")
    ax.legend()
    plt.tight_layout()
    p = out_dir / "detection_by_model.png"
    plt.savefig(p, dpi=150, bbox_inches="tight"); plt.close()
    print(f"  saved {p.name}")

    # ── Chart 2: detection by ablation config ──────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    rates = df.groupby("config")["detected"].mean().reindex(cfgs)
    colors = [CONFIG_COLORS[CONFIG_ORDER.index(c)] for c in cfgs]
    rates.plot(kind="bar", ax=ax, color=colors, edgecolor="black")
    ax.set_title("Tỷ lệ phát hiện theo cấu hình (ablation)")
    ax.set_ylabel("Detection rate")
    ax.set_ylim(0, 1.05)
    ax.axhline(y=0.8, color="red", linestyle="--", label="Mục tiêu 80%")
    ax.legend()
    ax.tick_params(axis="x", rotation=30)
    plt.tight_layout()
    p = out_dir / "detection_by_config.png"
    plt.savefig(p, dpi=150, bbox_inches="tight"); plt.close()
    print(f"  saved {p.name}")

    # ── Chart 3: detection by vuln class (style MAPTA Table 1) ─
    fig, ax = plt.subplots(figsize=(10, 5))
    class_rates = (df.groupby("expected_vuln")["detected"].mean()
                   .sort_values(ascending=False))
    n_per_class = df.groupby("expected_vuln")["detected"].count()
    labels = [f"{c} (n={n_per_class[c]})" for c in class_rates.index]
    bars = ax.bar(labels, class_rates.values, color="#4daf4a", edgecolor="black")
    ax.set_title("Tỷ lệ phát hiện theo lớp lỗ hổng (gộp mọi cấu hình)")
    ax.set_ylabel("Detection rate")
    ax.set_ylim(0, 1.05)
    ax.axhline(y=0.8, color="red", linestyle="--", label="Mục tiêu 80%")
    ax.legend()
    ax.tick_params(axis="x", rotation=30)
    for b, v in zip(bars, class_rates.values):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.2f}",
                ha="center", fontsize=9)
    plt.tight_layout()
    p = out_dir / "detection_by_vuln_class.png"
    plt.savefig(p, dpi=150, bbox_inches="tight"); plt.close()
    print(f"  saved {p.name}")

    # ── Chart 4: wall-time distribution (boxplot per config) ───
    fig, ax = plt.subplots(figsize=(8, 5))
    data = [df[df["config"] == c]["wall_s"].dropna().values for c in cfgs]
    bp = ax.boxplot(data, tick_labels=cfgs, patch_artist=True, showfliers=False)
    for patch, color in zip(bp["boxes"], [CONFIG_COLORS[CONFIG_ORDER.index(c)] for c in cfgs]):
        patch.set_facecolor(color)
    ax.set_title("Phân bố thời gian mỗi phiên theo cấu hình")
    ax.set_ylabel("Wall time (giây)")
    ax.tick_params(axis="x", rotation=30)
    plt.tight_layout()
    p = out_dir / "wall_time_distribution.png"
    plt.savefig(p, dpi=150, bbox_inches="tight"); plt.close()
    print(f"  saved {p.name}")

    # ── Chart 5: failure taxonomy (pie, style VulnBot) ─────────
    fig, ax = plt.subplots(figsize=(8, 8))
    fail_counts = df["failure_class"].value_counts()
    palette = plt.cm.tab10.colors[:len(fail_counts)]
    ax.pie(fail_counts.values, labels=fail_counts.index,
           autopct="%1.1f%%", colors=palette, startangle=90,
           wedgeprops={"edgecolor": "white"})
    ax.set_title(f"Phân loại lỗi/thành công ({fail_counts.sum()} runs)")
    plt.tight_layout()
    p = out_dir / "failure_taxonomy.png"
    plt.savefig(p, dpi=150, bbox_inches="tight"); plt.close()
    print(f"  saved {p.name}")

    # ── Chart 6: cost vs detection Pareto ──────────────────────
    df_cost = _enrich_cost(df)
    by_model = df_cost.groupby("model").agg(
        mean_cost=("est_cost_usd", "mean"),
        detection_rate=("detected", "mean"),
    )
    if len(by_model) >= 2 and by_model["mean_cost"].max() > 0:
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.scatter(by_model["mean_cost"], by_model["detection_rate"],
                   s=120, color="#e41a1c", edgecolor="black", zorder=3)
        for model, row in by_model.iterrows():
            ax.annotate(model, (row["mean_cost"], row["detection_rate"]),
                        xytext=(5, 5), textcoords="offset points", fontsize=9)
        ax.set_title("Cost vs Detection rate (Pareto frontier)")
        ax.set_xlabel("Chi phí trung bình mỗi phiên (USD)")
        ax.set_ylabel("Detection rate")
        ax.set_ylim(0, 1.05)
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        p = out_dir / "cost_vs_detection.png"
        plt.savefig(p, dpi=150, bbox_inches="tight"); plt.close()
        print(f"  saved {p.name}")
    else:
        print("  skipped cost_vs_detection.png (chưa đủ dữ liệu cost / chỉ 1 model)")

    # ── Chart 7: correlation heatmap (style MAPTA Sec 3.4) ─────
    numeric_cols = ["tool_calls", "wall_s", "steps", "budget_tokens", "detected"]
    corr = df_cost[numeric_cols].corr()
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(corr.values, cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(numeric_cols)))
    ax.set_yticks(range(len(numeric_cols)))
    ax.set_xticklabels(numeric_cols, rotation=30, ha="right")
    ax.set_yticklabels(numeric_cols)
    for i in range(len(numeric_cols)):
        for j in range(len(numeric_cols)):
            ax.text(j, i, f"{corr.values[i, j]:.2f}",
                    ha="center", va="center",
                    color="white" if abs(corr.values[i, j]) > 0.5 else "black",
                    fontsize=10)
    plt.colorbar(im, ax=ax, shrink=0.7)
    ax.set_title("Ma trận tương quan: nguồn lực vs kết quả")
    plt.tight_layout()
    p = out_dir / "correlation_matrix.png"
    plt.savefig(p, dpi=150, bbox_inches="tight"); plt.close()
    print(f"  saved {p.name}")


# ── Entry point ───────────────────────────────────────────────────────────
def main() -> int:
    if len(sys.argv) > 1:
        paths = [Path(p) for p in sys.argv[1:]]
    else:
        paths = sorted((ROOT / "outputs").rglob("bench_local_*.csv"))
        if not paths:
            sys.exit("Không có outputs/**/bench_local_*.csv — chạy bench_api_local.py trước.")
        print(f"Auto-pick {len(paths)} CSV:")
        for p in paths:
            print(f"  {p.relative_to(ROOT)}")

    print("\nLoading...")
    df = load_results(paths)
    print(f"\nTổng: {len(df)} rows | {df['model'].nunique()} model(s) | "
          f"{df['fixture'].nunique()} fixture(s) | {df['config'].nunique()} config(s)")

    DEFAULT_OUT.mkdir(parents=True, exist_ok=True)
    ablation_table = print_tables(df, DEFAULT_OUT)

    print("\n" + "=" * 70)
    print("Sinh biểu đồ → outputs/plots/")
    print("=" * 70)
    plot_charts(df, DEFAULT_OUT)

    ablation_table.to_csv(DEFAULT_OUT / "ablation_table.csv")
    print(f"  saved ablation_table.csv")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
