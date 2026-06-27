"""Phân tích kết quả bench → bảng + biểu đồ cho report.

Đọc các file outputs/bench_local_*.csv (sinh ra bởi bench_api_local.py),
xuất bảng số + 3 biểu đồ PNG sẵn sàng để chèn vào LaTeX.

Cách dùng (tự pick mọi CSV trong outputs/):
    python scripts/plot_bench.py

Hoặc chỉ định file cụ thể:
    python scripts/plot_bench.py outputs/bench_local_gemini_gemini-2.5-flash.csv

Output:
    outputs/plots/detection_by_model.png       — tỷ lệ phát hiện theo mô hình
    outputs/plots/detection_by_config.png      — tỷ lệ phát hiện theo cấu hình (ablation)
    outputs/plots/wall_time_by_config.png      — thời gian trung bình theo cấu hình
    outputs/plots/ablation_table.csv           — bảng số ablation full
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
    return df


def print_tables(df: pd.DataFrame) -> None:
    print("\n" + "=" * 70)
    print("BẢNG 1 — Tỷ lệ phát hiện theo mô hình (toàn bộ config)")
    print("=" * 70)
    t1 = df.groupby("model").agg(
        runs=("detected", "count"),
        detected=("detected", "sum"),
        detection_rate=("detected", "mean"),
        avg_steps=("steps", "mean"),
        avg_wall_s=("wall_s", "mean"),
    ).round(3)
    print(t1.to_string())

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
    print("BẢNG 3 — Tỷ lệ phát hiện theo Mô hình × Fixture")
    print("=" * 70)
    t3 = df.pivot_table(
        index="model", columns="fixture", values="detected",
        aggfunc="mean", margins=True, margins_name="Overall",
    ).round(3)
    print(t3.to_string())

    print("\n" + "=" * 70)
    print("BẢNG 4 — Delta ablation so với baseline (theo mô hình)")
    print("=" * 70)
    baseline = df[df["config"] == "baseline"].groupby("model")["detected"].mean()
    for cfg in [c for c in ["C2_only", "C3_only", "C1_only", "all"] if c in df["config"].unique()]:
        cfg_rate = df[df["config"] == cfg].groupby("model")["detected"].mean()
        delta = (cfg_rate - baseline).round(3)
        print(f"\n  {cfg} − baseline:")
        for model, d in delta.items():
            sign = "+" if d >= 0 else ""
            print(f"    {model}: {sign}{d}")

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

    return t2  # cho caller export


def plot_charts(df: pd.DataFrame, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Chart 1: Detection rate by model
    fig, ax = plt.subplots(figsize=(8, 5))
    rates = df.groupby("model")["detected"].mean().sort_values()
    rates.plot(kind="barh", ax=ax, color="steelblue", edgecolor="black")
    ax.set_title("Tỷ lệ phát hiện theo mô hình")
    ax.set_xlabel("Detection rate")
    ax.set_xlim(0, 1.05)
    ax.axvline(x=0.8, color="red", linestyle="--", label="Mục tiêu 80%")
    ax.legend()
    plt.tight_layout()
    p1 = out_dir / "detection_by_model.png"
    plt.savefig(p1, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  saved {p1}")

    # Chart 2: Detection rate by ablation config
    fig, ax = plt.subplots(figsize=(8, 5))
    cfgs = [c for c in CONFIG_ORDER if c in df["config"].unique()]
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
    p2 = out_dir / "detection_by_config.png"
    plt.savefig(p2, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  saved {p2}")

    # Chart 3: Wall time by config
    fig, ax = plt.subplots(figsize=(8, 5))
    wall = df.groupby("config")["wall_s"].mean().reindex(cfgs)
    wall.plot(kind="bar", ax=ax, color="#984ea3", edgecolor="black")
    ax.set_title("Thời gian trung bình mỗi phiên theo cấu hình")
    ax.set_ylabel("Wall time (giây)")
    ax.tick_params(axis="x", rotation=30)
    plt.tight_layout()
    p3 = out_dir / "wall_time_by_config.png"
    plt.savefig(p3, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  saved {p3}")


def main() -> int:
    if len(sys.argv) > 1:
        paths = [Path(p) for p in sys.argv[1:]]
    else:
        paths = sorted((ROOT / "outputs").glob("bench_local_*.csv"))
        if not paths:
            sys.exit("Không có outputs/bench_local_*.csv — chạy bench_api_local.py trước.")
        print(f"Auto-pick {len(paths)} CSV:")
        for p in paths:
            print(f"  {p.name}")

    print("\nLoading...")
    df = load_results(paths)
    print(f"\nTổng: {len(df)} rows | {df['model'].nunique()} model(s) | "
          f"{df['fixture'].nunique()} fixture(s) | {df['config'].nunique()} config(s)")

    ablation_table = print_tables(df)

    print("\n" + "=" * 70)
    print("Sinh biểu đồ → outputs/plots/")
    print("=" * 70)
    plot_charts(df, DEFAULT_OUT)

    # Export bảng ablation gọn (model × config) ra CSV cho LaTeX
    csv_path = DEFAULT_OUT / "ablation_table.csv"
    ablation_table.to_csv(csv_path)
    print(f"  saved {csv_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
