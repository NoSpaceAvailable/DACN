"""Detection-rate statistics with Wilson 95% confidence intervals.

Reads every outputs/bench_local_*.{json,csv}, computes per-model detection rate
and a Wilson score 95% CI (no scipy needed), and — because the benchmark is
small (n<=100) — prints the CIs so the report avoids over-reading small gaps
(e.g. 78% vs 75%). Also does a two-proportion z-test between any two models
passed with --compare A B.

Usage:
    python scripts/bench_stats.py
    python scripts/bench_stats.py --compare mistral-medium-3.5-128b gpt-5.4-mini
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import os
from typing import Dict, List, Tuple

Z = 1.96  # 95%


def wilson_ci(k: int, n: int) -> Tuple[float, float, float]:
    """Return (rate, lo, hi) as fractions using the Wilson score interval."""
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    denom = 1 + Z * Z / n
    centre = (p + Z * Z / (2 * n)) / denom
    half = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


def two_prop_z(k1: int, n1: int, k2: int, n2: int) -> Tuple[float, float]:
    """Two-proportion z-test. Returns (z, two-sided p-value)."""
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0
    p1, p2 = k1 / n1, k2 / n2
    p = (k1 + k2) / (n1 + n2)
    se = math.sqrt(p * (1 - p) * (1 / n1 + 1 / n2))
    if se == 0:
        return 0.0, 1.0
    z = (p1 - p2) / se
    # two-sided p from the normal CDF via erf
    pval = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))
    return z, pval


def _detected(r: dict) -> bool:
    v = r.get("detected", "")
    return str(v).strip() in ("1", "True", "true") or v is True


def load_model_counts() -> Dict[str, Tuple[int, int]]:
    """model -> (detected, n), reading .json (has 'runs') then .csv."""
    out: Dict[str, Tuple[int, int]] = {}
    for f in sorted(glob.glob("outputs/bench_local_*.json")):
        try:
            j = json.load(open(f))
        except Exception:
            continue
        runs = j.get("runs") or j.get("results") or []
        if not runs:
            continue
        model = j.get("model") or os.path.basename(f)
        out[model] = (sum(1 for r in runs if _detected(r)), len(runs))
    for f in sorted(glob.glob("outputs/bench_local_*.csv")):
        model = os.path.basename(f)[len("bench_local_"):-len(".csv")]
        model = model.split("_", 1)[-1] if "_" in model else model
        try:
            rows = list(csv.DictReader(open(f)))
        except Exception:
            continue
        if not rows:
            continue
        key = rows[0].get("model", model)
        if key not in out:  # don't overwrite a richer json entry
            out[key] = (sum(1 for r in rows if _detected(r)), len(rows))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--compare", nargs=2, metavar=("A", "B"),
                    help="Two-proportion z-test between two model substrings.")
    args = ap.parse_args()

    counts = load_model_counts()
    print(f"{'model':42} {'n':>4} {'det':>4} {'rate':>6}  95% CI (Wilson)")
    print("-" * 78)
    for model in sorted(counts, key=lambda m: -(counts[m][0] / counts[m][1] if counts[m][1] else 0)):
        k, n = counts[model]
        p, lo, hi = wilson_ci(k, n)
        print(f"{model[:42]:42} {n:>4} {k:>4} {p*100:5.0f}%  [{lo*100:4.0f}%, {hi*100:4.0f}%]")

    if args.compare:
        def find(sub):
            for m in counts:
                if sub.lower() in m.lower():
                    return m
            return None
        a, b = find(args.compare[0]), find(args.compare[1])
        if a and b:
            ka, na = counts[a]; kb, nb = counts[b]
            z, pv = two_prop_z(ka, na, kb, nb)
            print(f"\nCompare {a} ({ka}/{na}) vs {b} ({kb}/{nb}): z={z:.2f}, p={pv:.3f}"
                  f"  -> {'significant' if pv < 0.05 else 'NOT significant'} at alpha=0.05")
        else:
            print(f"\nCould not match both models: {args.compare}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
