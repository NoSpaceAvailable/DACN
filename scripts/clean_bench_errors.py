"""Xóa các row transient-error (401, 429, timeout) khỏi bench_local_*.jsonl
để lần bench tiếp theo có thể retry các fixture đó.

Dùng:
    python scripts/clean_bench_errors.py                     # dry-run, in stats
    python scripts/clean_bench_errors.py --apply             # ghi đè jsonl
    python scripts/clean_bench_errors.py outputs/foo.jsonl --apply
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TRANSIENT_STATUSES = {
    "error:AuthenticationError",
    "error:RateLimitError",
    "error:APITimeoutError",
    "error:APIConnectionError",
    "error:PermissionDeniedError",
    "error:InternalServerError",
    "error:ServiceUnavailableError",
}


def is_transient(row: dict) -> bool:
    status = row.get("status", "")
    if status in TRANSIENT_STATUSES:
        return True
    err = (row.get("error") or "")
    return "401" in err or "429" in err or "rate" in err.lower() or "unauthor" in err.lower()


def clean_file(path: Path, apply: bool) -> tuple[int, int]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    kept = [r for r in rows if not is_transient(r)]
    removed = len(rows) - len(kept)
    if removed == 0:
        return len(rows), 0
    if apply:
        # Ghi lại jsonl
        path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in kept) + "\n",
                        encoding="utf-8")
        # Regen CSV bên cạnh nếu có
        csv_path = path.with_suffix(".csv")
        if kept:
            fieldnames = list(kept[0].keys())
            for r in kept:
                for k in r.keys():
                    if k not in fieldnames:
                        fieldnames.append(k)
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                w.writeheader()
                w.writerows(kept)
    return len(rows), removed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", help="jsonl files (default: outputs/**/bench_local_*.jsonl)")
    parser.add_argument("--apply", action="store_true", help="thật sự ghi (mặc định dry-run)")
    args = parser.parse_args()

    paths = [Path(p) for p in args.paths] if args.paths else sorted(
        (ROOT / "outputs").rglob("bench_local_*.jsonl")
    )
    if not paths:
        sys.exit("Không tìm thấy jsonl nào.")

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"\n[{mode}]\n{'File':<60s}  {'Total':>6s}  {'Bad':>5s}  {'Kept':>5s}")
    print("-" * 85)
    total_bad = 0
    for p in paths:
        total, removed = clean_file(p, args.apply)
        total_bad += removed
        print(f"{p.name:<60s}  {total:>6d}  {removed:>5d}  {total-removed:>5d}")
    print("-" * 85)
    if total_bad == 0:
        print("Không có row nào cần xóa.")
    elif not args.apply:
        print(f"\n→ {total_bad} row sẽ bị xóa. Chạy lại với --apply để ghi.")
    else:
        print(f"\n→ Đã xóa {total_bad} row + regen CSV. Bench lần sau sẽ retry các fixture đó.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
