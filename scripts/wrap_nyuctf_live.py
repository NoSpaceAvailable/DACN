"""Wrap NYU CTF Bench web challenges into our live-exploit fixture format.

For each challenge directory (with challenge.json + docker-compose.yml referencing
a prebuilt llmctf/* image), this generates a fixture under data/fixtures/<id>/:

  - docker-compose.yml : same image, but publishes 127.0.0.1:<hostport>:<internal_port>
                         (our HTTP tools reach the target on a host port; the
                         original compose used an external ctfnet network instead).
  - manifest.json      : "live" block (compose_file, target_url, ready_path) + scope.
  - ground_truth.json  : the real flag (oracle for solve-rate) + expected_vulnerability.
  - source/            : challenge source for read_source (EXCLUDES test_solver/ — that
                         is the reference solution and would leak the answer).
  - transcripts/http.json : minimal neutral routes.

Usage:
    python scripts/wrap_nyuctf_live.py --root NYU_CTF_Bench-main/test --limit 10
    python scripts/wrap_nyuctf_live.py --challenges <dir1> <dir2> ...
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "data" / "fixtures"

# Files/dirs never copied into the fixture source (leakage / bloat).
_EXCLUDE = {"test_solver", "node_modules", ".git", "public", "__pycache__",
            "package-lock.json", ".dockerignore", ".gitignore",
            "target", "build", "dist", ".idea", "vendor"}
# Skip files by extension (build artifacts / media / archives) or by name
# (walkthroughs/solutions = leakage), and anything over the size cap.
_SKIP_EXT = {".war", ".jar", ".class", ".zip", ".tar", ".gz", ".pdf", ".jpg",
             ".jpeg", ".png", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".mp4",
             ".so", ".bin", ".pyc"}
_SKIP_NAME_SUBSTR = ("walkthrough", "solution", "writeup", "solver", "exploit_solution")
_MAX_FILE_BYTES = 200_000

_HOST_PORT_BASE = 9001


def _keep_file(p: Path) -> bool:
    name = p.name.lower()
    if any(s in name for s in _SKIP_NAME_SUBSTR):
        return False
    if p.suffix.lower() in _SKIP_EXT:
        return False
    try:
        if p.stat().st_size > _MAX_FILE_BYTES:
            return False
    except OSError:
        return False
    return True


def _image_from_compose(compose_path: Path) -> str | None:
    txt = compose_path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"^\s*image:\s*['\"]?([^'\"\n]+)['\"]?\s*$", txt, re.MULTILINE)
    return m.group(1).strip() if m else None


def _copy_source(chal_dir: Path, dest: Path) -> int:
    """Recursively copy source, skipping excluded dirs and unwanted/large files."""
    n = 0
    for item in sorted(chal_dir.rglob("*")):
        rel = item.relative_to(chal_dir)
        if any(part in _EXCLUDE for part in rel.parts):
            continue
        if item.is_dir():
            continue
        if not _keep_file(item):
            continue
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, out)
        n += 1
    return n


def wrap(chal_dir: Path, host_port: int) -> dict:
    cj_path = chal_dir / "challenge.json"
    compose_path = chal_dir / "docker-compose.yml"
    if not cj_path.exists() or not compose_path.exists():
        return {"skipped": chal_dir.name, "reason": "missing challenge.json or docker-compose.yml"}

    cj = json.loads(cj_path.read_text(encoding="utf-8"))
    flag = cj.get("flag", "")
    internal_port = int(cj.get("internal_port", 80))
    image = _image_from_compose(compose_path)
    if not image:
        return {"skipped": chal_dir.name, "reason": "no prebuilt image in compose (build-only)"}

    fid = f"live_{re.sub(r'[^a-zA-Z0-9]+', '_', chal_dir.name.lower()).strip('_')}"
    fdir = FIXTURES / fid
    if fdir.exists():
        shutil.rmtree(fdir)
    (fdir / "transcripts").mkdir(parents=True)
    src = fdir / "source"; src.mkdir()
    _copy_source(chal_dir, src)

    # Host-port compose (no external network; just publish the port on loopback).
    (fdir / "docker-compose.yml").write_text(
        "services:\n"
        "  target:\n"
        f"    image: {image}\n"
        "    ports:\n"
        f"      - \"127.0.0.1:{host_port}:{internal_port}\"\n",
        encoding="utf-8",
    )
    (fdir / "manifest.json").write_text(json.dumps({
        "id": fid,
        "title": f"NYU CTF Bench / {chal_dir.name}",
        "mode": "dynamic",
        "difficulty": 0.6,
        "skills": ["analysis", "exploit", "validation"],
        "entrypoint": "transcripts/http.json",
        "source_root": "source",
        "live": {
            "compose_file": "docker-compose.yml",
            "target_url": f"http://127.0.0.1:{host_port}",
            "ready_path": "/",
            "ready_timeout_s": 90,
        },
        "scope": {"allow_hosts": ["127.0.0.1", "localhost"], "allow_ports": [host_port]},
        "budget": {"tool_calls": 60, "time_seconds": 420, "simulated_usd": 0.50},
        "notes": f"NYU CTF Bench {chal_dir.name}. Live target via Docker; flag in ground_truth.",
    }, indent=2), encoding="utf-8")
    (fdir / "ground_truth.json").write_text(json.dumps({
        "expected_vulnerability": "",
        "severity": "High",
        "oracle": "flag_captured",
        "flag": flag,
        "source": f"NYU CTF Bench / {chal_dir.relative_to(ROOT / 'NYU_CTF_Bench-main') if (ROOT/'NYU_CTF_Bench-main') in chal_dir.parents else chal_dir.name}",
    }, indent=2), encoding="utf-8")
    (fdir / "transcripts" / "http.json").write_text(json.dumps({
        "routes": [{"method": "GET", "path": "/", "notes": "web challenge entrypoint"}],
        "observations": [],
    }, indent=2), encoding="utf-8")

    return {"id": fid, "image": image, "host_port": host_port, "internal_port": internal_port,
            "flag_len": len(flag)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=None, help="Scan this dir for */web/<challenge> dirs.")
    ap.add_argument("--challenges", nargs="*", default=None, help="Explicit challenge dirs.")
    ap.add_argument("--limit", type=int, default=10)
    args = ap.parse_args()

    if args.challenges:
        chals = [Path(c) for c in args.challenges]
    else:
        root = Path(args.root or (ROOT / "NYU_CTF_Bench-main" / "test"))
        chals = sorted(p.parent for p in root.glob("**/web/*/challenge.json"))

    done = 0
    for c in chals:
        if done >= args.limit:
            break
        res = wrap(c, _HOST_PORT_BASE + done)
        if "skipped" in res:
            print(f"  SKIP {res['skipped']}: {res['reason']}")
            continue
        print(f"  OK   {res['id']}  image={res['image']}  port={res['host_port']}->{res['internal_port']}  flag_len={res['flag_len']}")
        done += 1
    print(f"\nWrapped {done} live fixtures into {FIXTURES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
