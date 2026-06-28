"""bench_codex_local.py — chạy gpt-5-mini (hoặc model khác) qua Codex CLI exec mode.

Codex CLI tự là agent (multi-step, tool calls, planning) → script này KHÔNG
gọi engine của repo. Mỗi fixture: copy source ra workdir riêng, prompt Codex
với đề bài + source path, capture stream events qua `codex exec --json`, ghi
jsonl tương thích với plot_bench.py.

Dùng để bench baseline "GPT-5-mini via Codex CLI" (và Claude-Sonnet via Claude
CLI nếu muốn) — 2 reference model thầy chốt cho target ≥80% mà không tốn
API key riêng (dùng quota Plus của CLI).

Threats to validity (ghi rõ trong thesis):
  - Codex CLI tự có planner / anti-loop của OpenAI → bench đo cả "model" +
    "OpenAI agent harness", không phải raw model như API call.
  - Token count đọc từ stream event `token_count`; schema có thể thay đổi
    giữa các bản Codex CLI. Đối chiếu với rollout.jsonl nếu nghi ngờ.
  - Rate limit theo Plus plan (5h window) → batch nhỏ, sleep_between đủ.

Flags theo Codex CLI documented spec (https://github.com/openai/codex):
  -m, --model         <id>
  -C, --cd            <dir>
      --sandbox       read-only | workspace-write | danger-full-access
      --skip-git-repo-check
      --json          stream JSONL events ra stdout
      --output-last-message <file>

Usage::
    python scripts/bench_codex_local.py --model gpt-5-mini
    python scripts/bench_codex_local.py --model gpt-5-mini --fixtures web-001,web-002
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURES = [f"web-{i:03d}" for i in range(1, 21)]
CODEX_BIN = os.environ.get("CODEX_BIN", "codex")

PROMPT_TEMPLATE = """You are a CTF web-challenge solver. Analyze the source code in the current working directory and identify the vulnerability.

Challenge: {title}
Description: {description}

Read files as needed (the source root is the current directory). Then:
1. Identify the vulnerability class (e.g. SQLi, LFI, SSRF, XSS, IDOR, RCE, AuthBypass, XXE, Deserialization, CSRF, Open Redirect).
2. Explain bug location + root cause briefly.
3. Give a concrete exploit payload (URL / request body / parameter).

End your final message with EXACTLY one line in this format (no markdown):
FINAL: {{"vuln": "<class>", "payload": "<exploit>", "file": "<path>"}}
"""

# Keyword sets để chấm detect khi FINAL JSON không match exact.
VULN_KEYWORDS = {
    "LFI":         {"lfi", "local file inclusion", "path traversal", "directory traversal", "file_get_contents"},
    "SQLi":        {"sqli", "sql injection", "sql-injection"},
    "SSRF":        {"ssrf", "server-side request forgery"},
    "XSS":         {"xss", "cross-site scripting"},
    "IDOR":        {"idor", "insecure direct object", "authorization bypass"},
    "RCE":         {"rce", "remote code execution", "command injection", "code injection", "eval("},
    "AuthBypass":  {"auth bypass", "authentication bypass", "authn bypass", "broken authentication"},
    "XXE":         {"xxe", "xml external entity"},
    "Deserialization": {"deserialization", "unserialize", "pickle"},
    "Open Redirect":  {"open redirect"},
    "CSRF":        {"csrf", "cross-site request forgery"},
}


def detect_vuln(stdout: str, last_msg: str, expected: str) -> int:
    text = (stdout + "\n" + last_msg).lower()
    m = re.search(r'FINAL:\s*\{[^}]*"vuln"\s*:\s*"([^"]+)"', stdout + "\n" + last_msg, re.I)
    if m:
        guess = m.group(1).strip().lower()
        exp = expected.lower()
        if exp and (exp in guess or guess in exp):
            return 1
    keys = VULN_KEYWORDS.get(expected, {expected.lower()} if expected else set())
    return int(any(k in text for k in keys))


def parse_stream(stdout: str) -> dict:
    """Đếm steps / tool_calls / tokens từ codex exec --json stream.

    Codex emit JSONL events; shape thường là {"id": "...", "msg": {"type":...}}.
    Một số bản emit flat {"type": ...} → fallback xử lý cả 2."""
    steps = 0
    tool_calls = 0
    tok_in = 0
    tok_out = 0
    last_msg = ""
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = ev.get("msg") if isinstance(ev.get("msg"), dict) else ev
        t = msg.get("type", "")
        if t == "agent_message":
            steps += 1
            last_msg = msg.get("message") or msg.get("text") or last_msg
        elif t == "agent_reasoning":
            steps += 1
        elif t in ("exec_command_begin", "patch_apply_begin", "function_call",
                   "mcp_tool_call_begin", "web_search_begin"):
            tool_calls += 1
        elif t == "token_count":
            info = msg.get("info") or msg
            usage = info.get("total_token_usage") or info.get("last_token_usage") or info
            if isinstance(usage, dict):
                tok_in = max(tok_in, int(usage.get("input_tokens", 0) or 0))
                tok_out = max(tok_out, int(usage.get("output_tokens", 0) or 0))
    return {"steps": steps, "tool_calls": tool_calls,
            "llm_tokens_in": tok_in, "llm_tokens_out": tok_out,
            "last_message": last_msg}


def run_one(model: str, fixture: Path, timeout_s: int, workdir_root: Path) -> dict:
    manifest = json.loads((fixture / "manifest.json").read_text(encoding="utf-8"))
    gt = json.loads((fixture / "ground_truth.json").read_text(encoding="utf-8"))
    expected = gt.get("expected_vulnerability", "")
    src_root = fixture / manifest.get("source_root", "source")

    # Copy source ra workdir tạm — Codex chạy với --cd trỏ vào đây, đảm bảo
    # nó không thấy ground_truth.json hay manifest (hint leakage).
    workdir = workdir_root / f"{fixture.name}-{os.getpid()}-{int(time.monotonic_ns())}"
    shutil.copytree(src_root, workdir)

    prompt = PROMPT_TEMPLATE.format(
        title=manifest.get("title", fixture.name),
        description=manifest.get("description", ""),
    )
    last_msg_file = workdir_root / f"{fixture.name}.last.txt"
    cmd = [
        CODEX_BIN, "exec",
        "--model", model,
        "--cd", str(workdir),
        "--sandbox", "read-only",
        "--skip-git-repo-check",
        "--json",
        "--output-last-message", str(last_msg_file),
        prompt,
    ]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
            encoding="utf-8", errors="replace",
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        rc = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as e:
        stdout = (e.stdout or "") if isinstance(e.stdout, str) else (e.stdout.decode("utf-8", "replace") if e.stdout else "")
        stderr = "timeout"
        rc = -1
        timed_out = True
    wall_s = time.perf_counter() - t0

    parsed = parse_stream(stdout)
    last_msg_disk = ""
    if last_msg_file.exists():
        last_msg_disk = last_msg_file.read_text(encoding="utf-8", errors="replace")
        last_msg_file.unlink(missing_ok=True)
    last_msg = parsed["last_message"] or last_msg_disk
    detected = detect_vuln(stdout, last_msg, expected)

    status = "timeout" if timed_out else ("ok" if rc == 0 else f"error:exit{rc}")
    error = "" if rc == 0 and not timed_out else stderr[:1000]

    shutil.rmtree(workdir, ignore_errors=True)

    return {
        "model": f"{model}@codex-cli",
        "fixture": fixture.name,
        "config": "codex_default",
        "status": status,
        "stop_reason": "?",
        "steps": parsed["steps"],
        "tool_calls": parsed["tool_calls"],
        "validated_findings": 0,
        "llm_findings": int(bool(last_msg)),
        "solved": False,
        "expected_vuln": expected,
        "detected": detected,
        "loop_detected": 0,
        "watchdog_trips": 0,
        "wall_s": round(wall_s, 2),
        "budget_tokens": parsed["llm_tokens_in"] + parsed["llm_tokens_out"],
        "budget_cost": 0,
        "llm_tokens_in": parsed["llm_tokens_in"],
        "llm_tokens_out": parsed["llm_tokens_out"],
        "llm_calls": parsed["steps"],
        "error": error,
    }


def _safe_tag(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)


def _demo() -> None:
    """ponytail self-check: parser + detector phải chạy đúng trên stream giả."""
    sample = "\n".join([
        '{"id":"1","msg":{"type":"agent_reasoning","text":"thinking..."}}',
        '{"id":"2","msg":{"type":"exec_command_begin","command":["ls"]}}',
        '{"id":"3","msg":{"type":"exec_command_end","exit_code":0}}',
        '{"id":"4","msg":{"type":"agent_message","message":"Found LFI in index.php. FINAL: {\\"vuln\\": \\"LFI\\", \\"payload\\": \\"?poem=../flag.txt\\", \\"file\\": \\"index.php\\"}"}}',
        '{"id":"5","msg":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1234,"output_tokens":567}}}}',
    ])
    p = parse_stream(sample)
    assert p["steps"] == 2, p
    assert p["tool_calls"] == 1, p
    assert p["llm_tokens_in"] == 1234 and p["llm_tokens_out"] == 567, p
    assert "FINAL" in p["last_message"], p
    assert detect_vuln(sample, p["last_message"], "LFI") == 1
    assert detect_vuln("nothing here", "", "LFI") == 0
    print("demo OK: parse_stream + detect_vuln pass.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default="gpt-5-mini",
                        help="Codex CLI --model (default: gpt-5-mini).")
    parser.add_argument("--fixtures", nargs="*", default=DEFAULT_FIXTURES,
                        help="Fixture names under data/fixtures/")
    parser.add_argument("--timeout-s", type=int, default=600,
                        help="Per-fixture timeout (default 600s).")
    parser.add_argument("--sleep-between", type=float, default=2.0)
    parser.add_argument("--outputs-dir", default=str(ROOT / "outputs"))
    parser.add_argument("--demo", action="store_true", help="Self-check parser + detector then exit.")
    args = parser.parse_args()
    if args.demo:
        _demo()
        return 0

    args.fixtures = [f for raw in args.fixtures for f in raw.split(",") if f.strip()]

    outputs_dir = Path(args.outputs_dir)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    tag = f"codex_{_safe_tag(args.model)}"
    jsonl_path = outputs_dir / f"bench_local_{tag}.jsonl"
    csv_path = outputs_dir / f"bench_local_{tag}.csv"

    workdir_root = Path(tempfile.mkdtemp(prefix="codex-bench-"))
    print(f"Codex CLI: {CODEX_BIN}  Model: {args.model}")
    print(f"Workdir scratch: {workdir_root}")
    print(f"Output jsonl:    {jsonl_path}\n")

    # Resume: chỉ skip fixture đã có row "ok" (giữ lại để retry timeout/error).
    completed = set()
    if jsonl_path.exists():
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                if row.get("status") == "ok":
                    completed.add(row["fixture"])
        print(f"Resumed: {len(completed)} fixtures already ok.\n")

    # Preflight: codex exec với prompt nhỏ — confirm CLI + model + auth.
    print(f"Preflight: {CODEX_BIN} exec --model {args.model} 'say ok' ...")
    try:
        pf = subprocess.run(
            [CODEX_BIN, "exec", "--model", args.model,
             "--sandbox", "read-only", "--skip-git-repo-check", "say ok"],
            capture_output=True, text=True, timeout=90,
            encoding="utf-8", errors="replace",
        )
        if pf.returncode != 0:
            raise SystemExit(f"Preflight FAILED (exit {pf.returncode}):\n{(pf.stderr or '')[:800]}")
        print("Preflight OK.\n")
    except FileNotFoundError:
        raise SystemExit(f"Không tìm thấy '{CODEX_BIN}'. Cài Codex CLI hoặc set CODEX_BIN env.")

    fixtures = [ROOT / "data" / "fixtures" / n for n in args.fixtures]
    for fd in fixtures:
        if not fd.exists():
            raise SystemExit(f"Fixture not found: {fd}")

    total = len(fixtures)
    bench_t0 = time.perf_counter()
    for idx, fd in enumerate(fixtures, 1):
        print(f"[{idx}/{total}] codex:{args.model}  fixture={fd.name}")
        if fd.name in completed:
            print("  SKIP: already ok in jsonl")
            continue
        row = run_one(args.model, fd, args.timeout_s, workdir_root)
        with open(jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        flag = "D" if row.get("detected") else "-"
        elapsed = time.perf_counter() - bench_t0
        eta = (elapsed / idx) * (total - idx)
        print(f"  [{flag}] {row['status']}  steps={row['steps']}  tools={row['tool_calls']}  "
              f"tok={row['llm_tokens_in']}+{row['llm_tokens_out']}  wall={row['wall_s']:.1f}s")
        print(f"  Elapsed {elapsed/60:.1f}m | ETA {eta/60:.1f}m")
        if row.get("error"):
            print(f"  ERROR: {row['error'][:300]}")
        if args.sleep_between > 0 and idx < total:
            time.sleep(args.sleep_between)

    try:
        import pandas as pd
        rows = []
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        if rows:
            pd.DataFrame(rows).to_csv(csv_path, index=False)
            print(f"\nCSV: {csv_path}")
    except ImportError:
        print("(skip CSV — pandas chưa cài)")

    shutil.rmtree(workdir_root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
