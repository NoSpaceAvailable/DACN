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
CODEX_BIN = os.environ.get("CODEX_BIN", "C:/nvm4w/nodejs/codex.cmd")

PROMPT_TEMPLATE = """You are a CTF web-challenge solver. Analyze the source code in the current working directory and identify the vulnerability.

Challenge: {title}
Description: {description}

Hard constraints:
- Use AT MOST {max_steps} tool calls total. Plan accordingly — read source first, reason, then commit.
- ONLY read files inside the current working directory. Do NOT read any path containing 'data/fixtures', 'ground_truth', 'manifest.json', or 'transcripts'. Do NOT explore parent directories.
- No network access.

Task:
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


_AGENT_TYPES = {"agent_message"}
_REASONING_TYPES = {"agent_reasoning", "reasoning"}
_TOOL_TYPES = {
    # Schema cũ (begin/end pairs)
    "exec_command_begin", "patch_apply_begin", "function_call",
    "mcp_tool_call_begin", "web_search_begin",
    # Schema mới (item.completed wrapper)
    "command_execution", "file_change", "patch_apply",
    "tool_call", "mcp_tool_call", "web_search",
}


def _consume(ev: dict, state: dict) -> None:
    """Update steps/tool_calls/tokens/last_msg theo 1 event JSON.

    Xử lý cả 2 schema:
      - Cũ: {"id": ..., "msg": {"type": ..., ...}}
      - Mới: {"type": "item.completed", "item": {"type": ..., ...}}
             {"type": "turn.completed", "usage": {...}}
    """
    top_t = ev.get("type", "")

    # Schema mới: turn.completed → cộng dồn usage qua từng turn.
    # Tách cached riêng để tính cost chính xác (cached ≈ 1/10 giá full).
    if top_t == "turn.completed":
        usage = ev.get("usage") or {}
        if isinstance(usage, dict):
            state["tok_in"] += int(usage.get("input_tokens", 0) or 0)
            state["tok_cached"] += int(usage.get("cached_input_tokens", 0) or 0)
            state["tok_out"] += int(usage.get("output_tokens", 0) or 0)
            state["tok_reasoning"] += int(usage.get("reasoning_output_tokens", 0) or 0)
        return

    # Schema mới: item.completed wraps actual event in `item`
    inner = ev.get("item") if top_t in ("item.completed", "item.started") and isinstance(ev.get("item"), dict) else None
    # Schema cũ: msg wraps actual event
    if inner is None:
        inner = ev.get("msg") if isinstance(ev.get("msg"), dict) else ev
    t = inner.get("type", "")

    if t in _AGENT_TYPES:
        # Chỉ count step khi item.completed (tránh đếm cả started + completed)
        if top_t != "item.started":
            state["steps"] += 1
            state["last_msg"] = inner.get("text") or inner.get("message") or state["last_msg"]
    elif t in _REASONING_TYPES:
        if top_t != "item.started":
            state["steps"] += 1
    elif t in _TOOL_TYPES:
        # Begin (cũ) hoặc completed (mới) đều count 1 lần — KHÔNG đếm 'started'.
        if top_t != "item.started" and not t.endswith("_end"):
            state["tool_calls"] += 1
    elif t == "token_count":  # schema cũ
        info = inner.get("info") or inner
        usage = info.get("total_token_usage") or info.get("last_token_usage") or info
        if isinstance(usage, dict):
            state["tok_in"] = max(state["tok_in"], int(usage.get("input_tokens", 0) or 0))
            state["tok_out"] = max(state["tok_out"], int(usage.get("output_tokens", 0) or 0))


def parse_stream(stdout: str) -> dict:
    state = {"steps": 0, "tool_calls": 0, "tok_in": 0, "tok_out": 0,
             "tok_cached": 0, "tok_reasoning": 0, "last_msg": ""}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        _consume(ev, state)
    return {"steps": state["steps"], "tool_calls": state["tool_calls"],
            "llm_tokens_in": state["tok_in"], "llm_tokens_out": state["tok_out"],
            "last_message": state["last_msg"]}


# Pattern để phát hiện Codex (hoặc model) lén đọc path ngoài workdir tạm.
# Nếu hit → log warning, đánh dấu row leak=1 để sau loại bỏ khỏi bench.
LEAK_PATTERNS = (
    re.compile(r"data[\\/]fixtures[\\/]", re.I),
    re.compile(r"ground_truth", re.I),
    re.compile(r"expected_vulnerability", re.I),
    re.compile(r"expected_payload_pattern", re.I),
    re.compile(r"\bmanifest\.json\b", re.I),
    re.compile(r"transcripts[\\/]", re.I),
)


def scan_leak(text: str) -> str:
    for pat in LEAK_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0)
    return ""


def run_one(model: str, fixture: Path, timeout_s: int, max_steps: int,
            workdir_root: Path) -> dict:
    manifest = json.loads((fixture / "manifest.json").read_text(encoding="utf-8"))
    gt = json.loads((fixture / "ground_truth.json").read_text(encoding="utf-8"))
    expected = gt.get("expected_vulnerability", "")
    src_root = fixture / manifest.get("source_root", "source")

    # Workdir tạm — KHÔNG copy ground_truth/manifest/transcripts, chỉ source.
    workdir = workdir_root / f"{fixture.name}-{os.getpid()}-{int(time.monotonic_ns())}"
    shutil.copytree(src_root, workdir)

    prompt = PROMPT_TEMPLATE.format(
        title=manifest.get("title", fixture.name),
        description=manifest.get("description", ""),
        max_steps=max_steps,
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

    # Popen + streaming: count tool_calls + agent_messages incrementally, kill
    # khi vượt max_steps. Đây là cách duy nhất ép cap step vì Codex CLI không
    # có flag --max-steps.
    t0 = time.perf_counter()
    stdout_chunks: list[str] = []
    state = {"steps": 0, "tool_calls": 0, "tok_in": 0, "tok_out": 0,
             "tok_cached": 0, "tok_reasoning": 0, "last_msg": ""}
    killed_reason = ""
    timed_out = False
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            stdout_chunks.append(line)
            line_strip = line.strip()
            if line_strip.startswith("{"):
                try:
                    _consume(json.loads(line_strip), state)
                except json.JSONDecodeError:
                    pass
            # Hard cap: kill khi tool_calls vượt max_steps.
            if state["tool_calls"] >= max_steps or state["steps"] >= max_steps * 2:
                killed_reason = f"step_cap({state['tool_calls']}tc/{state['steps']}st)"
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            # Wall timeout check (per-fixture).
            if time.perf_counter() - t0 > timeout_s:
                killed_reason = "timeout"
                timed_out = True
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
        try:
            rc = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = -1
        stderr = (proc.stderr.read() if proc.stderr else "") or ""
    finally:
        if proc.poll() is None:
            proc.kill()

    stdout = "".join(stdout_chunks)
    wall_s = time.perf_counter() - t0

    last_msg_disk = ""
    if last_msg_file.exists():
        last_msg_disk = last_msg_file.read_text(encoding="utf-8", errors="replace")
        last_msg_file.unlink(missing_ok=True)
    last_msg = state["last_msg"] or last_msg_disk
    detected = detect_vuln(stdout, last_msg, expected)
    leak_hit = scan_leak(stdout + "\n" + last_msg)
    steps = state["steps"]
    tool_calls = state["tool_calls"]
    tok_in = state["tok_in"]
    tok_out = state["tok_out"]
    tok_cached = state["tok_cached"]
    tok_reasoning = state["tok_reasoning"]

    if killed_reason:
        status = killed_reason if killed_reason.startswith("step_cap") else "timeout"
    elif rc == 0:
        status = "ok"
    else:
        status = f"error:exit{rc}"
    error = ""
    if status != "ok" and not killed_reason.startswith("step_cap"):
        error = stderr[:1000]

    shutil.rmtree(workdir, ignore_errors=True)

    return {
        "model": f"{model}@codex-cli",
        "fixture": fixture.name,
        "config": "codex_default",
        "status": status,
        "stop_reason": killed_reason or ("ok" if rc == 0 else "?"),
        "steps": steps,
        "tool_calls": tool_calls,
        "validated_findings": 0,
        "llm_findings": int(bool(last_msg)),
        "solved": False,
        "expected_vuln": expected,
        "detected": detected,
        "loop_detected": 0,
        "watchdog_trips": 1 if killed_reason.startswith("step_cap") else 0,
        "wall_s": round(wall_s, 2),
        "budget_tokens": tok_in + tok_out,
        "budget_cost": 0,
        "llm_tokens_in": tok_in,
        "llm_tokens_out": tok_out,
        "llm_tokens_cached": tok_cached,
        "llm_tokens_reasoning": tok_reasoning,
        "llm_calls": steps,
        "leak_hit": leak_hit,
        "error": error,
    }


def _safe_tag(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)


def _demo() -> None:
    """ponytail self-check: parser + detector + leak-scanner + prompt-format."""
    # Schema mới (Codex CLI 2025): flat type + item.completed wrapper + turn.completed.usage
    sample_new = "\n".join([
        '{"type":"thread.started","thread_id":"abc"}',
        '{"type":"turn.started"}',
        '{"type":"item.completed","item":{"type":"reasoning","text":"hmm"}}',
        '{"type":"item.completed","item":{"type":"command_execution","command":["ls"]}}',
        '{"type":"item.completed","item":{"type":"agent_message","text":"Found LFI. FINAL: {\\"vuln\\": \\"LFI\\", \\"payload\\": \\"?p=../flag\\", \\"file\\": \\"i.php\\"}"}}',
        '{"type":"turn.completed","usage":{"input_tokens":1000,"output_tokens":50,"reasoning_output_tokens":17}}',
    ])
    p = parse_stream(sample_new)
    assert p["steps"] == 2, p
    assert p["tool_calls"] == 1, p
    assert p["llm_tokens_in"] == 1000 and p["llm_tokens_out"] == 50, p
    assert "FINAL" in p["last_message"], p
    assert detect_vuln(sample_new, p["last_message"], "LFI") == 1

    # Schema cũ (msg-wrapper) phải vẫn parse được — fallback
    sample_old = "\n".join([
        '{"id":"1","msg":{"type":"agent_reasoning","text":"x"}}',
        '{"id":"2","msg":{"type":"exec_command_begin","command":["ls"]}}',
        '{"id":"3","msg":{"type":"agent_message","message":"FINAL: {\\"vuln\\":\\"SQLi\\",\\"payload\\":\\"q\'--\\",\\"file\\":\\"a\\"}"}}',
        '{"id":"4","msg":{"type":"token_count","info":{"total_token_usage":{"input_tokens":99,"output_tokens":11}}}}',
    ])
    p2 = parse_stream(sample_old)
    assert p2["steps"] == 2 and p2["tool_calls"] == 1, p2
    assert p2["llm_tokens_in"] == 99 and p2["llm_tokens_out"] == 11, p2

    assert detect_vuln("nothing here", "", "LFI") == 0
    assert scan_leak("normal log") == ""
    assert scan_leak("cat data/fixtures/web-001/ground_truth.json")
    rendered = PROMPT_TEMPLATE.format(title="x", description="y", max_steps=40)
    assert "AT MOST 40" in rendered
    print("demo OK: parse_stream(new+old) + detect_vuln + scan_leak + prompt pass.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default="gpt-5-mini",
                        help="Codex CLI --model (default: gpt-5-mini).")
    parser.add_argument("--fixtures", nargs="*", default=DEFAULT_FIXTURES,
                        help="Fixture names under data/fixtures/")
    parser.add_argument("--timeout-s", type=int, default=600,
                        help="Per-fixture wall timeout (default 600s).")
    parser.add_argument("--max-steps", type=int, default=40,
                        help="Hard cap on tool_calls per fixture (default 40, "
                             "matching bench_api_local.py).")
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
        row = run_one(args.model, fd, args.timeout_s, args.max_steps, workdir_root)
        with open(jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        flag = "D" if row.get("detected") else "-"
        elapsed = time.perf_counter() - bench_t0
        eta = (elapsed / idx) * (total - idx)
        print(f"  [{flag}] {row['status']}  steps={row['steps']}  tools={row['tool_calls']}  "
              f"tok={row['llm_tokens_in']}+{row['llm_tokens_out']}  wall={row['wall_s']:.1f}s")
        print(f"  Elapsed {elapsed/60:.1f}m | ETA {eta/60:.1f}m")
        if row.get("leak_hit"):
            print(f"  ⚠️  LEAK pattern hit: {row['leak_hit']!r} — Codex có thể đã đọc path ngoài workdir.")
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
