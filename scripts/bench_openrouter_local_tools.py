"""Benchmark an OpenRouter chat model using the SAME local tool wiring as the
Mistral bench.

Provider differences vs ``bench_mistral_agent_local_tools.py``:

  * Endpoint: ``https://openrouter.ai/api/v1/chat/completions`` (OpenAI Chat
    Completions shape).
  * Stateless: caller resends the full ``messages[]`` array each turn.
  * Tool calls live on the assistant message as ``tool_calls[]``; tool
    results come back as ``{"role":"tool","tool_call_id":...,"content":...}``.
  * ``reasoning_effort`` is the OpenAI-compatible knob (gpt-oss-* honors it).

Everything else — KG/RAG/Blackboard/tools/prompt/scoring — is reused as-is
from the Mistral bench module via direct import. The Mistral script stays
untouched.

Usage (PowerShell)::

    python scripts/bench_openrouter_local_tools.py `
        --model "openai/gpt-oss-120b:free" `
        --api-key $env:OPENROUTER_API_KEY

Defaults pick up ``OPENROUTER_API_KEY`` and ``OPENROUTER_MODEL`` from .env.

Free-tier rate limits on OpenRouter are tight (~20 RPM, daily cap shared
across all ``:free`` models). The ``--sleep-between`` default is bumped to
4s and the script will surface ``429`` quickly so you can pace yourself.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.exists() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import requests

# Reuse everything that isn't provider-specific.
import bench_mistral_agent_local_tools as bm
from vapt_orchestrator_safe.config import DEFAULT_KB, _load_dotenv_if_present
from vapt_orchestrator_safe.memory.rag import CompressedRAG
from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.sandbox.local_lab import LocalLabAdapter

_load_dotenv_if_present()


API_BASE = "https://openrouter.ai/api/v1"
CHAT_PATH = "/chat/completions"

_DEFAULT_FIXTURES = bm._DEFAULT_FIXTURES
_MAX_TOOL_TURNS = bm._MAX_TOOL_TURNS


def _post(url: str, api_key: str, payload: Dict[str, Any], timeout_s: int,
          referer: str = "", title: str = "") -> Dict[str, Any]:
    """Same retry policy as the Mistral bench — 2 retries on 429/5xx/network."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-Title"] = title
    last_err: Optional[str] = None
    for attempt in range(bm._POST_MAX_RETRIES + 1):
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
        except (requests.ReadTimeout, requests.ConnectTimeout, requests.ConnectionError) as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            if attempt < bm._POST_MAX_RETRIES:
                time.sleep(bm._POST_BACKOFFS_S[attempt]); continue
            raise RuntimeError(f"network failure after {bm._POST_MAX_RETRIES+1} attempts: {last_err}")
        if r.status_code == 200:
            return r.json()
        if (r.status_code == 429 or 500 <= r.status_code < 600) and attempt < bm._POST_MAX_RETRIES:
            last_err = f"HTTP {r.status_code}: {r.text[:200]}"
            time.sleep(bm._POST_BACKOFFS_S[attempt]); continue
        raise RuntimeError(f"HTTP {r.status_code} on {url}: {r.text[:600]}")
    raise RuntimeError(f"post exhausted retries: {last_err}")


def _outputs_from_choice(msg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Translate an OpenAI assistant message into the Mistral-style ``outputs``
    entries that ``_extract_text`` / ``_collect_function_calls`` already speak.

    This keeps the downstream parsers (text extraction, JSON scanner,
    thinking-block fallback) reusable without forking them.
    """
    outs: List[Dict[str, Any]] = []
    # Reasoning content (some providers return it; gpt-oss does when
    # reasoning_effort is set).
    rc = msg.get("reasoning") or msg.get("reasoning_content")
    if isinstance(rc, str) and rc:
        outs.append({"type": "thinking", "content": rc})
    content = msg.get("content")
    if isinstance(content, str) and content:
        outs.append({"type": "message.output", "content": content})
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, dict):
                t = part.get("type")
                if t in ("text", "output_text"):
                    outs.append({"type": "message.output", "content": part.get("text", "")})
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        outs.append({
            "type": "function.call",
            "name": fn.get("name", ""),
            "arguments": fn.get("arguments", "{}"),
            "tool_call_id": tc.get("id", ""),
        })
    return outs


def run_with_local_tools(
    api_key: str,
    model: str,
    instructions: Optional[str],
    user_input: str,
    tools_by_name: Dict[str, Any],
    tool_schemas: List[Dict[str, Any]],
    timeout_s: int,
    max_turns: int = _MAX_TOOL_TURNS,
    reasoning_effort: Optional[str] = None,
    temperature: Optional[float] = None,
    referer: str = "",
    title: str = "",
    print_progress: bool = True,
) -> Dict[str, Any]:
    """Chat-completions tool loop. Mirrors ``bm.run_with_local_tools`` semantics
    but speaks OpenAI shape."""
    messages: List[Dict[str, Any]] = []
    if instructions:
        messages.append({"role": "system", "content": instructions})
    messages.append({"role": "user", "content": user_input})

    all_outputs: List[Dict[str, Any]] = []
    invocations: List[Dict[str, Any]] = []
    usage_total: Dict[str, int] = {}

    def _emit(m: str) -> None:
        if print_progress:
            print(m)

    def _accum_usage(u: Dict[str, Any]) -> None:
        for k, v in (u or {}).items():
            if isinstance(v, (int, float)):
                usage_total[k] = usage_total.get(k, 0) + int(v)

    _emit("      ▸ starting conversation")
    for turn in range(max_turns + 1):
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "tools": tool_schemas,
            "stream": False,
        }
        if reasoning_effort:
            payload["reasoning_effort"] = reasoning_effort
            # OpenRouter unifies via either "reasoning_effort" or
            # "reasoning":{"effort":...}; sending both is safe.
            payload["reasoning"] = {"effort": reasoning_effort}
        if temperature is not None:
            payload["temperature"] = temperature

        resp = _post(f"{API_BASE}{CHAT_PATH}", api_key, payload, timeout_s,
                     referer=referer, title=title)
        _accum_usage(resp.get("usage") or {})
        choice = (resp.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        outs = _outputs_from_choice(msg)
        all_outputs.extend(outs)

        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            break

        # Append the assistant message verbatim — provider requires the same
        # tool_calls object referenced by subsequent role:tool replies.
        messages.append({
            "role": "assistant",
            "content": msg.get("content") or "",
            "tool_calls": tool_calls,
        })

        _emit(f"      ▸ turn {turn+1}: {len(tool_calls)} tool_call(s)")
        for tc in tool_calls:
            tc_id = tc.get("id", "")
            fn = tc.get("function") or {}
            name = fn.get("name", "")
            raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                args = {}
            tool = tools_by_name.get(name)
            if tool is None:
                out_str = json.dumps({"error": f"unknown tool {name!r}",
                                      "available": sorted(tools_by_name)})
                ok = False
            else:
                try:
                    out_str = tool.invoke(args)
                    ok = True
                except Exception as exc:  # noqa: BLE001
                    out_str = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
                    ok = False
            invocations.append({
                "turn": turn + 1, "name": name, "args": args, "ok": ok,
                "tool_call_id": tc_id, "output_chars": len(out_str),
            })
            messages.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "name": name,
                "content": out_str,
            })
            _emit(f"        - {name}({bm._short_args(args)}) → {len(out_str)} chars")

        if turn == max_turns:
            _emit(f"      ▸ hit max_turns={max_turns}; stopping local loop")
            break

    return {
        "conversation_id": "",
        "outputs": all_outputs,
        "usage": usage_total,
        "tool_invocations": invocations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default=os.environ.get("OPENROUTER_MODEL", "openai/gpt-oss-120b:free"))
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--instructions-file", default=None,
                        help="Path to a file whose content becomes the system prompt. "
                             "Defaults to src/vapt_orchestrator_safe/prompts/dispatcher.md.")
    parser.add_argument("--reasoning-effort", default="high",
                        choices=["low", "medium", "high"],
                        help="OpenAI-compatible reasoning knob (gpt-oss honors it).")
    parser.add_argument("--temperature", type=float, default=None)
    parser.add_argument("--timeout-s", type=int, default=360)
    parser.add_argument("--fixtures", nargs="*", default=_DEFAULT_FIXTURES)
    parser.add_argument("--sleep-between", type=float, default=4.0,
                        help="Free-tier RPM is tight; default 4s ≈ 15 req/min.")
    parser.add_argument("--max-turns", type=int, default=_MAX_TOOL_TURNS)
    parser.add_argument("--outputs-dir", default=str(ROOT / "outputs"))
    parser.add_argument("--save-raw", action="store_true")
    parser.add_argument("--referer", default=os.environ.get("OPENROUTER_REFERER", ""))
    parser.add_argument("--app-title", default=os.environ.get("OPENROUTER_APP_TITLE", "vapt-orchestrator-safe"))
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise SystemExit("Need --api-key or OPENROUTER_API_KEY")

    # Resolve system prompt (defaults to the dispatcher prompt the Mistral
    # bench's agent was wired with).
    prompt_path = Path(args.instructions_file) if args.instructions_file else (
        ROOT / "src" / "vapt_orchestrator_safe" / "prompts" / "dispatcher.md"
    )
    if not prompt_path.exists():
        raise SystemExit(f"System prompt file not found: {prompt_path}")
    instructions = prompt_path.read_text(encoding="utf-8")

    lab = LocalLabAdapter(ROOT)
    outputs_dir = Path(args.outputs_dir); outputs_dir.mkdir(parents=True, exist_ok=True)
    tag = re.sub(r"[^A-Za-z0-9._-]+", "_", args.model)
    jsonl_path = outputs_dir / f"bench_openrouter_{tag}.jsonl"
    json_path = outputs_dir / f"bench_openrouter_{tag}.json"
    raw_dir = outputs_dir / f"raw_openrouter_{tag}"
    runs_dir = outputs_dir / f"runs_openrouter_{tag}"
    if args.save_raw:
        raw_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)

    print("Loading KG + RAG …")
    kg = bm._build_kg()
    rag = CompressedRAG(DEFAULT_KB)
    nodes, edges = kg.size()
    print(f"  KG: {nodes} nodes, {edges} edges")

    schema_tools = bm._instantiate_tools(
        Blackboard(run_id="schema_only", run_dir=runs_dir / "_schema"), kg, rag,
    )
    tool_schemas = [bm._tool_to_mistral_schema(t) for t in schema_tools.values()]
    print(f"  Tools exposed to provider: {[s['function']['name'] for s in tool_schemas]}")

    results: List[Dict[str, Any]] = []
    completed: set = set()
    if jsonl_path.exists():
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line); results.append(row); completed.add(row["fixture"])
        print(f"Resumed {len(results)} rows from {jsonl_path}")

    total = len(args.fixtures); bench_t0 = time.perf_counter()
    print(f"\nProvider: openrouter   model={args.model!r}")
    print(f"Endpoint: {API_BASE}{CHAT_PATH}")
    print(f"Reasoning: effort={args.reasoning_effort}")
    print(f"Fixtures: {total}\n")

    for idx, fixname in enumerate(args.fixtures, 1):
        if fixname in completed:
            print(f"[{idx}/{total}] {fixname}  SKIP"); continue
        fixture_dir = (ROOT / "data" / "fixtures" / fixname).resolve()
        if not fixture_dir.exists():
            print(f"[{idx}/{total}] {fixname}  MISSING fixture"); continue

        manifest = lab.load_manifest(fixture_dir)
        transcript = lab.load_http_transcript(fixture_dir)
        source_files = lab.load_source_files(fixture_dir)
        ground_truth = lab.load_ground_truth(fixture_dir)

        run_dir = runs_dir / fixname; run_dir.mkdir(parents=True, exist_ok=True)
        bb = bm._build_blackboard(fixname, manifest, transcript, source_files, run_dir)
        tools_by_name = bm._instantiate_tools(bb, kg, rag)

        user_input = bm._build_user_input(manifest, transcript)
        expected = ground_truth.get("expected_vulnerability", "")
        expected_oracle = ground_truth.get("oracle", "")

        print(f"[{idx}/{total}] {fixname}  expected={expected}")
        t0 = time.perf_counter(); text = ""; err = ""; run_data: Dict[str, Any] = {}
        try:
            run_data = run_with_local_tools(
                api_key=api_key,
                model=args.model,
                instructions=instructions,
                user_input=user_input,
                tools_by_name=tools_by_name,
                tool_schemas=tool_schemas,
                timeout_s=args.timeout_s,
                max_turns=args.max_turns,
                reasoning_effort=args.reasoning_effort,
                temperature=args.temperature,
                referer=args.referer,
                title=args.app_title,
                print_progress=True,
            )
            text = bm._extract_text(run_data.get("outputs") or [])
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
        wall_s = time.perf_counter() - t0

        if args.save_raw and run_data:
            (raw_dir / f"{fixname}.json").write_text(
                json.dumps(run_data, indent=2, ensure_ascii=False), encoding="utf-8")
        try: bb.persist()
        except Exception: pass

        parsed = bm._extract_json(text) if text else None
        predicted = ""; predicted_oracle = ""; severity = ""
        confidence = 0.0; citations: List[str] = []
        if parsed:
            predicted = str(parsed.get("attack_family", "") or "")
            severity = str(parsed.get("severity", "") or "")
            try: confidence = float(parsed.get("confidence", 0.0) or 0.0)
            except (TypeError, ValueError): confidence = 0.0
            poc = parsed.get("poc") or {}
            if isinstance(poc, dict): predicted_oracle = str(poc.get("oracle", "") or "")
            citations = list(parsed.get("citations", []) or [])

        findings_ctx = bb.get_phase_context("findings") or {}
        findings_items: List[Dict[str, Any]] = findings_ctx.get("items", []) or []
        if not predicted and findings_items:
            predicted = str(findings_items[0].get("vuln_class", "") or "")

        predicted_norm = bm._normalise_family(predicted)
        detected = int(bm._family_matches(expected, predicted_norm))

        invocations = run_data.get("tool_invocations", []); by_tool: Dict[str, int] = {}
        for inv in invocations: by_tool[inv["name"]] = by_tool.get(inv["name"], 0) + 1
        output_types = sorted({str(o.get("type", "?")) for o in (run_data.get("outputs") or [])})

        row = {
            "fixture": fixname, "expected_attack_family": expected,
            "expected_oracle": expected_oracle,
            "predicted_attack_family": predicted, "predicted_oracle": predicted_oracle,
            "predicted_severity": severity, "predicted_confidence": confidence,
            "citations": citations, "tool_calls_by_name": by_tool,
            "tool_call_count": len(invocations),
            "recorded_findings": findings_items, "output_types": output_types,
            "detected": detected, "wall_s": round(wall_s, 2),
            "raw_text": text[:3000], "parsed": parsed,
            "usage": run_data.get("usage", {}), "error": err,
        }
        results.append(row)
        with open(jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

        flag = "V" if detected else "-"
        if err:
            print(f"  ERROR: {err[:400]}")
        else:
            print(f"  [{flag}] predicted={predicted!r}  oracle={predicted_oracle!r}  "
                  f"sev={severity}  conf={confidence:.2f}  wall={wall_s:.1f}s")
            print(f"      tool_calls: {by_tool} (total {len(invocations)})")
            print(f"      findings_recorded: {len(findings_items)}")
            usage = run_data.get("usage", {})
            if usage: print(f"      usage(sum across turns): {usage}")
            if not text: print(f"      !! No user-visible text extracted.")
            elif not parsed:
                print(f"      !! Text extracted but JSON parse FAILED. "
                      f"Last 200 chars: ...{text[-200:]!r}")

        if args.sleep_between > 0 and idx < total:
            time.sleep(args.sleep_between)

    detected_count = sum(r["detected"] for r in results)
    total_runs = len(results); rate = detected_count / max(1, total_runs)
    elapsed = time.perf_counter() - bench_t0

    json_path.write_text(json.dumps({
        "provider": "openrouter", "model": args.model,
        "fixtures": args.fixtures, "runs": results,
        "detection_rate": round(rate, 3),
        "detected_count": detected_count, "total": total_runs,
        "elapsed_s": round(elapsed, 1),
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n{'='*60}")
    print(f"Done in {elapsed/60:.1f}m")
    print(f"  Detection rate: {detected_count}/{total_runs} = {rate*100:.0f}%")
    per_fixture = {r["fixture"]: ("V" if r["detected"] else "-") for r in results}
    print(f"  By fixture: {per_fixture}")
    print(f"  JSONL: {jsonl_path}")
    print(f"  JSON:  {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
