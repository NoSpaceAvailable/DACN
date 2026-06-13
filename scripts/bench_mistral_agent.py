"""Benchmark a Mistral Agent (with document_library RAG) against eval fixtures.

Uses raw HTTP to /v1/conversations (the official Mistral Agents API endpoint,
matching what the Mistral Studio web UI calls). Avoids mistralai SDK version
incompatibilities.

Response shape from /v1/conversations (stream=false):
  {
    "conversation_id": "conv_...",
    "outputs": [
      {
        "type": "message.output",
        "role": "assistant",
        "content": [
          {"type": "thinking", "thinking": [...]},   # reasoning, skip
          {"type": "text", "text": "actual answer"}, # final output
          {"type": "tool.execution", ...}            # document_library calls
        ]
      }
    ],
    "usage": {...}
  }

Usage (PowerShell)::

    python scripts/bench_mistral_agent.py `
        --agent-id ag_... `
        --api-key $env:MISTRAL_API_KEY `
        --fixtures challenge_nosqli_01

Outputs (resume-safe):
    outputs/bench_mistral_<agent_id>.jsonl
    outputs/bench_mistral_<agent_id>.json
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

try:
    import requests
except ImportError:
    raise SystemExit("pip install requests")

from vapt_orchestrator_safe.sandbox.local_lab import LocalLabAdapter  # noqa: E402


API_BASE = "https://api.mistral.ai"
CONVERSATIONS_PATH = "/v1/conversations"


_DEFAULT_FIXTURES = [
    "challenge_idor_01",
    "challenge_ssrf_01",
    "challenge_sqli_01",
    "challenge_lfi_01",
    "challenge_sqli_02",
    "challenge_nosqli_01",
    "challenge_pathtraversal_01",
]


# ─────────────────────────── Input builder ────────────────────────────────

def _build_user_input(
    manifest: Dict[str, Any],
    transcript: Dict[str, Any],
    source_files: List[Dict[str, Any]],
) -> str:
    """Render the input a CTF player would see: one-line description + the
    HTTP transcript + the source-code handout.

    Everything else in the manifest (id, title, skills, difficulty, mode,
    notes, ...) is deliberately omitted — those fields can leak the
    intended attack family. The challenge description is a vague hook
    matching the framing real CTFs give players.
    """
    description = str(manifest.get("description") or "Web application security challenge.")

    parts: List[str] = [
        "MODE: JSON",
        "",
        "## Challenge",
        description,
        "",
        "## HTTP Transcript",
        "```json",
        json.dumps(transcript, indent=2, ensure_ascii=False),
        "```",
        "",
        "## Source Files",
    ]
    for sf in source_files:
        basename = sf["path"].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        parts.append(f"--- {basename} ---")
        parts.append(sf["content"])
        parts.append("")
    parts.append(
        "Emit a single JSON object per the schema in your system instructions. "
        "Pick a snake_case `oracle` that names a concrete signal in the "
        "response or server state that would confirm exploitation. "
        "Before answering, call document_library with conceptual queries "
        "(vulnerability class + technique, NOT source-code tokens)."
    )
    return "\n".join(parts)


# ─────────────────────────── Response parsing ─────────────────────────────

def _block_text(block: Any) -> str:
    """Extract user-facing text from a single content block. Skips reasoning."""
    if isinstance(block, str):
        return block
    if not isinstance(block, dict):
        return ""
    btype = block.get("type", "")
    if btype == "thinking":
        return ""  # skip reasoning content
    if btype == "text":
        t = block.get("text")
        if isinstance(t, str):
            return t
        if isinstance(t, list):
            return "".join(_block_text(x) for x in t)
    # Some blocks may put text directly under "text" without type
    if "text" in block and isinstance(block["text"], str):
        return block["text"]
    return ""


def _extract_text(response_json: Dict[str, Any]) -> str:
    """Pull assistant text from a /v1/conversations response, skipping thinking.

    Per Mistral docs, `outputs[].content` may be:
      - a plain string  (no reasoning, simple text reply)
      - a single block dict  (one content element, e.g. just text or just thinking)
      - a list of mixed strings + block dicts  (reasoning + final text)
    """
    outputs = response_json.get("outputs") or []
    parts: List[str] = []
    for out in outputs:
        if not isinstance(out, dict):
            continue
        otype = out.get("type", "")
        # Only message outputs carry user-visible text. Tool execution etc. are
        # surfaced separately by _count_rag_use.
        if otype not in ("message.output", "message"):
            continue
        content = out.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, dict):
            parts.append(_block_text(content))
        elif isinstance(content, list):
            for block in content:
                parts.append(_block_text(block))
    text = "".join(parts).strip()
    if text:
        return text

    # Fallback: /v1/agents/completions shape (in case the org routes differently)
    choices = response_json.get("choices") or []
    if choices:
        msg = choices[0].get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, dict):
            return _block_text(content)
        if isinstance(content, list):
            return "".join(_block_text(b) for b in content)
    return ""


def _count_rag_use(response_json: Dict[str, Any]) -> Dict[str, Any]:
    """Count built-in tool invocations + references in a conversations response.

    Per Mistral docs, output types relevant here are `tool.execution`
    (built-in tools: document_library, web_search, code_interpreter, image)
    and `function.call` (custom function tools). Since the agent only has
    document_library attached, any tool.execution is a RAG call.
    """
    info: Dict[str, Any] = {"calls": 0, "queries": [], "references": 0}

    outputs = response_json.get("outputs") or []
    for out in outputs:
        if not isinstance(out, dict):
            continue
        otype = str(out.get("type", "")).lower()

        if otype == "tool.execution" or otype == "function.call":
            info["calls"] += 1
            # Best-effort: capture whatever the query/args were called as
            for key in ("arguments", "input", "query", "name", "tool_name", "function"):
                v = out.get(key)
                if v:
                    info["queries"].append(f"{key}={str(v)[:200]}")
                    break
            # Retrieved chunks may appear under several keys depending on the tool
            for key in ("references", "results", "documents", "chunks", "output", "result"):
                v = out.get(key)
                if isinstance(v, list):
                    info["references"] += len(v)

        # Citations attached to message outputs
        if otype in ("message.output", "message"):
            for key in ("references", "citations", "tool_references"):
                refs = out.get(key)
                if isinstance(refs, list):
                    info["references"] += len(refs)
            # References embedded inside content blocks
            content = out.get("content")
            blocks = content if isinstance(content, list) else (
                [content] if isinstance(content, dict) else []
            )
            for block in blocks:
                if isinstance(block, dict):
                    for key in ("references", "citations"):
                        refs = block.get(key)
                        if isinstance(refs, list):
                            info["references"] += len(refs)

    # Top-level references field
    for key in ("references", "citations"):
        v = response_json.get(key)
        if isinstance(v, list):
            info["references"] += len(v)

    return info


# ─────────────────────────── JSON extraction ──────────────────────────────

def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    s = re.sub(r"^```(?:json)?\s*", "", text.strip())
    s = re.sub(r"```\s*$", "", s)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    start = s.find("{")
    if start < 0:
        return None
    depth, in_str, esc = 0, False, False
    for i in range(start, len(s)):
        c = s[i]
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _normalise_family(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "", s)
    aliases = {
        "nosqlinjection": "nosqli",
        "sqlinjection": "sqli",
        "ssrfattack": "ssrf",
        "lfiattack": "lfi",
        "directorytraversal": "pathtraversal",
        "insecuredirectobjectreference": "idor",
        # Auth bypass family (JWT forgery, token forgery, session hijack all
        # collapse to the same outcome class for benchmark purposes).
        "jwtforgery": "authbypass",
        "jwttokenforgery": "authbypass",
        "jwtmanipulation": "authbypass",
        "tokenforgery": "authbypass",
        "authenticationbypass": "authbypass",
        "authorizationbypass": "authbypass",
        "sessionhijack": "authbypass",
        # HTTP smuggling variants
        "httpsmuggling": "httprequestsmuggling",
        "requestsmuggling": "httprequestsmuggling",
        "clterequestsmuggling": "httprequestsmuggling",
        "telcsmuggling": "httprequestsmuggling",
    }
    return aliases.get(s, s)


# ─────────────────────────── API call ─────────────────────────────────────

def call_agent_conversation(
    api_key: str,
    agent_id: str,
    user_input: str,
    timeout_s: int,
    agent_version: Optional[str] = None,
    store: bool = True,
) -> Dict[str, Any]:
    """POST /v1/conversations with stream=false. Returns parsed JSON response.

    Conforms to the Mistral Conversations API contract:
    https://docs.mistral.ai/api/endpoint/beta/conversations

    Note: ``completion_args`` (max_tokens, temperature, top_p) cannot be
    overridden per-call when ``agent_id`` is used — Mistral rejects with HTTP
    422. Use ``update_mistral_agent.py`` to bump the agent's max_tokens, or
    edit it in Studio (Agents → DACN-pentest → model settings row).
    """
    payload: Dict[str, Any] = {
        "agent_id": agent_id,
        "inputs": user_input,
        "stream": False,
        "store": store,
    }
    if agent_version is not None:
        payload["agent_version"] = agent_version

    r = requests.post(
        f"{API_BASE}{CONVERSATIONS_PATH}",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=timeout_s,
    )
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:600]}")
    return r.json()


def call_agent_streaming(
    api_key: str,
    agent_id: str,
    user_input: str,
    timeout_s: int,
    agent_version: Optional[str] = None,
    store: bool = True,
    print_progress: bool = True,
) -> Dict[str, Any]:
    """POST /v1/conversations with stream=true and consume SSE events.

    Returns a dict matching the non-streaming response shape (outputs/usage)
    so the rest of the pipeline (parsing, RAG counting) is unchanged. Also
    prints live progress to stdout so the user can see thinking and text
    chunks arrive in real time, just like the Studio web UI does.
    """
    payload: Dict[str, Any] = {
        "agent_id": agent_id,
        "inputs": user_input,
        "stream": True,
        "store": store,
    }
    if agent_version is not None:
        payload["agent_version"] = agent_version

    response: Dict[str, Any] = {
        "object": "conversation.response",
        "conversation_id": "",
        "outputs": [],
        "usage": {},
    }

    # Per-message accumulators keyed by output_index from the SSE deltas
    msg_acc: Dict[int, Dict[str, Any]] = {}
    started_at = time.perf_counter()

    def _emit(s: str) -> None:
        if print_progress:
            sys.stdout.write(s)
            sys.stdout.flush()

    with requests.post(
        f"{API_BASE}{CONVERSATIONS_PATH}",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        },
        json=payload,
        timeout=timeout_s,
        stream=True,
    ) as r:
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:600]}")

        for raw_line in r.iter_lines(decode_unicode=True):
            if not raw_line or not raw_line.startswith("data:"):
                continue
            try:
                event = json.loads(raw_line[5:].strip())
            except json.JSONDecodeError:
                continue

            etype = event.get("type", "")

            if etype == "conversation.response.started":
                response["conversation_id"] = event.get("conversation_id", "")
                _emit(f"      ▸ conversation started ({response['conversation_id']})\n")

            elif etype == "message.output.delta":
                output_idx = int(event.get("output_index", 0))
                content_idx = int(event.get("content_index", 0))
                content = event.get("content")
                msg = msg_acc.setdefault(output_idx, {
                    "object": "entry",
                    "type": "message.output",
                    "role": event.get("role", "assistant"),
                    "model": event.get("model", ""),
                    "id": event.get("id", ""),
                    "content": [],
                })
                while len(msg["content"]) <= content_idx:
                    msg["content"].append(None)

                if isinstance(content, dict) and content.get("type") == "thinking":
                    slot = msg["content"][content_idx] or {
                        "type": "thinking",
                        "thinking": [{"type": "text", "text": ""}],
                    }
                    for piece in content.get("thinking") or []:
                        slot["thinking"][0]["text"] += piece.get("text", "")
                    msg["content"][content_idx] = slot
                    _emit(".")  # dot per thinking chunk
                elif isinstance(content, str):
                    slot = msg["content"][content_idx] or {"type": "text", "text": ""}
                    slot["text"] += content
                    msg["content"][content_idx] = slot
                    _emit(content)
                elif isinstance(content, dict) and content.get("type") == "text":
                    slot = msg["content"][content_idx] or {"type": "text", "text": ""}
                    t = content.get("text", "")
                    if isinstance(t, list):
                        t = "".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in t)
                    slot["text"] += str(t)
                    msg["content"][content_idx] = slot
                    _emit(str(t))

            elif etype == "message.output.done":
                output_idx = int(event.get("output_index", 0))
                if output_idx in msg_acc:
                    response["outputs"].append(msg_acc.pop(output_idx))
                _emit("\n      ▸ message complete\n")

            elif etype == "tool.execution.started":
                name = event.get("name", "?")
                _emit(f"\n      ▸ tool '{name}' started\n")

            elif etype == "tool.execution.done":
                response["outputs"].append({
                    "object": "entry",
                    "type": "tool.execution",
                    "name": event.get("name", ""),
                    "arguments": event.get("arguments", ""),
                    "function": event.get("function", ""),
                    "info": event.get("info") or {},
                })
                _emit(f"      ▸ tool done\n")

            elif etype == "conversation.response.done":
                response["usage"] = event.get("usage") or {}
                _emit(f"      ▸ done in {time.perf_counter() - started_at:.1f}s\n")

            elif etype == "conversation.response.error":
                err = event.get("error") or event
                raise RuntimeError(f"Streaming error: {err}")

    # Flush any pending messages that never got an explicit .done event
    for idx in sorted(msg_acc):
        response["outputs"].append(msg_acc[idx])

    return response


# ─────────────────────────── Main loop ────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--agent-id", required=True,
                        help="Mistral Agent id (ag_...)")
    parser.add_argument("--agent-version", default=None,
                        help="Optional agent version (string or int). Omit to use latest.")
    parser.add_argument("--no-store", action="store_true",
                        help="Set store=false on the conversation (won't be persisted).")
    parser.add_argument("--api-key", default=None,
                        help="MISTRAL_API_KEY override (else read from env)")
    parser.add_argument("--timeout-s", type=int, default=240)
    parser.add_argument("--stream", action="store_true",
                        help="Stream SSE events from the agent and print live "
                             "thinking / text deltas, like the Studio web UI. "
                             "Output shape and metrics are identical to the "
                             "non-streaming path.")
    parser.add_argument("--fixtures", nargs="*", default=_DEFAULT_FIXTURES)
    parser.add_argument("--sleep-between", type=float, default=2.0,
                        help="Seconds between API calls (1 req/sec is Mistral default).")
    parser.add_argument("--outputs-dir", default=str(ROOT / "outputs"))
    parser.add_argument("--save-raw", action="store_true",
                        help="Save the full Mistral response JSON alongside each row "
                             "(useful for debugging response shape).")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        raise SystemExit("Need --api-key or MISTRAL_API_KEY")

    lab = LocalLabAdapter(ROOT)

    outputs_dir = Path(args.outputs_dir)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    tag = args.agent_id.replace(":", "_")
    jsonl_path = outputs_dir / f"bench_mistral_{tag}.jsonl"
    json_path = outputs_dir / f"bench_mistral_{tag}.json"
    raw_dir = outputs_dir / f"raw_mistral_{tag}"
    if args.save_raw:
        raw_dir.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []
    completed: set = set()
    if jsonl_path.exists():
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                results.append(row)
                completed.add(row["fixture"])
        print(f"Resumed {len(results)} rows from {jsonl_path}")

    total = len(args.fixtures)
    bench_t0 = time.perf_counter()

    print(f"\nAgent:  {args.agent_id}")
    print(f"Endpoint: {API_BASE}{CONVERSATIONS_PATH}")
    print(f"Fixtures: {total}\n")

    for idx, fixname in enumerate(args.fixtures, 1):
        if fixname in completed:
            print(f"[{idx}/{total}] {fixname}  SKIP (already in jsonl)")
            continue
        fixture_dir = (ROOT / "data" / "fixtures" / fixname).resolve()
        if not fixture_dir.exists():
            print(f"[{idx}/{total}] {fixname}  MISSING fixture")
            continue

        manifest = lab.load_manifest(fixture_dir)
        transcript = lab.load_http_transcript(fixture_dir)
        source_files = lab.load_source_files(fixture_dir)
        ground_truth = lab.load_ground_truth(fixture_dir)

        user_input = _build_user_input(manifest, transcript, source_files)
        expected = ground_truth.get("expected_vulnerability", "")
        expected_oracle = ground_truth.get("oracle", "")
        expected_norm = _normalise_family(expected)

        print(f"[{idx}/{total}] {fixname}  expected={expected}")

        t0 = time.perf_counter()
        response_json: Dict[str, Any] = {}
        text = ""
        err = ""
        try:
            if args.stream:
                response_json = call_agent_streaming(
                    api_key=api_key,
                    agent_id=args.agent_id,
                    user_input=user_input,
                    timeout_s=args.timeout_s,
                    agent_version=args.agent_version,
                    store=not args.no_store,
                    print_progress=True,
                )
            else:
                response_json = call_agent_conversation(
                    api_key=api_key,
                    agent_id=args.agent_id,
                    user_input=user_input,
                    timeout_s=args.timeout_s,
                    agent_version=args.agent_version,
                    store=not args.no_store,
                )
            text = _extract_text(response_json)
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
        wall_s = time.perf_counter() - t0

        if args.save_raw and response_json:
            (raw_dir / f"{fixname}.json").write_text(
                json.dumps(response_json, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        rag_info = _count_rag_use(response_json) if response_json else {
            "calls": 0, "queries": [], "references": 0,
        }

        parsed = _extract_json(text) if text else None
        predicted = ""
        predicted_oracle = ""
        severity = ""
        confidence = 0.0
        citations: List[str] = []
        if parsed:
            predicted = str(parsed.get("attack_family", "") or "")
            severity = str(parsed.get("severity", "") or "")
            try:
                confidence = float(parsed.get("confidence", 0.0) or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0
            poc = parsed.get("poc") or {}
            if isinstance(poc, dict):
                predicted_oracle = str(poc.get("oracle", "") or "")
            citations = list(parsed.get("citations", []) or [])

        predicted_norm = _normalise_family(predicted)
        detected = int(bool(predicted_norm) and predicted_norm == expected_norm)

        # Surface the response output types so we can spot shape issues fast.
        output_types: List[str] = []
        for out in (response_json.get("outputs") or []):
            if isinstance(out, dict):
                output_types.append(str(out.get("type", "?")))

        row = {
            "fixture": fixname,
            "expected_attack_family": expected,
            "expected_oracle": expected_oracle,
            "predicted_attack_family": predicted,
            "predicted_oracle": predicted_oracle,
            "predicted_severity": severity,
            "predicted_confidence": confidence,
            "citations": citations,
            "rag_calls": rag_info["calls"],
            "rag_queries": rag_info["queries"],
            "rag_references": rag_info["references"],
            "output_types": output_types,
            "detected": detected,
            "wall_s": round(wall_s, 2),
            "raw_text": text[:3000],
            "parsed": parsed,
            "conversation_id": response_json.get("conversation_id", ""),
            "usage": response_json.get("usage", {}),
            "error": err,
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
            if citations:
                kb_hits = sum(1 for c in citations if str(c).startswith("[KB"))
                train_hits = sum(1 for c in citations if str(c).startswith("[TRAIN"))
                print(f"      citations: {kb_hits} KB, {train_hits} TRAIN")
            print(f"      RAG: {rag_info['calls']} call(s), "
                  f"{rag_info['references']} reference(s)")
            print(f"      output_types: {output_types}")
            usage = response_json.get("usage", {})
            if usage:
                print(f"      usage: prompt={usage.get('prompt_tokens', '?')} "
                      f"completion={usage.get('completion_tokens', '?')} "
                      f"connector={usage.get('connector_tokens', '?')} "
                      f"total={usage.get('total_tokens', '?')}")
            if not text:
                print(f"      !! No user-visible text extracted. "
                      f"Pass --save-raw to dump full response.")
            elif not parsed:
                print(f"      !! Text extracted but JSON parse FAILED — "
                      f"likely truncated. Try increasing --max-tokens. "
                      f"Last 200 chars: ...{text[-200:]!r}")

        if args.sleep_between > 0 and idx < total:
            time.sleep(args.sleep_between)

    detected_count = sum(r["detected"] for r in results)
    total_runs = len(results)
    rate = detected_count / max(1, total_runs)
    elapsed = time.perf_counter() - bench_t0

    json_path.write_text(json.dumps({
        "agent_id": args.agent_id,
        "fixtures": args.fixtures,
        "runs": results,
        "detection_rate": round(rate, 3),
        "detected_count": detected_count,
        "total": total_runs,
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
