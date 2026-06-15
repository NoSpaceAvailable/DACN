"""Benchmark a Mistral Agent using LOCAL framework tools (no Mistral hosted RAG).

Unlike :file:`bench_mistral_agent.py` (which relies on Mistral's hosted
``document_library``), this script keeps the agent_id (model + system prompt
the user configured in Mistral Studio) but **passes our framework's function
tools at runtime** and executes them locally:

  - ``query_kg``    — local InMemoryKG seeded with build_default_kg + the
                       distilled HackTricks corpus (data/corpus/hacktricks.jsonl).
  - ``query_rag``   — CompressedRAG over data/knowledge/.
  - ``read_source`` — the fixture source code (loaded via LocalLabAdapter).
  - ``record_finding`` — writes findings to a per-run Blackboard.

The loop is:

  1. POST /v1/conversations   {agent_id, inputs, tools=[...], stream:false}
  2. Parse outputs[] for entries of type "function.call"
  3. For each call: invoke the matching local tool, capture the stdout JSON
  4. POST /v1/conversations/{id}/append  {inputs: [function.result, ...]}
  5. Repeat until a turn returns only message.output (no more calls).

Document_library hosted on the agent **stays attached** (Mistral merges
runtime tools with agent tools). To compare apples-to-apples with the
local-only KG, attach an agent that has no built-in tools — or detach
document_library via :file:`scripts/attach_mistral_library.py --drop-builtin`.

Usage (PowerShell)::

    python scripts/bench_mistral_agent_local_tools.py `
        --agent-id ag_019ebfe8084d737b913847fe75e7bc77 `
        --api-key $env:MISTRAL_API_KEY

Outputs (resume-safe):
    outputs/bench_mistral_local_<agent_id>.jsonl
    outputs/bench_mistral_local_<agent_id>.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.exists() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    import requests
except ImportError:
    raise SystemExit("pip install requests")

from vapt_orchestrator_safe.config import DEFAULT_KB, _load_dotenv_if_present

# Pull .env / .env.local into os.environ BEFORE argparse defaults are resolved
# so the CLI flags below see MISTRAL_API_KEY / MISTRAL_AGENT_ID / MISTRAL_MODEL_ID
# values from the file. Idempotent: keys already in os.environ win.
_load_dotenv_if_present()

from vapt_orchestrator_safe.dataset import Distiller
from vapt_orchestrator_safe.kg import InMemoryKG, build_default_kg
from vapt_orchestrator_safe.memory.rag import CompressedRAG
from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.sandbox.local_lab import LocalLabAdapter
from vapt_orchestrator_safe.tools.analysis_tools import ReadSourceTool, RecordFindingTool
from vapt_orchestrator_safe.tools.cve_tool import QueryCveTool
from vapt_orchestrator_safe.tools.ghsa_tool import QueryGhsaTool
from vapt_orchestrator_safe.tools.kg_tools import QueryKGTool, QueryRAGTool


API_BASE = "https://api.mistral.ai"
CONVERSATIONS_PATH = "/v1/conversations"

_DEFAULT_FIXTURES = [f"web-{i:03d}" for i in range(1, 21)]

_MAX_TOOL_TURNS = 18  # Hard cap on local tool-loop iterations per fixture.


# ─────────────────────────── Tool schema conversion ──────────────────────────

def _tool_to_mistral_schema(tool: Any) -> Dict[str, Any]:
    """Convert a BaseTool (LangChain + pydantic v2 args_schema) into a Mistral
    function tool definition.

    Mistral accepts the OpenAI-style ``{"type": "function", "function": {...}}``
    shape with a flat JSON schema in ``parameters``.
    """
    schema = tool.args_schema.model_json_schema()
    # Strip pydantic-only fields that Mistral may reject.
    for k in ("title", "$defs", "definitions"):
        schema.pop(k, None)
    # Ensure required keys exist so Mistral's validator doesn't complain.
    schema.setdefault("type", "object")
    schema.setdefault("properties", {})
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": schema,
        },
    }


# ─────────────────────────── KG / Blackboard wiring ──────────────────────────

def _build_kg() -> InMemoryKG:
    kg = InMemoryKG()
    build_default_kg(kg)
    distiller = Distiller.from_seed()
    corpus_path = ROOT / "data" / "corpus" / "hacktricks.jsonl"
    if corpus_path.exists():
        distiller = distiller.merge(Distiller.from_jsonl(corpus_path))
    distiller.populate_kg(kg)
    return kg


def _build_blackboard(
    fixture_name: str, manifest: Dict[str, Any],
    transcript: Dict[str, Any], source_files: List[Dict[str, Any]],
    run_dir: Path,
) -> Blackboard:
    bb = Blackboard(run_id=f"bench_local_{fixture_name}", run_dir=run_dir)
    bb.set_phase_context("intake", {
        "manifest": manifest,
        "transcript": transcript,
        "source_files": source_files,
    })
    return bb


# ─────────────────────────── User input builder ──────────────────────────────

def _build_user_input(manifest: Dict[str, Any], transcript: Dict[str, Any]) -> str:
    """Vague challenge description + transcript (no source — model fetches via read_source).

    Source files are intentionally NOT inlined: the whole point of this script
    is to make the model use ``read_source`` + ``query_kg`` to assemble its
    own context, mirroring the framework dispatcher's pipeline.
    """
    description = str(manifest.get("description") or "Web application security challenge.")
    return "\n".join([
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
        "## Available tools",
        "- `read_source(path?)` — read the target source code; call once with NO args to get every file.",
        "- `query_kg(attack_family?, framework?, subject?, limit?)` — query the local offensive KG for payloads/sinks/CWEs.",
        "- `query_rag(query, top_k?)` — full-text fallback over compressed knowledge cards.",
        "- `query_cve(cve_id? | keyword? | component?+version?, limit?)` — online NVD CVE lookup (cached). Best for system/server software: nginx, apache, openssl, php, postgresql, etc. Pass `component=\"nginx\", version=\"1.17.6\"` when source pins a version.",
        "- `query_ghsa(ghsa_id? | cve_id? | package?+ecosystem?+version?, limit?)` — online GitHub Advisory DB (cached). Best for package-ecosystem deps: npm/pip/maven/rubygems/go/rust/composer/nuget. Pass `package=\"express\", ecosystem=\"npm\", version=\"4.17.0\"` when a lockfile pins a version.",
        "- `record_finding(vuln_class, location, description, severity, suggested_poc?)` — log ONE bug.",
        "",
        "## Workflow",
        "1. Call `read_source` (no args) to see all source code.",
        "2. **MANDATORY VERSION SWEEP — before any `record_finding`:** scan everything you read for pinned component+version (comments like `# nginx version 1.17.6`, server banners `Server: nginx/1.17.6`, dependency files `package.json`/`requirements.txt`/`pom.xml`, Dockerfile `FROM nginx:1.17.6`). For EACH pinned version, call `query_cve` (system software) OR `query_ghsa` (package ecosystem). DO NOT skip this step — a logic bug at version X.Y.Z often turns out to be a known CVE with a different vuln class than you initially guessed (e.g. nginx 1.17.6 `error_page` ≠ Auth Bypass; it is CVE-2019-20372 HTTP Request Smuggling).",
        "3. For each suspicious pattern, call `query_kg(attack_family=<class>)` to confirm the technique.",
        "4. Call `record_finding` for every distinct bug. **If `query_cve`/`query_ghsa` returned a matching CVE, use the CVE's vuln class as `vuln_class` (e.g. \"HTTP Request Smuggling\") and cite the CVE id in `description`.** Do not invent your own classification when a CVE is available.",
        "5. After recording, emit ONE JSON object matching your system schema "
        "(attack_family, severity, confidence, poc{request,oracle}, citations).",
        "",
        "Begin by calling `read_source`. Do NOT emit the final JSON before "
        "you have read the code, performed the version sweep, and recorded at least one finding.",
    ])


# ─────────────────────────── Response parsing ────────────────────────────────

def _block_text(block: Any) -> str:
    if isinstance(block, str):
        return block
    if not isinstance(block, dict):
        return ""
    btype = block.get("type", "")
    if btype == "thinking":
        return ""
    if btype == "text":
        t = block.get("text")
        if isinstance(t, str):
            return t
        if isinstance(t, list):
            return "".join(_block_text(x) for x in t)
    if "text" in block and isinstance(block["text"], str):
        return block["text"]
    return ""


def _extract_text(outputs: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    for out in outputs:
        if not isinstance(out, dict):
            continue
        if out.get("type") not in ("message.output", "message"):
            continue
        content = out.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, dict):
            parts.append(_block_text(content))
        elif isinstance(content, list):
            for block in content:
                parts.append(_block_text(block))
    return "".join(parts).strip()


def _collect_function_calls(outputs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pull out function.call entries (custom tools the client must execute)."""
    calls: List[Dict[str, Any]] = []
    for out in outputs:
        if not isinstance(out, dict):
            continue
        if out.get("type") != "function.call":
            continue
        name = out.get("name") or (out.get("function") or {}).get("name") or ""
        args_str = out.get("arguments") or out.get("input") or "{}"
        tool_call_id = (
            out.get("tool_call_id")
            or out.get("id")
            or out.get("call_id")
            or ""
        )
        calls.append({
            "name": name,
            "arguments_raw": args_str,
            "tool_call_id": tool_call_id,
        })
    return calls


# ─────────────────────────── HTTP helpers ────────────────────────────────────

def _post(url: str, api_key: str, payload: Dict[str, Any], timeout_s: int) -> Dict[str, Any]:
    r = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=timeout_s,
    )
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code} on {url}: {r.text[:600]}")
    return r.json()


def fetch_agent_config(api_key: str, agent_id: str, timeout_s: int = 30) -> Dict[str, Any]:
    """Pull an agent's model + instructions so we can replay them stateless.

    Mistral routes /v1/conversations into TWO mutually exclusive request types:

      - AgentConversationRequest  (agent_id, inputs)            → tools FIXED on agent
      - ModelConversationRequest  (model, instructions, tools, inputs)  → runtime tools

    To use the user's existing agent config (model + system prompt) BUT pass
    our local function tools at runtime, we fetch the agent once at startup
    and feed (model, instructions) into ModelConversationRequest below.
    """
    last_err = ""
    for path in (f"/v1/agents/{agent_id}", f"/v1/beta/agents/{agent_id}"):
        r = requests.get(
            f"{API_BASE}{path}",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout_s,
        )
        if r.status_code == 200:
            return r.json()
        last_err = f"GET {path} → {r.status_code}: {r.text[:200]}"
    raise RuntimeError(f"Cannot retrieve agent {agent_id}. {last_err}")


def start_conversation(
    api_key: str,
    model: str,
    instructions: Optional[str],
    user_input: str,
    tools: List[Dict[str, Any]],
    timeout_s: int,
    store: bool = True,
    completion_args: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Open a fresh conversation in ModelConversationRequest mode.

    ``agent_id`` is intentionally NOT sent — including it alongside ``tools``
    triggers Mistral's validator to require ``model`` (it routes to the
    ModelConversationRequest branch). We replay the agent's model and
    instructions here so behavior stays as close to the agent as possible.
    """
    payload: Dict[str, Any] = {
        "model": model,
        "inputs": user_input,
        "tools": tools,
        "stream": False,
        "store": store,
    }
    if instructions:
        payload["instructions"] = instructions
    if completion_args:
        payload["completion_args"] = completion_args
    return _post(f"{API_BASE}{CONVERSATIONS_PATH}", api_key, payload, timeout_s)


def append_function_results(
    api_key: str,
    conversation_id: str,
    results: List[Dict[str, Any]],
    timeout_s: int,
    store: bool = True,
) -> Dict[str, Any]:
    """Append function.result entries to an open conversation."""
    payload: Dict[str, Any] = {
        "inputs": results,
        "stream": False,
        "store": store,
    }
    return _post(
        f"{API_BASE}{CONVERSATIONS_PATH}/{conversation_id}",
        api_key, payload, timeout_s,
    )


# ─────────────────────────── Tool-loop driver ────────────────────────────────

def run_with_local_tools(
    api_key: str,
    model: str,
    instructions: Optional[str],
    user_input: str,
    tools_by_name: Dict[str, Any],
    tool_schemas: List[Dict[str, Any]],
    timeout_s: int,
    store: bool = True,
    max_turns: int = _MAX_TOOL_TURNS,
    print_progress: bool = True,
    completion_args: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Drive a Mistral agent through a local-tool conversation loop.

    Returns a dict containing the aggregated outputs from every turn (so the
    downstream parsing / RAG-counting logic can read them like a single
    non-streaming response) plus accounting metadata.
    """
    all_outputs: List[Dict[str, Any]] = []
    invocations: List[Dict[str, Any]] = []
    usage_total: Dict[str, int] = {}

    def _accum_usage(u: Dict[str, Any]) -> None:
        for k, v in (u or {}).items():
            if isinstance(v, (int, float)):
                usage_total[k] = usage_total.get(k, 0) + int(v)

    def _emit(msg: str) -> None:
        if print_progress:
            print(msg)

    _emit("      ▸ starting conversation")
    resp = start_conversation(
        api_key=api_key,
        model=model,
        instructions=instructions,
        user_input=user_input,
        tools=tool_schemas,
        timeout_s=timeout_s,
        store=store,
        completion_args=completion_args,
    )
    conv_id = resp.get("conversation_id", "")
    outputs = resp.get("outputs") or []
    all_outputs.extend(outputs)
    _accum_usage(resp.get("usage") or {})

    for turn in range(max_turns):
        fn_calls = _collect_function_calls(outputs)
        if not fn_calls:
            break  # No more tool calls → final message is in outputs.

        _emit(f"      ▸ turn {turn+1}: {len(fn_calls)} function.call(s)")
        result_entries: List[Dict[str, Any]] = []
        for call in fn_calls:
            name = call["name"]
            tool_call_id = call["tool_call_id"]
            try:
                args = json.loads(call["arguments_raw"]) if call["arguments_raw"] else {}
            except json.JSONDecodeError:
                args = {}

            tool = tools_by_name.get(name)
            if tool is None:
                output_str = json.dumps({
                    "error": f"unknown tool {name!r}",
                    "available": sorted(tools_by_name),
                })
                ok = False
            else:
                try:
                    # tool.invoke runs _run → returns the LLM-facing summary string.
                    output_str = tool.invoke(args)
                    ok = True
                except Exception as exc:  # noqa: BLE001
                    output_str = json.dumps({
                        "error": f"{type(exc).__name__}: {exc}",
                    })
                    ok = False

            invocations.append({
                "turn": turn + 1,
                "name": name,
                "args": args,
                "ok": ok,
                "tool_call_id": tool_call_id,
                "output_chars": len(output_str),
            })

            # Per Mistral's FunctionResultEntry schema (mistralai SDK source):
            #   {object: "entry", type: "function.result", tool_call_id, result}
            # No "name" field — including it makes the discriminator misfire
            # and the request fails with a 422 against MessageInputEntry.
            result_entries.append({
                "object": "entry",
                "type": "function.result",
                "tool_call_id": tool_call_id,
                "result": output_str,
            })
            _emit(f"        - {name}({_short_args(args)}) → {len(output_str)} chars")

        if not conv_id:
            raise RuntimeError("Missing conversation_id; cannot append function results.")

        resp = append_function_results(
            api_key=api_key,
            conversation_id=conv_id,
            results=result_entries,
            timeout_s=timeout_s,
            store=store,
        )
        outputs = resp.get("outputs") or []
        all_outputs.extend(outputs)
        _accum_usage(resp.get("usage") or {})
    else:
        _emit(f"      ▸ hit max_turns={max_turns}; stopping local loop")

    return {
        "conversation_id": conv_id,
        "outputs": all_outputs,
        "usage": usage_total,
        "tool_invocations": invocations,
    }


def _short_args(args: Dict[str, Any], limit: int = 80) -> str:
    s = json.dumps(args, ensure_ascii=False)
    return s if len(s) <= limit else s[: limit - 3] + "..."


# ─────────────────────────── JSON extraction (shared logic) ──────────────────

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
        "lfi": "lfi",
        "lfiattack": "lfi",
        "localfileinclusion": "lfi",
        "pathtraversal": "lfi",
        "directorytraversal": "lfi",
        "pathtraversalattack": "lfi",
        "filepathmanipulation": "lfi",
        "insecuredirectobjectreference": "idor",
        "jwtforgery": "authbypass",
        "jwttokenforgery": "authbypass",
        "jwtmanipulation": "authbypass",
        "tokenforgery": "authbypass",
        "authenticationbypass": "authbypass",
        "authorizationbypass": "authbypass",
        "sessionhijack": "authbypass",
        "httpsmuggling": "httprequestsmuggling",
        "requestsmuggling": "httprequestsmuggling",
        "clterequestsmuggling": "httprequestsmuggling",
        "telcsmuggling": "httprequestsmuggling",
    }
    return aliases.get(s, s)


# ─────────────────────────── Main loop ───────────────────────────────────────

def _instantiate_tools(blackboard: Blackboard, kg: InMemoryKG, rag: CompressedRAG) -> Dict[str, Any]:
    tools = [
        ReadSourceTool(),
        RecordFindingTool(),
        QueryKGTool(kg),
        QueryRAGTool(rag),
        QueryCveTool(),
        QueryGhsaTool(),
    ]
    for t in tools:
        if hasattr(t, "bind_blackboard"):
            t.bind_blackboard(blackboard)
    return {t.name: t for t in tools}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--agent-id", default=os.environ.get("MISTRAL_AGENT_ID"),
                        help="Source the model + instructions from this agent (one-time GET). "
                             "Falls back to MISTRAL_AGENT_ID env var. "
                             "If omitted, you must pass --model (and optionally --instructions).")
    parser.add_argument("--model", default=os.environ.get("MISTRAL_MODEL_ID"),
                        help="Override the model resolved from --agent-id (or set directly). "
                             "Falls back to MISTRAL_MODEL_ID env var.")
    parser.add_argument("--instructions", default=None,
                        help="Override the agent's system instructions. Pass '' to clear.")
    parser.add_argument("--no-store", action="store_true")
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--timeout-s", type=int, default=240)
    parser.add_argument("--fixtures", nargs="*", default=_DEFAULT_FIXTURES)
    parser.add_argument("--sleep-between", type=float, default=2.0)
    parser.add_argument("--max-turns", type=int, default=_MAX_TOOL_TURNS,
                        help="Hard cap on tool-loop iterations per fixture.")
    parser.add_argument("--outputs-dir", default=str(ROOT / "outputs"))
    parser.add_argument("--save-raw", action="store_true",
                        help="Dump every per-turn response under outputs/raw_mistral_local_<agent>/.")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        raise SystemExit("Need --api-key or MISTRAL_API_KEY")
    if not args.agent_id and not args.model:
        raise SystemExit("Need either --agent-id (to source model+instructions) or --model.")

    # ── Resolve model + instructions ────────────────────────────────────────
    # Mistral routes a request with `tools` AND `agent_id` as a
    # ModelConversationRequest, which rejects `agent_id` (422 "model" required).
    # So we fetch the agent ONCE to copy its model + instructions, then call
    # the model flow with our runtime tools. The agent stays untouched.
    resolved_model: Optional[str] = args.model
    resolved_instructions: Optional[str] = args.instructions
    resolved_completion_args: Optional[Dict[str, Any]] = None
    agent_name = ""
    if args.agent_id:
        print(f"Fetching agent {args.agent_id} (one-time) …")
        agent_cfg = fetch_agent_config(api_key, args.agent_id, timeout_s=args.timeout_s)
        agent_name = str(agent_cfg.get("name", ""))
        if not resolved_model:
            resolved_model = str(agent_cfg.get("model") or "")
        if resolved_instructions is None:
            resolved_instructions = agent_cfg.get("instructions") or ""
        resolved_completion_args = agent_cfg.get("completion_args") or None
        print(f"  name:         {agent_name!r}")
        print(f"  model:        {resolved_model}")
        print(f"  instructions: {len(resolved_instructions or '')} chars")
        print(f"  completion_args: {resolved_completion_args}")
    if not resolved_model:
        raise SystemExit("Could not resolve model. Pass --model.")

    lab = LocalLabAdapter(ROOT)
    outputs_dir = Path(args.outputs_dir)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    tag_source = args.agent_id or resolved_model
    tag = re.sub(r"[^A-Za-z0-9._-]+", "_", tag_source)
    jsonl_path = outputs_dir / f"bench_mistral_local_{tag}.jsonl"
    json_path = outputs_dir / f"bench_mistral_local_{tag}.json"
    raw_dir = outputs_dir / f"raw_mistral_local_{tag}"
    runs_dir = outputs_dir / f"runs_mistral_local_{tag}"
    if args.save_raw:
        raw_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)

    # Build KG + RAG once for the whole bench (KG is read-only across fixtures).
    print("Loading KG + RAG …")
    kg = _build_kg()
    rag = CompressedRAG(DEFAULT_KB)
    nodes, edges = kg.size()
    print(f"  KG: {nodes} nodes, {edges} edges")

    # Tool schemas only depend on args_schema, not the instance → build once.
    schema_tools = _instantiate_tools(
        Blackboard(run_id="schema_only", run_dir=runs_dir / "_schema"), kg, rag,
    )
    tool_schemas = [_tool_to_mistral_schema(t) for t in schema_tools.values()]
    print(f"  Tools exposed to Mistral: {[s['function']['name'] for s in tool_schemas]}")

    # Resume support
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

    print(f"\nSource:   agent_id={args.agent_id!r}  → model={resolved_model!r}")
    print(f"Endpoint: {API_BASE}{CONVERSATIONS_PATH}  "
          f"(ModelConversationRequest + runtime function tools, agent left untouched)")
    print(f"Fixtures: {total}\n")

    for idx, fixname in enumerate(args.fixtures, 1):
        if fixname in completed:
            print(f"[{idx}/{total}] {fixname}  SKIP")
            continue
        fixture_dir = (ROOT / "data" / "fixtures" / fixname).resolve()
        if not fixture_dir.exists():
            print(f"[{idx}/{total}] {fixname}  MISSING fixture")
            continue

        manifest = lab.load_manifest(fixture_dir)
        transcript = lab.load_http_transcript(fixture_dir)
        source_files = lab.load_source_files(fixture_dir)
        ground_truth = lab.load_ground_truth(fixture_dir)

        # Fresh per-fixture blackboard so findings/loop signatures don't bleed.
        run_dir = runs_dir / fixname
        run_dir.mkdir(parents=True, exist_ok=True)
        bb = _build_blackboard(fixname, manifest, transcript, source_files, run_dir)
        tools_by_name = _instantiate_tools(bb, kg, rag)

        user_input = _build_user_input(manifest, transcript)
        expected = ground_truth.get("expected_vulnerability", "")
        expected_oracle = ground_truth.get("oracle", "")
        expected_norm = _normalise_family(expected)

        print(f"[{idx}/{total}] {fixname}  expected={expected}")
        t0 = time.perf_counter()
        text = ""
        err = ""
        run_data: Dict[str, Any] = {}
        try:
            run_data = run_with_local_tools(
                api_key=api_key,
                model=resolved_model,
                instructions=resolved_instructions,
                user_input=user_input,
                tools_by_name=tools_by_name,
                tool_schemas=tool_schemas,
                timeout_s=args.timeout_s,
                store=not args.no_store,
                max_turns=args.max_turns,
                print_progress=True,
                completion_args=resolved_completion_args,
            )
            text = _extract_text(run_data.get("outputs") or [])
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
        wall_s = time.perf_counter() - t0

        if args.save_raw and run_data:
            (raw_dir / f"{fixname}.json").write_text(
                json.dumps(run_data, indent=2, ensure_ascii=False), encoding="utf-8",
            )
        # Persist blackboard so each fixture has its own memory.json
        try:
            bb.persist()
        except Exception:
            pass

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

        # Also pull findings the model recorded via the local tool (so even if
        # the final JSON is mangled, we have an attack-family signal).
        findings_ctx = bb.get_phase_context("findings") or {}
        findings_items: List[Dict[str, Any]] = findings_ctx.get("items", []) or []
        if not predicted and findings_items:
            predicted = str(findings_items[0].get("vuln_class", "") or "")

        predicted_norm = _normalise_family(predicted)
        detected = int(bool(predicted_norm) and predicted_norm == expected_norm)

        invocations = run_data.get("tool_invocations", [])
        by_tool: Dict[str, int] = {}
        for inv in invocations:
            by_tool[inv["name"]] = by_tool.get(inv["name"], 0) + 1

        output_types = sorted({str(o.get("type", "?")) for o in (run_data.get("outputs") or [])})

        row = {
            "fixture": fixname,
            "expected_attack_family": expected,
            "expected_oracle": expected_oracle,
            "predicted_attack_family": predicted,
            "predicted_oracle": predicted_oracle,
            "predicted_severity": severity,
            "predicted_confidence": confidence,
            "citations": citations,
            "tool_calls_by_name": by_tool,
            "tool_call_count": len(invocations),
            "recorded_findings": findings_items,
            "output_types": output_types,
            "detected": detected,
            "wall_s": round(wall_s, 2),
            "raw_text": text[:3000],
            "parsed": parsed,
            "conversation_id": run_data.get("conversation_id", ""),
            "usage": run_data.get("usage", {}),
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
            print(f"      tool_calls: {by_tool} (total {len(invocations)})")
            print(f"      findings_recorded: {len(findings_items)}")
            usage = run_data.get("usage", {})
            if usage:
                print(f"      usage(sum across turns): {usage}")
            if not text:
                print(f"      !! No user-visible text extracted. Pass --save-raw to inspect.")
            elif not parsed:
                print(f"      !! Text extracted but JSON parse FAILED. "
                      f"Last 200 chars: ...{text[-200:]!r}")

        if args.sleep_between > 0 and idx < total:
            time.sleep(args.sleep_between)

    detected_count = sum(r["detected"] for r in results)
    total_runs = len(results)
    rate = detected_count / max(1, total_runs)
    elapsed = time.perf_counter() - bench_t0

    json_path.write_text(json.dumps({
        "agent_id": args.agent_id,
        "model": resolved_model,
        "agent_name": agent_name,
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
