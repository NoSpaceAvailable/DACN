"""Benchmark an OpenAI Studio stored prompt against the eval fixtures.

The Studio "stored prompts" feature is exposed via OpenAI's Responses API
(client.responses.create) — NOT the Chat Completions API that LangChain's
ChatOpenAI wraps. So this script bypasses the dispatcher pipeline and runs
the Studio prompt once per fixture in JSON mode, then compares the predicted
attack_family against ground_truth.

Use this for Phase 1 (teacher quality evaluation): feed each fixture into
the RAG-augmented prompt, parse its JSON output, score detection rate.

Usage (PowerShell)::

    # Single run on the full 7-fixture set
    python scripts/bench_openai_prompt.py `
        --prompt-id pmpt_6a2cfa24d3148195bd1d052f26ddc8c801dec46f2ee671c5 `
        --model gpt-5.4-mini `
        --api-key $env:OPENAI_API_KEY

    # Smoke test on 2 fixtures
    python scripts/bench_openai_prompt.py --prompt-id pmpt_... `
        --model gpt-5.4-mini --api-key $env:OPENAI_API_KEY `
        --fixtures challenge_idor_01 challenge_ssrf_01

    # Pin a specific prompt version (else uses the active version)
    python scripts/bench_openai_prompt.py --prompt-id pmpt_... `
        --prompt-version 3 --model gpt-5.4-mini --api-key $env:OPENAI_API_KEY

Outputs (resume-safe):
    outputs/bench_studio_<prompt_id>_<model>.jsonl
    outputs/bench_studio_<prompt_id>_<model>.json
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
    from openai import OpenAI
except ImportError:
    raise SystemExit(
        "Missing dependency. Install with: pip install --upgrade openai"
    )

from vapt_orchestrator_safe.sandbox.local_lab import LocalLabAdapter  # noqa: E402


_DEFAULT_FIXTURES = [
    "challenge_idor_01",
    "challenge_ssrf_01",
    "challenge_sqli_01",
    "challenge_lfi_01",
    "challenge_sqli_02",
    "challenge_nosqli_01",
    "challenge_pathtraversal_01",
]


def _build_user_input(
    fixture_name: str,  # noqa: ARG001 — intentionally not used in input
    manifest: Dict[str, Any],
    transcript: Dict[str, Any],
    source_files: List[Dict[str, Any]],
) -> str:
    """Render the input a CTF player would see: one-line description + the
    HTTP transcript + the source-code handout. Everything else in the
    manifest is omitted to avoid leaking the intended attack family.
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
        # Use just basename so the model doesn't search for the literal path.
        basename = sf["path"].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        parts.append(f"--- {basename} ---")
        parts.append(sf["content"])
        parts.append("")
    parts.append(
        "Emit a single JSON object per the schema in your system instructions. "
        "Pick a snake_case `oracle` that names a concrete signal in the "
        "response or server state that would confirm exploitation. "
        "Before answering, call file_search with conceptual queries about the "
        "vulnerability class (NOT source-code tokens)."
    )
    return "\n".join(parts)


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Tolerant JSON extraction: strip fences, then brace-match."""
    if not text:
        return None
    stripped = re.sub(r"^```(?:json)?\s*", "", text.strip())
    stripped = re.sub(r"```\s*$", "", stripped)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    start = stripped.find("{")
    if start < 0:
        return None
    depth, in_str, esc = 0, False, False
    for i in range(start, len(stripped)):
        c = stripped[i]
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
                    return json.loads(stripped[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _normalise_family(s: str) -> str:
    """Lowercase + strip non-alphanumerics so 'NoSQL Injection' == 'nosqli'."""
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "", s)
    aliases = {
        "nosqlinjection": "nosqli",
        "sqlinjection": "sqli",
        "ssrfattack": "ssrf",
        "lfiattack": "lfi",
        "rfiattack": "rfi",
        "pathtraversal": "pathtraversal",
        "directorytraversal": "pathtraversal",
        "insecuredirectobjectreference": "idor",
        "idorvulnerability": "idor",
    }
    return aliases.get(s, s)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--prompt-id", required=True,
                        help="OpenAI Studio stored prompt id (pmpt_...)")
    parser.add_argument("--prompt-version", default=None,
                        help="Pin a version. Omit to use the active version.")
    parser.add_argument("--model", default="gpt-5.4-mini",
                        help="Model to run the stored prompt with")
    parser.add_argument("--api-key", default=None,
                        help="OPENAI_API_KEY override (else read from env)")
    parser.add_argument("--effort", default="high",
                        choices=["low", "medium", "high"])
    parser.add_argument("--verbosity", default="medium",
                        choices=["low", "medium", "high"])
    parser.add_argument("--max-output-tokens", type=int, default=4096)
    parser.add_argument("--store", action="store_true", default=True,
                        help="Persist run on OpenAI side (default True)")
    parser.add_argument("--no-store", dest="store", action="store_false")
    parser.add_argument("--fixtures", nargs="*", default=_DEFAULT_FIXTURES,
                        help="Fixture names under data/fixtures/")
    parser.add_argument("--sleep-between", type=float, default=1.0,
                        help="Seconds between API calls (rate-limit friendly).")
    parser.add_argument("--outputs-dir", default=str(ROOT / "outputs"))
    parser.add_argument("--force-search", action="store_true",
                        help="Force the model to call file_search at least once "
                             "via tool_choice. Use this to verify RAG binding.")
    parser.add_argument("--vector-store-id", default=None,
                        help="Pass file_search tool explicitly with this vector "
                             "store id (overrides anything bound on the prompt).")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("Need --api-key or OPENAI_API_KEY")

    client = OpenAI(api_key=api_key)
    lab = LocalLabAdapter(ROOT)

    outputs_dir = Path(args.outputs_dir)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    safe_pid = args.prompt_id.replace(":", "_")
    safe_model = args.model.replace("/", "_").replace(":", "_")
    tag = f"{safe_pid}_{safe_model}"
    jsonl_path = outputs_dir / f"bench_studio_{tag}.jsonl"
    json_path = outputs_dir / f"bench_studio_{tag}.json"

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

    print(f"\nPrompt: {args.prompt_id}" +
          (f" (v{args.prompt_version})" if args.prompt_version else " (active)"))
    print(f"Model:  {args.model}")
    print(f"Settings: effort={args.effort} verbosity={args.verbosity} "
          f"max_output={args.max_output_tokens} store={args.store}")
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

        user_input = _build_user_input(fixname, manifest, transcript, source_files)
        expected = ground_truth.get("expected_vulnerability", "")
        expected_oracle = ground_truth.get("oracle", "")
        expected_norm = _normalise_family(expected)

        print(f"[{idx}/{total}] {fixname}  expected={expected}")

        prompt_arg: Dict[str, Any] = {"id": args.prompt_id}
        if args.prompt_version:
            prompt_arg["version"] = args.prompt_version

        extra_kwargs: Dict[str, Any] = {}
        if args.vector_store_id:
            extra_kwargs["tools"] = [{
                "type": "file_search",
                "vector_store_ids": [args.vector_store_id],
            }]
        if args.force_search:
            extra_kwargs["tool_choice"] = {"type": "file_search"}

        t0 = time.perf_counter()
        response = None
        text = ""
        err = ""
        try:
            response = client.responses.create(
                model=args.model,
                prompt=prompt_arg,
                input=user_input,
                reasoning={"effort": args.effort},
                text={"verbosity": args.verbosity},
                max_output_tokens=args.max_output_tokens,
                store=args.store,
                **extra_kwargs,
            )
            text = response.output_text or ""
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
        wall_s = time.perf_counter() - t0

        # ── Inspect tool calls to see if RAG was actually used ──
        search_calls = 0
        search_queries: List[str] = []
        search_results_total = 0
        if response is not None:
            for item in (getattr(response, "output", None) or []):
                if getattr(item, "type", "") == "file_search_call":
                    search_calls += 1
                    qs = getattr(item, "queries", None) or []
                    search_queries.extend(str(q) for q in qs)
                    rs = getattr(item, "results", None) or []
                    search_results_total += len(rs)

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

        row = {
            "fixture": fixname,
            "expected_attack_family": expected,
            "expected_oracle": expected_oracle,
            "predicted_attack_family": predicted,
            "predicted_oracle": predicted_oracle,
            "predicted_severity": severity,
            "predicted_confidence": confidence,
            "citations": citations,
            "rag_search_calls": search_calls,
            "rag_search_queries": search_queries,
            "rag_search_results": search_results_total,
            "detected": detected,
            "wall_s": round(wall_s, 2),
            "response_id": getattr(response, "id", "") if response else "",
            "raw_text": text[:3000],
            "parsed": parsed,
            "error": err,
        }
        results.append(row)
        with open(jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

        flag = "V" if detected else "-"
        if err:
            print(f"  ERROR: {err[:300]}")
        else:
            print(f"  [{flag}] predicted={predicted!r}  oracle={predicted_oracle!r}  "
                  f"sev={severity}  conf={confidence:.2f}  wall={wall_s:.1f}s")
            if citations:
                kb_hits = sum(1 for c in citations if str(c).startswith("[KB"))
                train_hits = sum(1 for c in citations if str(c).startswith("[TRAIN"))
                print(f"      citations: {kb_hits} KB, {train_hits} TRAIN")
            print(f"      RAG: {search_calls} search(es), "
                  f"{search_results_total} result(s)" +
                  (f", q={search_queries[:2]}" if search_queries else ""))

        if args.sleep_between > 0 and idx < total:
            time.sleep(args.sleep_between)

    detected_count = sum(r["detected"] for r in results)
    total_runs = len(results)
    rate = detected_count / max(1, total_runs)
    elapsed = time.perf_counter() - bench_t0

    json_path.write_text(json.dumps({
        "prompt_id": args.prompt_id,
        "prompt_version": args.prompt_version,
        "model": args.model,
        "effort": args.effort,
        "verbosity": args.verbosity,
        "max_output_tokens": args.max_output_tokens,
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
