"""Distill HackTricks (or any markdown corpus) into a CveEntry JSONL knowledge file.

This is the C3 knowledge-ingestion path: it turns messy security-wiki
markdown into the compact, structured ``CveEntry`` records that
``Distiller.populate_kg()`` injects into the knowledge graph. No model
weights are trained — the knowledge is served at query time via
``query_kg`` / ``query_rag``.

Pipeline:
    markdown pages  ->  LLM structured-extraction  ->  CveEntry JSONL
    JSONL           ->  Distiller.from_jsonl(...).populate_kg(kg)   (at run time)

The extraction LLM is resolved through ``backend_factory.build_chat_model``,
so it works with Gemini (default), Mistral, OpenRouter, or a local Ollama
model — you only change ``--model`` / env vars, never the code.

Examples::

    # Gemini (default). Grab a key at aistudio.google.com/apikey
    export GEMINI_API_KEY=...
    python scripts/distill_hacktricks.py --src ~/hacktricks/src/pentesting-web

    # Any other backend understood by backend_factory
    python scripts/distill_hacktricks.py --src ./pages --model custom:mistral-small-latest

    # Local Ollama (free, slower)
    OLLAMA_BASE_URL=http://127.0.0.1:11434 \
        python scripts/distill_hacktricks.py --src ./pages --model ollama:qwen3:8b

Output (resume-safe — re-running skips pages already processed):
    data/corpus/hacktricks.jsonl          (one CveEntry per line)
    data/corpus/hacktricks.jsonl.done     (relative paths already distilled)
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

from vapt_orchestrator_safe.dataset.cve_entry import CveEntry  # noqa: E402
from vapt_orchestrator_safe.llm.backend_factory import build_chat_model  # noqa: E402
from vapt_orchestrator_safe.utils.llm_json import extract_json  # noqa: E402


# Gemini's OpenAI-compatible endpoint — same one registered in bench_api_local.py.
_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"

# Controlled vocabulary for vuln_class so KG families stay consistent with seed.py.
_VULN_CLASSES = [
    "SQLi", "NoSQLi", "IDOR", "SSRF", "XSS", "RCE", "CommandInjection",
    "AuthBypass", "PathTraversal", "LFI", "RFI", "Deserialization",
    "XXE", "SSTI", "CSRF", "OpenRedirect", "FileUpload", "JWT", "Other",
]

_EXTRACT_PROMPT = """You are a security-knowledge distiller. Read the following \
penetration-testing wiki page and extract every distinct web-vulnerability \
technique it describes into structured JSON.

Return ONLY a JSON array (possibly empty). Each element MUST be an object with \
these fields:

  "cve_id":              real CVE id if the page cites one, else a synthetic id \
"HT-<short-slug>" (e.g. "HT-sqli-union").
  "cwe_id":              best-matching CWE id like "CWE-89", or "" if unknown.
  "title":               one concise line naming the technique.
  "vuln_class":          EXACTLY one of {classes}.
  "severity":            one of "critical","high","medium","low".
  "description":         1-3 sentences, factual, no marketing.
  "affected_frameworks": list of lowercased stacks/frameworks (e.g. ["php","express"]); [] if generic.
  "sinks":               list of dangerous sink names (e.g. ["mysqli_query","include"]).
  "sources":             list of taint sources (e.g. ["query_param","request_body"]); [] if none.
  "payload_templates":   list of concrete example payloads/strings from the page.
  "oracle_hints":        list of short signals proving success (e.g. ["sleep_delay","file_contents_returned"]).
  "remediation":         1 sentence fix, or "".
  "tags":                short keyword list (e.g. ["blind","union-based"]).

Rules:
- Split genuinely different techniques into separate objects; do NOT merge them.
- Keep every field compact — this feeds a token-efficient knowledge graph.
- If the page describes no concrete web vulnerability technique, return [].
- Output the JSON array and nothing else (no prose, no code fences are required).

PAGE TITLE: {title}

PAGE CONTENT:
{content}
"""


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
    return s[:40] or "page"


def _configure_gemini_env() -> None:
    """If using the default Gemini spec, wire the OpenAI-compat env vars."""
    os.environ.setdefault("LLM_CUSTOM_BASE_URL", _GEMINI_BASE_URL)
    key = (
        os.environ.get("LLM_CUSTOM_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or os.environ.get("GOOGLE_API_KEY")
    )
    if key:
        os.environ["LLM_CUSTOM_API_KEY"] = key


def _coerce_entries(raw: Any, source_rel: str) -> List[CveEntry]:
    """Validate LLM output into CveEntry objects, filling required fields."""
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []

    out: List[CveEntry] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        vuln_class = str(item.get("vuln_class") or "Other").strip()
        if not title:
            continue
        cve_id = str(item.get("cve_id") or "").strip()
        if not cve_id:
            cve_id = f"HT-{_slugify(title)}-{i}"
        item.setdefault("cwe_id", "")
        item.setdefault("severity", "medium")
        item.setdefault("description", title)
        item["cve_id"] = cve_id
        item["title"] = title
        item["vuln_class"] = vuln_class
        # Provenance so we can trace every fact back to its page.
        refs = item.get("references") or []
        if isinstance(refs, list):
            refs.append(f"hacktricks:{source_rel}")
            item["references"] = refs
        tags = item.get("tags") or []
        if isinstance(tags, list) and "hacktricks" not in tags:
            tags.append("hacktricks")
            item["tags"] = tags
        try:
            out.append(CveEntry.from_dict(item))
        except Exception:
            continue
    return out


def _is_rate_limit(exc: Exception) -> bool:
    s = str(exc).lower()
    return "429" in s or "quota" in s or "rate limit" in s or "resource_exhausted" in s


def _invoke_with_backoff(chat: Any, prompt: str, *, max_retries: int, backoff_s: float) -> Any:
    """Call the model, backing off and retrying on 429/quota errors.

    Rate-limit errors wait out the per-minute window (``backoff_s``, doubling
    each attempt) and retry the SAME page so nothing is lost. Non-rate-limit
    errors propagate immediately.
    """
    attempt = 0
    while True:
        try:
            return chat.invoke(prompt)
        except Exception as exc:
            if not _is_rate_limit(exc) or attempt >= max_retries:
                raise
            wait = backoff_s * (2 ** attempt)
            print(f"      rate-limited; backing off {wait:.0f}s "
                  f"(retry {attempt + 1}/{max_retries})")
            time.sleep(wait)
            attempt += 1


def _llm_content(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, list):
        return "".join(
            p.get("text", "") if isinstance(p, dict) else str(p) for p in content
        )
    return str(content or "")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--src", required=True,
                        help="Directory of markdown (.md) pages to distill.")
    parser.add_argument("--out", default=str(ROOT / "data" / "corpus" / "hacktricks.jsonl"),
                        help="Output JSONL path.")
    parser.add_argument("--model", default="custom:gemini-2.5-flash",
                        help="Backend spec understood by backend_factory (default: Gemini).")
    parser.add_argument("--glob", default="**/*.md",
                        help="Glob under --src for pages (default: recursive *.md).")
    parser.add_argument("--max-chars", type=int, default=12000,
                        help="Truncate each page to this many chars before sending.")
    parser.add_argument("--limit", type=int, default=0,
                        help="Process at most N pages (0 = all). Useful for a smoke run.")
    parser.add_argument("--sleep", type=float, default=7.0,
                        help="Seconds to sleep between LLM calls (keep under provider RPM; "
                             "Gemini free tier is ~10 req/min, so >=7s is safe).")
    parser.add_argument("--max-retries", type=int, default=5,
                        help="Retries per page on 429/quota errors (exponential backoff).")
    parser.add_argument("--backoff", type=float, default=30.0,
                        help="Base backoff seconds on a rate-limit error (doubles each retry).")
    parser.add_argument("--temperature", type=float, default=0.1)
    args = parser.parse_args()

    if args.model.startswith("custom:gemini") or "gemini" in args.model:
        _configure_gemini_env()

    src_dir = Path(args.src).expanduser().resolve()
    if not src_dir.is_dir():
        raise SystemExit(f"--src is not a directory: {src_dir}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    done_path = out_path.with_suffix(out_path.suffix + ".done")

    done: set = set()
    if done_path.exists():
        done = {ln.strip() for ln in done_path.read_text(encoding="utf-8").splitlines() if ln.strip()}

    pages = sorted(p for p in src_dir.glob(args.glob) if p.is_file())
    if args.limit > 0:
        pages = pages[: args.limit + len(done)]

    try:
        chat = build_chat_model(args.model, temperature=args.temperature)
    except Exception as exc:
        raise SystemExit(f"Failed to build model {args.model!r}: {exc}")

    total_entries = 0
    processed = 0
    print(f"Model:  {args.model}")
    print(f"Source: {src_dir}  ({len(pages)} pages matched)")
    print(f"Output: {out_path}\n")

    for page in pages:
        rel = str(page.relative_to(src_dir))
        if rel in done:
            continue
        processed += 1

        text = page.read_text(encoding="utf-8", errors="ignore")
        if not text.strip():
            done.add(rel)
            continue
        content = text[: args.max_chars]
        title = page.stem.replace("-", " ").replace("_", " ")

        prompt = _EXTRACT_PROMPT.format(
            classes=", ".join(_VULN_CLASSES), title=title, content=content
        )

        try:
            response = _invoke_with_backoff(
                chat, prompt, max_retries=args.max_retries, backoff_s=args.backoff
            )
            entries = _coerce_entries(extract_json(_llm_content(response)), rel)
        except Exception as exc:
            print(f"  [!] {rel}: {type(exc).__name__}: {str(exc)[:160]}")
            if args.sleep > 0:
                time.sleep(args.sleep)
            continue

        if entries:
            with open(out_path, "a", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")
            total_entries += len(entries)

        done.add(rel)
        done_path.write_text("\n".join(sorted(done)) + "\n", encoding="utf-8")
        print(f"  [{processed}] {rel}: +{len(entries)} entries  (total {total_entries})")

        if args.sleep > 0:
            time.sleep(args.sleep)

    print(f"\nDone. {total_entries} entries from {processed} new pages -> {out_path}")
    print("Next: load it into the run-time KG (merge into dispatcher_runner), or verify with:")
    print(f"  vapt-safe ingest --input {out_path} --populate-kg")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
