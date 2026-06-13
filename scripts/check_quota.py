"""Probe whether provider/model quota is available right now (1 cheap call each).

Prints OK (quota available) or THROTTLED (429) per model, so you know when a
daily free-tier budget has reset before launching a full run.

Usage:
    # default: probe the common Gemini + Mistral models
    python scripts/check_quota.py

    # specific models
    python scripts/check_quota.py --provider gemini --models gemini-2.5-flash gemini-flash-latest
    python scripts/check_quota.py --provider mistral --models mistral-small-latest mistral-large-latest
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.exists() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vapt_orchestrator_safe.llm.backend_factory import build_chat_model  # noqa: E402

# Keys live in the sibling context/ dir (outside the repo).
def _ctx(name: str) -> Path:
    for p in (ROOT / "context" / name, ROOT.parent / "context" / name):
        if p.exists():
            return p
    return ROOT.parent / "context" / name


ENDPOINTS = {
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/",
               _ctx("token"),
               ["gemini-2.5-flash", "gemini-flash-latest", "gemini-2.5-flash-lite"]),
    "mistral": ("https://api.mistral.ai/v1",
                _ctx("astral"),
                ["mistral-small-latest", "mistral-medium-latest", "mistral-large-latest"]),
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", choices=sorted(ENDPOINTS), default=None,
                    help="Probe one provider; omit to probe all.")
    ap.add_argument("--models", nargs="*", default=None, help="Override the model list.")
    ap.add_argument("--api-key", default=None, help="Override the key (else read from context/).")
    args = ap.parse_args()

    providers = [args.provider] if args.provider else list(ENDPOINTS)
    any_ok = False
    for prov in providers:
        base_url, key_path, default_models = ENDPOINTS[prov]
        key = args.api_key or (key_path.read_text(encoding="utf-8").strip() if key_path.exists() else None)
        if not key:
            print(f"[{prov}] no key (expected at {key_path})")
            continue
        os.environ["LLM_CUSTOM_BASE_URL"] = base_url
        os.environ["LLM_CUSTOM_API_KEY"] = key
        models = args.models or default_models
        print(f"[{prov}]")
        for m in models:
            try:
                build_chat_model("custom:" + m, temperature=0).invoke("ok")
                print(f"  {m:26s} OK  (quota available)")
                any_ok = True
            except Exception as e:
                s = str(e)
                tag = "THROTTLED (429)" if "429" in s else f"ERR: {s[:50]}"
                print(f"  {m:26s} {tag}")
    return 0 if any_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
