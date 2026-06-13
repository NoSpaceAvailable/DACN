"""Verify a Mistral library is attached to an agent; attach via API if not.

Uses raw HTTP to the Mistral REST API to avoid mistralai SDK version mismatch
issues (some SDK versions expose `client.beta.agents.retrieve`, others use
different paths).

Safe to run multiple times — idempotent.

Usage:
    python scripts/attach_mistral_library.py `
        --agent-id ag_019ebfe8084d737b913847fe75e7bc77 `
        --library-id 019ebfe6-571f-740e-9bf7-de047ac26765 `
        --api-key $env:MISTRAL_API_KEY `
        --disable-web-search
"""
from __future__ import annotations

import argparse
import json
import os
import sys

try:
    import requests
except ImportError:
    raise SystemExit("pip install requests")


API_BASE = "https://api.mistral.ai"


def _hdr(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def get_agent(api_key: str, agent_id: str) -> dict:
    """Retrieve agent. Tries v1/agents path first (most common)."""
    for path in (f"/v1/agents/{agent_id}", f"/v1/beta/agents/{agent_id}"):
        r = requests.get(f"{API_BASE}{path}", headers=_hdr(api_key))
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            continue
        # Other error — show body for debugging
        print(f"  GET {path} → {r.status_code}: {r.text[:300]}")
    raise SystemExit("Cannot retrieve agent. Both /v1/agents and /v1/beta/agents failed.")


def update_agent(api_key: str, agent_id: str, payload: dict) -> dict:
    """Update agent tools. Tries PATCH then PUT, on both path variants."""
    last_err = ""
    for path in (f"/v1/agents/{agent_id}", f"/v1/beta/agents/{agent_id}"):
        for method in ("patch", "put"):
            r = getattr(requests, method)(
                f"{API_BASE}{path}", headers=_hdr(api_key), json=payload,
            )
            if r.status_code in (200, 201):
                return r.json()
            last_err = f"{method.upper()} {path} → {r.status_code}: {r.text[:300]}"
            print(f"  {last_err}")
    raise SystemExit(f"Cannot update agent. Last error: {last_err}")


def _as_dict(t) -> dict:
    return t if isinstance(t, dict) else dict(t)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--library-id", required=True)
    parser.add_argument("--api-key", default=os.environ.get("MISTRAL_API_KEY"))
    parser.add_argument("--disable-web-search", action="store_true")
    parser.add_argument("--dump", action="store_true",
                        help="Print full agent JSON and exit (debugging)")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Need --api-key or MISTRAL_API_KEY")

    print(f"Retrieving agent {args.agent_id}...")
    agent = get_agent(args.api_key, args.agent_id)

    if args.dump:
        print(json.dumps(agent, indent=2))
        return 0

    current_tools = [_as_dict(t) for t in (agent.get("tools") or [])]
    print(f"\nAgent name: {agent.get('name', '?')}")
    print(f"Model:      {agent.get('model', '?')}")
    print(f"Current tools ({len(current_tools)}):")
    for t in current_tools:
        print(f"  - {t}")

    has_library = any(
        t.get("type") == "document_library" and args.library_id in (t.get("library_ids") or [])
        for t in current_tools
    )
    has_web_search = any(t.get("type") == "web_search" for t in current_tools)
    needs_drop_web = args.disable_web_search and has_web_search

    if has_library and not needs_drop_web:
        print(f"\nLibrary {args.library_id} already attached. Nothing to do.")
        return 0

    new_tools = []
    library_merged = False
    for t in current_tools:
        if t.get("type") == "web_search" and args.disable_web_search:
            print(f"  (dropping web_search)")
            continue
        if t.get("type") == "document_library":
            lib_ids = list(t.get("library_ids") or [])
            if args.library_id not in lib_ids:
                lib_ids.append(args.library_id)
            new_tools.append({"type": "document_library", "library_ids": lib_ids})
            library_merged = True
        else:
            new_tools.append(t)

    if not library_merged:
        new_tools.append({"type": "document_library", "library_ids": [args.library_id]})

    print(f"\nNew tools to set ({len(new_tools)}):")
    for t in new_tools:
        print(f"  - {t}")

    print("\nSubmitting update...")
    updated = update_agent(args.api_key, args.agent_id, {"tools": new_tools})
    print("Update OK.")

    final_tools = [_as_dict(t) for t in (updated.get("tools") or [])]
    print(f"\nFinal tools on agent:")
    for t in final_tools:
        print(f"  - {t}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
