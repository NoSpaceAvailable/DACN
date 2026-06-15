"""Manage a Mistral agent's tools — attach libraries, drop built-in tools.

Uses raw HTTP to the Mistral REST API to avoid mistralai SDK version mismatch
issues (some SDK versions expose `client.beta.agents.retrieve`, others use
different paths).

Safe to run multiple times — idempotent.

Usage examples::

    # Attach a document library (idempotent; merges into existing list)
    python scripts/attach_mistral_library.py `
        --agent-id ag_019ebfe8084d737b913847fe75e7bc77 `
        --library-id 019ebfe6-571f-740e-9bf7-de047ac26765 `
        --api-key $env:MISTRAL_API_KEY `
        --disable-web-search

    # Drop ALL built-in tools (document_library, web_search, code_interpreter,
    # image_generation, ...) so the agent only uses custom function tools you
    # pass at runtime. Use this before bench_mistral_agent_local_tools.py to
    # compare local-only KG vs. Mistral hosted RAG cleanly.
    python scripts/attach_mistral_library.py `
        --agent-id ag_019ebfe8084d737b913847fe75e7bc77 `
        --api-key $env:MISTRAL_API_KEY `
        --drop-builtin

    # Drop just one specific library_id without touching other tools
    python scripts/attach_mistral_library.py `
        --agent-id ag_... --api-key $env:MISTRAL_API_KEY `
        --drop-library 019ebfe6-571f-740e-9bf7-de047ac26765
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


# Mistral's "built-in" hosted tool types — i.e. anything that runs server-side
# on Mistral infra (RAG, web, code, image). Custom ``function`` tools defined
# on the agent are NOT in this set and are preserved across --drop-builtin.
_BUILTIN_TYPES = {
    "document_library",
    "web_search",
    "web_search_premium",
    "code_interpreter",
    "image_generation",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--library-id", default=None,
                        help="Library to attach (idempotent merge). Required unless "
                             "--drop-builtin / --drop-library / --dump is used.")
    parser.add_argument("--api-key", default=os.environ.get("MISTRAL_API_KEY"))
    parser.add_argument("--disable-web-search", action="store_true",
                        help="Drop only the web_search tool, keep everything else.")
    parser.add_argument("--drop-builtin", action="store_true",
                        help=f"Drop ALL Mistral built-in tools ({', '.join(sorted(_BUILTIN_TYPES))}). "
                             f"Custom function tools on the agent are preserved.")
    parser.add_argument("--drop-library", default=None,
                        help="Drop one specific library_id from the document_library tool "
                             "without touching anything else. If the resulting list is "
                             "empty, the document_library tool is removed entirely.")
    parser.add_argument("--dump", action="store_true",
                        help="Print full agent JSON and exit (debugging)")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Need --api-key or MISTRAL_API_KEY")

    actions = (
        bool(args.library_id)
        + bool(args.drop_builtin)
        + bool(args.drop_library)
    )
    if not args.dump and not args.disable_web_search and actions == 0:
        raise SystemExit(
            "Nothing to do. Pass one of: --library-id, --drop-builtin, "
            "--drop-library, --dump, --disable-web-search."
        )

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

    # ── Branch: drop ALL built-in hosted tools ──────────────────────────────
    if args.drop_builtin:
        new_tools = [t for t in current_tools if t.get("type") not in _BUILTIN_TYPES]
        dropped = [t.get("type", "?") for t in current_tools if t.get("type") in _BUILTIN_TYPES]
        if not dropped:
            print("\nNo built-in tools present. Nothing to do.")
            return 0
        print(f"\nDropping built-in tool(s): {dropped}")
        if not new_tools:
            print("(no remaining tools — agent will rely entirely on runtime "
                  "function tools passed in the conversation request)")
        return _submit(args.api_key, args.agent_id, new_tools)

    # ── Branch: drop ONE specific library_id ────────────────────────────────
    if args.drop_library:
        new_tools: list = []
        removed = False
        for t in current_tools:
            if t.get("type") != "document_library":
                new_tools.append(t)
                continue
            lib_ids = [lid for lid in (t.get("library_ids") or []) if lid != args.drop_library]
            if len(lib_ids) == len(t.get("library_ids") or []):
                new_tools.append(t)  # this tool didn't contain the target id
                continue
            removed = True
            if lib_ids:
                new_tools.append({"type": "document_library", "library_ids": lib_ids})
            else:
                print(f"  (document_library now empty → removing the tool entirely)")
        if not removed:
            print(f"\nLibrary {args.drop_library} was not attached. Nothing to do.")
            return 0
        return _submit(args.api_key, args.agent_id, new_tools)

    # ── Branch: attach a library (legacy default behavior) ──────────────────
    if not args.library_id:
        # Only got --disable-web-search; treat as a standalone drop request.
        has_web = any(t.get("type") == "web_search" for t in current_tools)
        if not has_web:
            print("\nNo web_search tool present. Nothing to do.")
            return 0
        new_tools = [t for t in current_tools if t.get("type") != "web_search"]
        print("\nDropping web_search.")
        return _submit(args.api_key, args.agent_id, new_tools)

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

    return _submit(args.api_key, args.agent_id, new_tools)


def _submit(api_key: str, agent_id: str, new_tools: list) -> int:
    print(f"\nNew tools to set ({len(new_tools)}):")
    for t in new_tools:
        print(f"  - {t}")

    print("\nSubmitting update...")
    updated = update_agent(api_key, agent_id, {"tools": new_tools})
    print("Update OK.")

    final_tools = [_as_dict(t) for t in (updated.get("tools") or [])]
    print(f"\nFinal tools on agent:")
    for t in final_tools:
        print(f"  - {t}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
