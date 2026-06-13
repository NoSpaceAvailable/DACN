"""Update a Mistral Agent's completion_args (max_tokens, temperature, top_p).

Why this exists: Mistral's /v1/conversations endpoint REJECTS `completion_args`
when invoked with an `agent_id` (HTTP 422: "Conversation with an 'agent' can't
contain the following fields completion_args"). To change generation parameters
you must update the AGENT itself (creates a new agent version) and then the
bench script will inherit the new defaults on every call.

Usage:
    # Bump max_tokens so reasoning + JSON output fits
    python scripts/update_mistral_agent.py `
        --agent-id ag_019ebfe8084d737b913847fe75e7bc77 `
        --api-key $env:MISTRAL_API_KEY `
        --max-tokens 16384

    # Tweak temperature too
    python scripts/update_mistral_agent.py `
        --agent-id ag_... --api-key $env:MISTRAL_API_KEY `
        --max-tokens 16384 --temperature 0.3

The script GETs the current agent, merges your overrides into completion_args,
then PATCHes back. Idempotent.
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
    for path in (f"/v1/agents/{agent_id}", f"/v1/beta/agents/{agent_id}"):
        r = requests.get(f"{API_BASE}{path}", headers=_hdr(api_key))
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            continue
        print(f"  GET {path} → {r.status_code}: {r.text[:300]}")
    raise SystemExit("Cannot retrieve agent.")


def patch_agent(api_key: str, agent_id: str, payload: dict) -> dict:
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--api-key", default=os.environ.get("MISTRAL_API_KEY"))
    parser.add_argument("--max-tokens", type=int, default=None,
                        help="Set completion_args.max_tokens")
    parser.add_argument("--temperature", type=float, default=None)
    parser.add_argument("--top-p", type=float, default=None)
    parser.add_argument("--dump", action="store_true",
                        help="Print current agent JSON and exit (no update).")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Need --api-key or MISTRAL_API_KEY")

    print(f"Retrieving agent {args.agent_id}...")
    agent = get_agent(args.api_key, args.agent_id)
    current_ca = agent.get("completion_args") or {}
    print(f"\nAgent name: {agent.get('name', '?')}")
    print(f"Model:      {agent.get('model', '?')}")
    print(f"Current completion_args: {current_ca}")

    if args.dump:
        print("\n--- Full agent JSON ---")
        print(json.dumps(agent, indent=2))
        return 0

    if args.max_tokens is None and args.temperature is None and args.top_p is None:
        print("\nNothing to update. Pass --max-tokens / --temperature / --top-p.")
        return 1

    new_ca = dict(current_ca)
    if args.max_tokens is not None:
        new_ca["max_tokens"] = args.max_tokens
    if args.temperature is not None:
        new_ca["temperature"] = args.temperature
    if args.top_p is not None:
        new_ca["top_p"] = args.top_p

    print(f"\nNew completion_args: {new_ca}")
    print("\nSubmitting PATCH...")
    updated = patch_agent(args.api_key, args.agent_id, {"completion_args": new_ca})
    print("Update OK.")
    final_ca = updated.get("completion_args") or {}
    print(f"\nFinal completion_args on agent: {final_ca}")
    new_version = updated.get("version")
    if new_version:
        print(f"New agent version: {new_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
