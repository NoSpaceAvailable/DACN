"""Create a Mistral library + agent via API (when the UI doesn't expose it).

Steps performed:
1. Create a new library
2. Upload all HackTricks .md files in --kb-dir to the library
3. Wait for indexing
4. Create an agent with model + system prompt + document_library tool
   pointing at the library
5. Print the agent_id to use with bench_mistral_agent.py

Usage:
    pip install --upgrade mistralai
    python scripts/setup_mistral_agent.py `
        --api-key $env:MISTRAL_API_KEY `
        --kb-dir C:\\path\\to\\hacktricks-md-files `
        --prompt-file path\\to\\dev_prompt.md `
        --model magistral-medium-latest
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

try:
    from mistralai.client import Mistral
except ImportError:
    raise SystemExit("pip install --upgrade mistralai")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-key", default=os.environ.get("MISTRAL_API_KEY"))
    parser.add_argument("--kb-dir", required=True,
                        help="Directory containing the HackTricks .md files")
    parser.add_argument("--prompt-file", required=True,
                        help="Path to the developer prompt (markdown)")
    parser.add_argument("--model", default="magistral-medium-latest")
    parser.add_argument("--name", default="DACN-pentest")
    parser.add_argument("--library-name", default="Pentest KB")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Need --api-key or MISTRAL_API_KEY")

    client = Mistral(api_key=args.api_key)

    kb_dir = Path(args.kb_dir)
    if not kb_dir.exists():
        raise SystemExit(f"KB dir not found: {kb_dir}")

    prompt = Path(args.prompt_file).read_text(encoding="utf-8")
    md_files = sorted(kb_dir.rglob("*.md"))
    print(f"Found {len(md_files)} markdown files in {kb_dir}")
    if not md_files:
        raise SystemExit("No .md files to upload")

    # ── Create library ─────────────────────────────────────────────────
    print(f"\nCreating library '{args.library_name}'...")
    library = client.beta.libraries.create(name=args.library_name)
    lib_id = library.id
    print(f"  library_id = {lib_id}")

    # ── Upload files ──────────────────────────────────────────────────
    print(f"\nUploading {len(md_files)} files...")
    for i, f in enumerate(md_files, 1):
        with open(f, "rb") as fh:
            client.beta.libraries.documents.upload(
                library_id=lib_id,
                file={"file_name": f.name, "content": fh.read()},
            )
        if i % 10 == 0:
            print(f"  uploaded {i}/{len(md_files)}")
    print(f"  uploaded {len(md_files)}/{len(md_files)}")

    # ── Wait for indexing ─────────────────────────────────────────────
    print("\nWaiting for indexing...")
    for attempt in range(60):
        time.sleep(5)
        docs = client.beta.libraries.documents.list(library_id=lib_id)
        statuses = [getattr(d, "processing_status", "?") for d in docs.data]
        ready = sum(1 for s in statuses if str(s).lower() in ("completed", "ready", "processed"))
        print(f"  {ready}/{len(statuses)} indexed", end="\r")
        if ready == len(statuses) and len(statuses) > 0:
            print(f"\n  All {ready} documents indexed.")
            break
    else:
        print(f"\n  Timed out waiting for indexing; continuing anyway.")

    # ── Create agent ──────────────────────────────────────────────────
    print(f"\nCreating agent '{args.name}'...")
    agent = client.beta.agents.create(
        model=args.model,
        name=args.name,
        instructions=prompt,
        tools=[{"type": "document_library", "library_ids": [lib_id]}],
        completion_args={
            "temperature": 0.2,
            "top_p": 0.95,
        },
    )
    agent_id = agent.id
    print(f"  agent_id   = {agent_id}")
    print(f"  library_id = {lib_id}")

    print(f"\n{'='*60}")
    print(f"Setup complete. Run benchmark with:")
    print(f"  python scripts/bench_mistral_agent.py --agent-id {agent_id} "
          f"--api-key $env:MISTRAL_API_KEY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
