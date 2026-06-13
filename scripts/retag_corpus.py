"""Re-tag distilled corpus entries that landed in 'Other' into real vuln classes.

The distillation prompt used a fixed vocabulary that lacked classes like
RequestSmuggling, CachePoisoning, CORS, etc., so many entries (notably all the
HTTP request-smuggling knowledge) fell back to 'Other'. That makes
query_kg(attack_family=...) unable to surface them by family.

This pass re-classifies entries by keyword-matching their title/description/tags
against an ordered rule list (first match wins). It is quota-free (no LLM) and
conservative: by default it only re-tags entries currently labelled 'Other'.

Usage:
    python scripts/retag_corpus.py                 # re-tag data/corpus/hacktricks.jsonl in place
    python scripts/retag_corpus.py --all           # consider every entry, not just 'Other'
    python scripts/retag_corpus.py --dry-run       # show what would change, write nothing
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "data" / "corpus" / "hacktricks.jsonl"

# Ordered (regex, class) rules — FIRST match wins, so put specific before generic.
RULES = [
    (r"smuggl|desync|\bcl\.te\b|\bte\.cl\b|\bte\.te\b|\bcl\.0\b|\bte\.0\b|\b0\.cl\b|\bh2\.te\b|\bh2\.cl\b|h2c|downgrade request|connection reuse|connection coalesc|pipelined|request splitting|http/2 .*split", "RequestSmuggling"),
    (r"cache poison|cache deception|response queue", "CachePoisoning"),
    (r"\bcors\b|cross-origin resource sharing", "CORS"),
    (r"clickjack|x-frame-options|frame busting", "Clickjacking"),
    (r"open redirect", "OpenRedirect"),
    (r"crlf|header injection|response splitting|http response splitting", "CRLFInjection"),
    (r"prototype pollution", "PrototypePollution"),
    (r"race condition|toctou|time-of-check", "RaceCondition"),
    (r"\bxxe\b|xml external entit", "XXE"),
    (r"ssti|server-side template|template injection", "SSTI"),
    (r"deserial|insecure deseriali|pickle|gadget chain", "Deserialization"),
    (r"\bssrf\b|server-side request forgery", "SSRF"),
    (r"\bjwt\b|json web token|jws|jwk", "JWT"),
    (r"graphql", "GraphQL"),
    (r"oauth|saml|openid|\bsso\b", "AuthBypass"),
    (r"websocket", "WebSocket"),
    (r"file upload|unrestricted upload|\.htaccess upload", "FileUpload"),
    (r"\bldap\b", "LDAPi"),
    (r"xpath", "XPath"),
    (r"\bnosql|mongo|\$where|\$ne\b", "NoSQLi"),
    (r"\bsql injection|union select|\bsqli\b|boolean-based|error-based|stacked quer", "SQLi"),
    (r"command inj|os command|rce|remote code exec|code injection|code execution", "RCE"),
    (r"local file inclusion|\blfi\b|file disclosure|arbitrary file read|path traversal|directory traversal", "LFI"),
    (r"\bxss\b|cross-site scripting|dom clobber", "XSS"),
    (r"\bcsrf\b|cross-site request forgery", "CSRF"),
    (r"\bidor\b|insecure direct object|broken object level", "IDOR"),
]
COMPILED = [(re.compile(p, re.IGNORECASE), c) for p, c in RULES]


def classify(entry: dict) -> str | None:
    hay = " ".join([
        str(entry.get("title", "")),
        str(entry.get("description", "")),
        " ".join(entry.get("tags", []) or []),
    ])
    for rx, cls in COMPILED:
        if rx.search(hay):
            return cls
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ap.add_argument("--all", action="store_true", help="Consider every entry, not just 'Other'.")
    ap.add_argument("--dry-run", action="store_true", help="Report only; do not write.")
    args = ap.parse_args()

    path = Path(args.corpus)
    entries = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

    before = Counter(e.get("vuln_class", "?") for e in entries)
    changed = 0
    for e in entries:
        cur = e.get("vuln_class", "Other")
        if not args.all and cur != "Other":
            continue
        new = classify(e)
        if new and new != cur:
            e["vuln_class"] = new
            changed += 1

    after = Counter(e.get("vuln_class", "?") for e in entries)
    still_other = after.get("Other", 0)

    print(f"entries: {len(entries)} | re-tagged: {changed} | still 'Other': {still_other}")
    print("\nnew distribution:")
    for k, v in after.most_common():
        delta = v - before.get(k, 0)
        print(f"  {k:18s} {v:4d}  ({'+' if delta >= 0 else ''}{delta})")

    if args.dry_run:
        print("\n(dry-run: nothing written)")
        return 0

    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
