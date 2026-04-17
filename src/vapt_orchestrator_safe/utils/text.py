from __future__ import annotations

import re
from typing import Iterable, List, Set


TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")


def tokenize(text: str) -> List[str]:
    return [t.lower() for t in TOKEN_RE.findall(text)]


def keyword_overlap_score(query_terms: Iterable[str], doc_text: str) -> float:
    q = set(t.lower() for t in query_terms if t)
    d: Set[str] = set(tokenize(doc_text))
    if not q:
        return 0.0
    return len(q & d) / max(len(q), 1)


def compact(text: str, limit: int = 220) -> str:
    normalized = re.sub(r"\s+", " ", text).strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."
