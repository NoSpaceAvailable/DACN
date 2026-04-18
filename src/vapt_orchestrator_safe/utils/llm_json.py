"""Robust JSON extraction from free-form LLM output.

LLMs sometimes wrap their JSON in ```json ... ``` fences, prepend
"Sure! Here is the JSON:", or emit thinking tokens before the actual
payload. This helper finds the first balanced JSON object/array in the
text and returns it parsed, or None if nothing usable is present.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional, Tuple


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_json(text: str) -> Optional[Any]:
    """Return the first parseable JSON value found in ``text``, else None.

    Strategy:
    1. Try the body of any ```json ... ``` markdown fence.
    2. Try the longest ``{...}`` or ``[...]`` substring with balanced braces
       starting from the first opening token.
    3. Try plain json.loads on the trimmed string.
    """
    if not text:
        return None

    # 1) markdown fence
    for match in _FENCE_RE.finditer(text):
        body = match.group(1).strip()
        parsed = _try_load(body)
        if parsed is not None:
            return parsed

    # 2) brace matching
    span = _find_balanced(text, "{", "}")
    if span is not None:
        parsed = _try_load(text[span[0] : span[1] + 1])
        if parsed is not None:
            return parsed
    span = _find_balanced(text, "[", "]")
    if span is not None:
        parsed = _try_load(text[span[0] : span[1] + 1])
        if parsed is not None:
            return parsed

    # 3) raw
    return _try_load(text.strip())


def _try_load(s: str) -> Optional[Any]:
    if not s:
        return None
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return None


def _find_balanced(text: str, open_ch: str, close_ch: str) -> Optional[Tuple[int, int]]:
    """Return (start, end) of the longest balanced span starting with open_ch.

    Tracks string literals and escapes so braces inside strings don't break
    the count. Returns None if no balanced span is found.
    """
    start = text.find(open_ch)
    if start == -1:
        return None
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return (start, i)
    return None
