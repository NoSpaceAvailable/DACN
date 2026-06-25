"""WebSearchTool — DuckDuckGo search so the agent can discover knowledge it
does not have in-context.

Why: HackTricks KG covers generic CVE/vuln-class patterns (SQLi, LFI, …),
not framework-quirk logic bugs (WSGI SCRIPT_NAME header trick, nginx
underscores_in_headers, Meteor pub/sub leak, …). The agent needs a way to
pull this knowledge in for any stack — not a hand-curated corpus per
challenge.

Flow:
    web_search(query="nginx underscores_in_headers SCRIPT_NAME bypass")
        → top-N {title, url, snippet}
    fetch_writeup(url=<picked URL>) → full text

No anti-leak filter — evaluating raw harness baseline first. If results show
the agent just googles for writeups, add filters back (see git history of
this file for the previous implementation).
"""
from __future__ import annotations

import json
from typing import Any, ClassVar, List, Type

from pydantic import BaseModel, ConfigDict, Field

from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


class _WebSearchArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    query: str = Field(description="Search query.")
    max_results: int = Field(default=8, ge=1, le=15)


class WebSearchTool(BaseTool):
    name: str = "web_search"
    description: str = (
        "Search the public web (DuckDuckGo) for security/dev knowledge you "
        "don't already have. Returns top results as {title, url, snippet}. "
        "After picking a relevant URL, call fetch_writeup(url=...) to read "
        "the full page. Use this for logic bugs at the seam between "
        "components (proxy + app server + framework) where in-context KG "
        "lookups by vuln class return nothing useful."
    )
    args_schema: Type[BaseModel] = _WebSearchArgs
    truncate_at: ClassVar[int] = 8000

    def _invoke(self, **kwargs: Any) -> ToolResult:
        query = (kwargs.get("query") or "").strip()
        if not query:
            return ToolResult(stderr="query is required.", exit_code=2)
        max_results = int(kwargs.get("max_results", 8))

        try:
            from ddgs import DDGS
        except ImportError:
            return ToolResult(
                stderr="ddgs package not installed (pip install ddgs).",
                exit_code=1,
            )

        try:
            raw = list(DDGS().text(query, max_results=max_results))
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                stderr=f"search failed: {type(exc).__name__}: {exc}",
                exit_code=1,
            )

        results: List[dict] = [
            {
                "title": (r.get("title") or "")[:200],
                "url": r.get("href") or r.get("url") or "",
                "snippet": (r.get("body") or "")[:400],
            }
            for r in raw
        ]
        payload = {"query": query, "count": len(results), "results": results}
        return ToolResult(
            stdout=json.dumps(payload, ensure_ascii=False),
            exit_code=0,
            metadata={"count": len(results)},
        )


def _demo() -> None:
    """ponytail: smallest runnable check — DDG returns results."""
    tool = WebSearchTool()
    res = tool._invoke(query="nginx underscores_in_headers SCRIPT_NAME bypass", max_results=5)
    assert res.exit_code == 0, f"search failed: {res.stderr}"
    payload = json.loads(res.stdout)
    assert payload["count"] >= 1, "expected ≥1 result"
    print(f"OK: {payload['count']} results")


if __name__ == "__main__":
    _demo()
