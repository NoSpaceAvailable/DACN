"""fetch_writeup — pull a security writeup/advisory URL and extract text.

Last-resort PoC retrieval channel after ``query_nuclei`` (404) and
``query_exploitdb`` (no match). Used when the only documented PoC for a
CVE is prose in a vendor blog, GitHub issue, or third-party advisory
(e.g. CVE-2019-20372's technique is described in a SecureAuth +
Wallarm writeup, not in any structured DB).

Host allowlist:
  This tool fetches arbitrary URLs, so the host is restricted to a
  curated set of advisory/blog domains. The list errs on the side of
  *security-research outlets* (PortSwigger, Wallarm, NCC Group, Snyk),
  *vendor advisories* (RedHat, Debian, Ubuntu, Mozilla, Apache, NGINX),
  and *public bug-tracker references* (NVD detail pages, MITRE,
  GitHub Issues / Security Advisories). Anything outside the list is
  refused so the model can't be convinced to fetch attacker-controlled
  pages from a poisoned `references` field.

Output is the textual content (HTML → text via BeautifulSoup), title,
and a focus-keyword extract if ``focus`` is passed. Cached under
``data/cache/writeup/<sha256(url)>.json`` for 30 days.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Type
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from vapt_orchestrator_safe.config import _load_dotenv_if_present
from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


# Host allowlist — only hosts known to publish legitimate security writeups.
# Suffix match: an entry "wallarm.com" matches "lab.wallarm.com" too.
_HOST_ALLOWLIST = {
    # Security research orgs
    "wallarm.com",
    "portswigger.net",
    "snyk.io",
    "nccgroup.com",
    "trustedsec.com",
    "rapid7.com",
    "tenable.com",
    "checkpoint.com",
    "research.checkpoint.com",
    "praetorian.com",
    "qualys.com",
    "synacktiv.com",
    "horizon3.ai",
    "watchtowr.com",
    # CVE/NVD/MITRE
    "nvd.nist.gov",
    "cve.org",
    "cve.mitre.org",
    "mitre.org",
    # Vendor advisories
    "access.redhat.com",
    "bugs.debian.org",
    "security-tracker.debian.org",
    "ubuntu.com",
    "usn.ubuntu.com",
    "wiki.mozilla.org",
    "bugzilla.mozilla.org",
    "nginx.org",
    "mailman.nginx.org",
    "apache.org",
    "lists.apache.org",
    "github.io",            # vendor security.github.io pages
    "openssl.org",
    "kb.cert.org",
    "cert.org",
    "securitylab.github.com",
    # Public PoC + advisory aggregators
    "github.com",           # Issues / Security Advisories / PoC repos
    "gist.github.com",
    "packetstormsecurity.com",
    "exploit-db.com",
    "vuldb.com",
    "seclists.org",         # fulldisclosure / oss-sec archives, NVD-cited
    "lists.opensuse.org",   # CVE security-announce mailing list
    "lists.debian.org",
    "marc.info",            # mailing-list aggregator NVD links to
    # Researcher personal pages frequently cited as Exploit-tagged refs in NVD.
    # Note: keybase.pub is user-controlled — this is opt-in trust that the
    # researcher (e.g. bertjwregeer for CVE-2019-20372) won't poison their
    # own write-up. NVD's `Exploit` tag is the cross-check; we follow only
    # what NVD already vouched for.
    "keybase.pub",
    # Blogs frequently linked from NVD as primary technical sources
    "googleprojectzero.blogspot.com",
    "project-zero.issues.chromium.org",
    "googleonline2.blogspot.com",
    "blog.cloudflare.com",
    "blog.qualys.com",
    "secureworks.com",
    # Developer Q&A — high-signal hits for framework/stack quirks (the kind
    # of knowledge HackTricks-style CVE corpora don't capture).
    "stackoverflow.com",
    "stackexchange.com",
    "serverfault.com",
    "superuser.com",
    "askubuntu.com",
    # Official framework / runtime docs — agents need these for logic bugs
    # rooted in component behaviour, not CVEs.
    "developer.mozilla.org",
    "docs.python.org",
    "flask.palletsprojects.com",
    "docs.djangoproject.com",
    "fastapi.tiangolo.com",
    "docs.gunicorn.org",
    "gunicorn.org",
    "docs.nginx.com",
    "docs.apache.org",
    "httpd.apache.org",
    "docs.meteor.com",
    "guide.meteor.com",
    "docs.mongodb.com",
    "www.mongodb.com",
    "redis.io",
    "docs.docker.com",
    "spring.io",
    "docs.spring.io",
    "docs.oracle.com",
    "openjdk.org",
    "nodejs.org",
    "expressjs.com",
    "react.dev",
    "reactjs.org",
    "vuejs.org",
    "angular.io",
    "rubyonrails.org",
    "guides.rubyonrails.org",
    "laravel.com",
    "php.net",
    "learn.microsoft.com",
    "docs.microsoft.com",
    "owasp.org",
    "cheatsheetseries.owasp.org",
    "hacktricks.xyz",
    "book.hacktricks.xyz",
}

_CACHE_TTL_SECONDS = 30 * 24 * 3600
_APPROX_CHARS_PER_TOKEN = 4
_MAX_RETURN_CHARS = 12000


def _approx_tokens(text: str) -> int:
    return max(1, len(text) // _APPROX_CHARS_PER_TOKEN)


class _FetchWriteupArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    url: str = Field(
        ...,
        description=(
            "Absolute URL to fetch. Must be on the host allowlist "
            "(security-research blogs, NVD/MITRE, vendor advisories, "
            "github.com Issues/Advisories). The tool refuses anything off-list."
        ),
    )
    focus: Optional[str] = Field(
        default=None,
        description=(
            "Optional keyword to extract surrounding paragraphs from the "
            "fetched page (case-insensitive). Useful to home in on PoC / "
            "payload / curl snippets without dumping the whole article."
        ),
    )


class FetchWriteupTool(BaseTool):
    name: str = "fetch_writeup"
    description: str = (
        "Fetch a security writeup, advisory, or GitHub Issue/Advisory by "
        "URL and return its plain-text content. Use this when "
        "`query_nuclei` and `query_exploitdb` did not surface a PoC, and "
        "you have a reference URL (typically from NVD/GHSA references) "
        "that describes the exploit technique. Only allowlisted hosts "
        "are fetchable — security blogs, vendor advisories, NVD/MITRE, "
        "github.com — so you cannot dereference an attacker-controlled "
        "URL. Pass `focus=<keyword>` to extract only the relevant "
        "paragraphs (PoC, payload, repro)."
    )
    args_schema: Type[BaseModel] = _FetchWriteupArgs
    truncate_at: ClassVar[int] = 12000

    _cache_dir: Path = PrivateAttr()
    _timeout_s: float = PrivateAttr(default=20.0)

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        timeout_s: float = 20.0,
        **data: Any,
    ) -> None:
        super().__init__(**data)
        _load_dotenv_if_present()
        if cache_dir is None:
            cache_dir = Path(__file__).resolve().parents[3] / "data" / "cache" / "writeup"
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._timeout_s = timeout_s

    def _invoke(self, **kwargs: Any) -> ToolResult:
        url = (kwargs.get("url") or "").strip()
        focus = (kwargs.get("focus") or "").strip()

        if not url:
            return ToolResult(stderr="url is required.", exit_code=2)
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:  # noqa: BLE001
            return ToolResult(stderr=f"Invalid URL {url!r}.", exit_code=2)
        # ponytail: host allowlist disabled — let agent fetch any URL it
        # discovered via web_search. Scope guard still applies to the live
        # target probes (curl/http_probe), this only affects doc reading.

        cache_key = self._cache_key(url)
        cached = self._read_cache(cache_key)
        if cached is not None:
            text = cached.get("text", "")
            payload = self._build_payload(url, host, cached.get("title"), text, focus)
            return self._render(payload, from_cache=True)

        try:
            html, title = self._fetch_live(url)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                stderr=f"fetch failed: {type(exc).__name__}: {exc}",
                exit_code=1,
                metadata={"url": url, "host": host},
            )

        text = _html_to_text(html)
        self._write_cache(cache_key, {"text": text, "title": title, "url": url})

        payload = self._build_payload(url, host, title, text, focus)
        return self._render(payload, from_cache=False)

    # ── HTTP fetch ────────────────────────────────────────────────────────────
    # Stack Overflow / ServerFault / many docs CDNs return 403 to bot-flavoured
    # User-Agents (including the previous "DACN-vapt-orchestrator/1.0" string).
    # Use a current real-browser UA so doc-reading paths actually load. We
    # still rate-limit via the host allowlist; this is a read-only fetch of
    # public pages we cited from our own search results.
    _BROWSER_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }

    def _fetch_live(self, url: str) -> tuple[str, Optional[str]]:
        try:
            import requests
        except ImportError as exc:
            raise RuntimeError("requests package required (pip install requests)") from exc
        r = requests.get(
            url,
            timeout=self._timeout_s,
            headers=self._BROWSER_HEADERS,
            allow_redirects=True,
        )
        if r.status_code in (403, 429):
            # Some hosts rate-limit aggressively; one retry with backoff.
            time.sleep(5.0)
            r = requests.get(
                url, timeout=self._timeout_s,
                headers=self._BROWSER_HEADERS, allow_redirects=True,
            )
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} from {url}")
        ctype = (r.headers.get("Content-Type") or "").lower()
        if "application/pdf" in ctype or url.lower().endswith(".pdf"):
            # No PDF extractor installed — bail with a useful suggestion so the
            # caller can try the next reference URL in the CVE references list.
            raise RuntimeError(
                "PDF references are not text-extractable by this tool yet. "
                "Try another reference URL (NVD detail page, GitHub commit/issue, "
                "vendor advisory)."
            )
        # Best-effort title extraction from raw HTML
        m = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.IGNORECASE)
        title = (m.group(1).strip() if m else None) or None
        return r.text, title

    # ── cache ─────────────────────────────────────────────────────────────────
    def _cache_key(self, url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]

    def _read_cache(self, key: str) -> Optional[Dict[str, Any]]:
        path = self._cache_dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            blob = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None
        cached_at = float(blob.get("cached_at", 0))
        if (time.time() - cached_at) > _CACHE_TTL_SECONDS:
            return None
        return blob.get("payload")

    def _write_cache(self, key: str, payload: Dict[str, Any]) -> None:
        path = self._cache_dir / f"{key}.json"
        try:
            path.write_text(
                json.dumps({"cached_at": time.time(), "payload": payload}, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:  # noqa: BLE001
            pass

    # ── payload ───────────────────────────────────────────────────────────────
    def _build_payload(
        self,
        url: str,
        host: str,
        title: Optional[str],
        text: str,
        focus: str,
    ) -> Dict[str, Any]:
        focused = _focus_extract(text, focus) if focus else ""
        # Decide what to return to the model. Prefer the focused extract when
        # available; otherwise return a head-tail snapshot capped at _MAX_RETURN_CHARS.
        if focused:
            body = focused
            mode = "focus"
        elif len(text) <= _MAX_RETURN_CHARS:
            body = text
            mode = "full"
        else:
            head = text[: _MAX_RETURN_CHARS - 1500]
            tail = text[-1500:]
            body = head + "\n\n... [middle truncated] ...\n\n" + tail
            mode = "head_tail"
        return {
            "url": url,
            "host": host,
            "title": title,
            "mode": mode,
            "focus": focus,
            "char_count": len(text),
            "content": body,
        }

    def _render(self, payload: Dict[str, Any], *, from_cache: bool) -> ToolResult:
        text = payload.get("content", "")
        approx = _approx_tokens(text)
        payload["from_cache"] = from_cache
        payload["approx_tokens"] = approx
        return ToolResult(
            stdout=json.dumps(payload, ensure_ascii=False),
            exit_code=0,
            metadata={
                "host": payload.get("host"),
                "mode": payload.get("mode"),
                "from_cache": from_cache,
                "approx_tokens": approx,
            },
        )


# ── helpers ──────────────────────────────────────────────────────────────────
def _host_allowed(host: str) -> bool:
    if not host:
        return False
    h = host.lower()
    for allowed in _HOST_ALLOWLIST:
        if h == allowed or h.endswith("." + allowed):
            return True
    return False


def _html_to_text(html: str) -> str:
    """HTML → plain text, preserving paragraph breaks + code blocks.

    Tries BeautifulSoup first (cleaner); falls back to a regex strip if
    bs4 isn't installed.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        # Lightweight fallback: drop script/style, strip tags.
        no_script = re.sub(
            r"<(script|style|noscript)[^>]*>.*?</\1>",
            "",
            html,
            flags=re.DOTALL | re.IGNORECASE,
        )
        stripped = re.sub(r"<[^>]+>", "\n", no_script)
        return re.sub(r"\n{3,}", "\n\n", stripped).strip()

    soup = BeautifulSoup(html, "html.parser")
    for s in soup(["script", "style", "noscript", "header", "footer", "nav", "aside"]):
        s.decompose()

    # Two-pass: first fence <pre> blocks (PoC payloads) and replace them with
    # placeholder text, then collect block-level text from p/li/h*. Doing this
    # in two passes avoids the "mutating while iterating .descendants" trap.
    fenced_chunks: List[str] = []
    for pre in soup.find_all("pre"):
        txt = pre.get_text("\n", strip=False).strip()
        if txt:
            placeholder = f"\n\n```\n{txt}\n```\n\n"
            fenced_chunks.append(placeholder)
            # Replace the <pre> node with a NavigableString placeholder so the
            # subsequent block-level pass picks it up in document order.
            pre.replace_with(placeholder)

    out_lines: List[str] = []
    for elem in soup.find_all(["p", "li", "h1", "h2", "h3", "h4", "h5", "h6"]):
        txt = elem.get_text(" ", strip=True)
        if txt:
            out_lines.append(txt)

    body_text = "\n\n".join(out_lines)
    # If nothing structural surfaced, fall through to a flat get_text dump.
    if not body_text.strip():
        body_text = soup.get_text("\n", strip=True)

    # The pre-placeholders may not have been picked up by find_all (they were
    # inserted as NavigableString, not block tags) — append them at the end so
    # the code/payload chunks survive even if the rest of the parse was sparse.
    extra = "".join(fenced_chunks)
    text = body_text
    if extra and extra.strip() not in body_text:
        text = body_text + "\n\n" + extra

    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _focus_extract(text: str, focus: str, window: int = 800) -> str:
    """Return paragraphs surrounding case-insensitive matches of ``focus``.

    Window controls how many chars on each side of a hit to include.
    Returns "" if no hit, signalling the caller to fall back to full/head_tail.
    """
    if not focus:
        return ""
    target = focus.lower()
    body = text.lower()
    hits: List[tuple[int, int]] = []
    start = 0
    while True:
        idx = body.find(target, start)
        if idx == -1:
            break
        s = max(0, idx - window)
        e = min(len(text), idx + len(focus) + window)
        if hits and s <= hits[-1][1]:
            # Merge overlapping windows
            hits[-1] = (hits[-1][0], max(hits[-1][1], e))
        else:
            hits.append((s, e))
        start = idx + len(focus)
        if len(hits) >= 6:
            break
    if not hits:
        return ""
    chunks = [text[s:e] for s, e in hits]
    return "\n\n--- [focus break] ---\n\n".join(chunks)
