"""query_ghsa — online GitHub Advisory Database lookup with disk cache.

Complements :class:`vapt_orchestrator_safe.tools.cve_tool.QueryCveTool`:

  - NVD is the source-of-truth for system/server software (nginx, apache,
    log4j-the-binary) and has rigorous CPE version-range data.
  - GHSA is purpose-built for **package-ecosystem vulns** (npm, PyPI,
    Maven, RubyGems, Go modules, etc.) and typically has cleaner
    `first_patched_version` + `vulnerable_version_range` strings than the
    NVD CPE rows for those ecosystems. It also surfaces GitHub-only IDs
    (GHSA-...) for vulns that may not yet have an NVD CVE assigned.

Three query modes:

  - ``ghsa_id="GHSA-2hj5-g63q-w7vw"``           — direct lookup
  - ``cve_id="CVE-2021-44228"``                  — cross-reference into GHSA
  - ``package="express", ecosystem="npm",
       version="4.17.0"``                        — ecosystem-aware lookup
    (the ``version`` arrow narrows to advisories whose
    ``vulnerable_version_range`` matches that version on GitHub's side)

Auth: pass ``GITHUB_TOKEN`` env var (any fine-grained PAT, no scopes
required for public-advisory reads) to get 5000 req/hr. Without a token
the public limit is 60 req/hr, which will rate-limit a full bench run.

Cache: every request lands in ``data/cache/ghsa/<sha256>.json`` with a
30-day TTL — same pattern as the NVD tool.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from vapt_orchestrator_safe.config import _load_dotenv_if_present
from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


_GHSA_BASE = "https://api.github.com/advisories"
_CACHE_TTL_SECONDS = 30 * 24 * 3600
_APPROX_CHARS_PER_TOKEN = 4

# GHSA-supported ecosystems (per /advisories docs); used for early validation
# rather than letting the API reject typos.
_VALID_ECOSYSTEMS = {
    "actions", "composer", "erlang", "go", "maven", "npm", "nuget",
    "other", "pip", "pub", "rubygems", "rust", "swift",
}

_RATE_LOCK = threading.Lock()
_LAST_REQUEST_AT: List[float] = [0.0]


def _approx_tokens(text: str) -> int:
    return max(1, len(text) // _APPROX_CHARS_PER_TOKEN)


# ── args schema ──────────────────────────────────────────────────────────────
class _QueryGhsaArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    ghsa_id: Optional[str] = Field(
        default=None,
        description="Direct lookup, e.g. 'GHSA-jfh8-c2jp-5v3q' (Log4Shell).",
    )
    cve_id: Optional[str] = Field(
        default=None,
        description="Cross-lookup a CVE into the GitHub Advisory DB, e.g. 'CVE-2021-44228'. "
                    "Useful when NVD only gave you the id; GHSA usually has cleaner "
                    "package-level remediation guidance.",
    )
    package: Optional[str] = Field(
        default=None,
        description="Package name within an ecosystem, e.g. 'express', 'log4j-core', 'django'.",
    )
    ecosystem: Optional[str] = Field(
        default=None,
        description=f"Ecosystem the package lives in. One of: {sorted(_VALID_ECOSYSTEMS)}. "
                    f"Pair with 'package' for an ecosystem-aware lookup.",
    )
    version: Optional[str] = Field(
        default=None,
        description="Optional pinned version. GHSA narrows to advisories whose "
                    "vulnerable_version_range matches this version.",
    )
    severity: Optional[str] = Field(
        default=None,
        description="Optional severity filter: critical | high | medium | low.",
    )
    limit: int = Field(default=5, description="Max advisories to return (1-20).")


# ── tool ─────────────────────────────────────────────────────────────────────
class QueryGhsaTool(BaseTool):
    name: str = "query_ghsa"
    description: str = (
        "Look up GitHub Security Advisories. Best for package-ecosystem vulns "
        "(npm, pip/PyPI, maven, rubygems, go, rust, composer, nuget, ...) — "
        "use this when the source/transcript pins a package+version like "
        "`\"express\": \"4.17.0\"` in package.json or `log4j-core 2.14.0` in "
        "pom.xml. Returns GHSA id, summary, severity, the vulnerable version "
        "range, and the first patched version. For nginx/apache and other "
        "non-package system software, prefer `query_cve` (NVD) instead."
    )
    args_schema: Type[BaseModel] = _QueryGhsaArgs
    truncate_at: ClassVar[int] = 6000

    _token: Optional[str] = PrivateAttr(default=None)
    _cache_dir: Path = PrivateAttr()
    _timeout_s: float = PrivateAttr(default=15.0)
    _has_token: bool = PrivateAttr(default=False)

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        github_token: Optional[str] = None,
        timeout_s: float = 15.0,
        **data: Any,
    ) -> None:
        super().__init__(**data)
        # Idempotent .env loader — see QueryCveTool for the rationale.
        _load_dotenv_if_present()
        if cache_dir is None:
            cache_dir = Path(__file__).resolve().parents[3] / "data" / "cache" / "ghsa"
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._token = github_token or os.environ.get("GITHUB_TOKEN")
        self._has_token = bool(self._token)
        self._timeout_s = timeout_s

    # ── core dispatch ────────────────────────────────────────────────────────
    def _invoke(self, **kwargs: Any) -> ToolResult:
        limit = max(1, min(20, int(kwargs.get("limit", 5))))

        ghsa_id = (kwargs.get("ghsa_id") or "").strip()
        cve_id = (kwargs.get("cve_id") or "").strip()
        package = (kwargs.get("package") or "").strip()
        ecosystem = (kwargs.get("ecosystem") or "").strip().lower()
        version = (kwargs.get("version") or "").strip()
        severity = (kwargs.get("severity") or "").strip().lower()

        if ecosystem and ecosystem not in _VALID_ECOSYSTEMS:
            return ToolResult(
                stderr=f"Unknown ecosystem {ecosystem!r}. Valid: {sorted(_VALID_ECOSYSTEMS)}.",
                exit_code=2,
            )

        # Direct id lookups: GHSA REST returns a single advisory object, not a list.
        if ghsa_id:
            url = f"{_GHSA_BASE}/{ghsa_id}"
            params: Dict[str, str] = {}
            mode = "ghsa_id"
            is_list = False
        else:
            url = _GHSA_BASE
            params = {"per_page": str(limit)}
            is_list = True
            if cve_id:
                params["cve_id"] = cve_id
                mode = "cve_id"
            elif package:
                affects = f"{package}@{version}" if version else package
                params["affects"] = affects
                if ecosystem:
                    params["ecosystem"] = ecosystem
                mode = "package"
            else:
                return ToolResult(
                    stderr="Pass at least one of: ghsa_id, cve_id, package (+ecosystem/version).",
                    exit_code=2,
                )
            if severity:
                params["severity"] = severity

        try:
            raw = self._fetch(url, params)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                stderr=f"GHSA lookup failed ({mode}): {type(exc).__name__}: {exc}",
                exit_code=1,
                metadata={"mode": mode, "params": params},
            )

        if is_list:
            advisories = raw if isinstance(raw, list) else []
        else:
            advisories = [raw] if isinstance(raw, dict) else []

        rows = [self._summarise(a) for a in advisories[:limit]]
        payload_text = self._render_text(rows)
        token_estimate = _approx_tokens(payload_text)
        payload = {
            "mode": mode,
            "query": params,
            "count": len(rows),
            "advisories": rows,
            "text": payload_text,
            "approx_tokens": token_estimate,
        }
        return ToolResult(
            stdout=json.dumps(payload, ensure_ascii=False),
            exit_code=0,
            metadata={
                "approx_tokens": token_estimate,
                "count": len(rows),
                "mode": mode,
                "params": params,
            },
        )

    # ── HTTP + cache ─────────────────────────────────────────────────────────
    def _fetch(self, url: str, params: Dict[str, str]) -> Any:
        cache_key = self._cache_key(url, params)
        cached = self._read_cache(cache_key)
        if cached is not None:
            return cached
        body = self._fetch_live(url, params)
        self._write_cache(cache_key, body)
        return body

    def _cache_key(self, url: str, params: Dict[str, str]) -> str:
        canon = json.dumps({"url": url, "params": params}, sort_keys=True)
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:32]

    def _read_cache(self, key: str) -> Any:
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
        return blob.get("response")

    def _write_cache(self, key: str, response: Any) -> None:
        path = self._cache_dir / f"{key}.json"
        try:
            path.write_text(
                json.dumps({"cached_at": time.time(), "response": response},
                           ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:  # noqa: BLE001
            pass

    def _fetch_live(self, url: str, params: Dict[str, str]) -> Any:
        try:
            import requests
        except ImportError as exc:
            raise RuntimeError("requests package required (pip install requests)") from exc

        self._respect_rate_limit()

        headers = {
            "User-Agent": "DACN-vapt-orchestrator/1.0",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        r = requests.get(url, params=params, headers=headers, timeout=self._timeout_s)
        if r.status_code in (403, 429):
            # GitHub returns 403 with X-RateLimit-Remaining: 0 when secondary
            # limit hits. Back off a bit and try once more.
            time.sleep(15.0)
            self._respect_rate_limit(force=True)
            r = requests.get(url, params=params, headers=headers, timeout=self._timeout_s)
        elif 500 <= r.status_code < 600:
            # GitHub edge is flaky; one quick retry usually clears 502/504/503.
            time.sleep(3.0)
            r = requests.get(url, params=params, headers=headers, timeout=self._timeout_s)
        if r.status_code == 404:
            # Direct id lookups hitting a non-existent advisory: return an
            # empty list-shape so callers see count=0 instead of crashing.
            return []
        if r.status_code != 200:
            raise RuntimeError(f"GHSA HTTP {r.status_code}: {r.text[:200]}")
        return r.json()

    def _respect_rate_limit(self, force: bool = False) -> None:
        """Sleep so we don't burst past GitHub's secondary limit.

        Authenticated: 5000/hr = 1.4 req/s, but 900 points/min secondary
        cap = 15 req/s. We pace at 1 req/s to leave headroom for other code.
        Unauthenticated: 60/hr = 1 req/min — slow but acceptable for cache-
        miss only.
        """
        interval = 1.0 if self._has_token else 60.0
        with _RATE_LOCK:
            now = time.monotonic()
            wait = (_LAST_REQUEST_AT[0] + interval) - now
            if wait > 0:
                time.sleep(wait)
            _LAST_REQUEST_AT[0] = time.monotonic()

    # ── response normalisation ───────────────────────────────────────────────
    @staticmethod
    def _summarise(advisory: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(advisory, dict):
            return {}
        vulns: List[Dict[str, Any]] = []
        for v in (advisory.get("vulnerabilities") or [])[:6]:
            pkg = v.get("package") or {}
            vulns.append({
                "ecosystem": pkg.get("ecosystem"),
                "package": pkg.get("name"),
                "vulnerable_range": v.get("vulnerable_version_range"),
                "first_patched": v.get("first_patched_version"),
            })
        cwes = [c.get("cwe_id") for c in (advisory.get("cwes") or []) if c.get("cwe_id")][:3]
        # GHSA `references` is a list of plain URL strings on the REST endpoint,
        # but the GraphQL counterpart returns objects. Handle both shapes.
        refs: List[str] = []
        for r in (advisory.get("references") or []):
            if isinstance(r, str):
                refs.append(r)
            elif isinstance(r, dict) and r.get("url"):
                refs.append(r["url"])
            if len(refs) >= 3:
                break
        cvss = (advisory.get("cvss_severities") or {})
        cvss_v3 = cvss.get("cvss_v3") or {}
        cvss_v4 = cvss.get("cvss_v4") or {}
        return {
            "ghsa_id": advisory.get("ghsa_id"),
            "cve_id": advisory.get("cve_id"),
            "summary": (advisory.get("summary") or "")[:400],
            "severity": advisory.get("severity"),
            "published": advisory.get("published_at"),
            "url": advisory.get("html_url"),
            "cwes": cwes,
            "cvss_v3_score": cvss_v3.get("score"),
            "cvss_v4_score": cvss_v4.get("score"),
            "vulnerabilities": vulns,
            "references": refs,
        }

    @staticmethod
    def _render_text(rows: List[Dict[str, Any]]) -> str:
        if not rows:
            return "(no matching GHSA advisories)"
        lines: List[str] = []
        for r in rows:
            head = f"{r.get('ghsa_id', '?')}"
            if r.get("cve_id"):
                head += f" / {r['cve_id']}"
            sev = r.get("severity")
            if sev:
                head += f" [{sev}]"
            if r.get("cwes"):
                head += f" {'/'.join(r['cwes'])}"
            if r.get("cvss_v3_score") is not None:
                head += f" cvss={r['cvss_v3_score']}"
            lines.append(head)
            if r.get("summary"):
                lines.append(f"  {r['summary']}")
            for v in (r.get("vulnerabilities") or [])[:3]:
                lines.append(
                    f"  {v.get('ecosystem','?')}:{v.get('package','?')} "
                    f"range={v.get('vulnerable_range','?')} "
                    f"patched={v.get('first_patched') or '-'}"
                )
            if r.get("references"):
                lines.append(f"  refs: {' | '.join(r['references'][:2])}")
        return "\n".join(lines)
