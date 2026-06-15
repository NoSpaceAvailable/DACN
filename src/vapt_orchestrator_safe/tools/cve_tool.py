"""query_cve — online CVE lookup against NVD API 2.0 with disk cache.

The local ``query_kg`` tool can match on *attack_family* / *framework* /
*subject id* but has no concept of (component, version). When a fixture
points at a specific component version (e.g. ``nginx.conf`` declaring
``# Pinned: nginx version 1.17.6``), the relevant CVE — like
CVE-2019-20372 (NGINX <1.17.7 error_page HTTP request smuggling) — is
not retrievable from the local HackTricks corpus.

This tool wraps the NVD REST API 2.0 with three query modes:

  - ``cve_id="CVE-2019-20372"``       — direct lookup
  - ``keyword="nginx error_page"``    — free-text search
  - ``component="nginx", version="1.17.6"`` — CPE-style structured lookup
    (wildcard vendor; the result CPE rows carry their own version range
    metadata so the model can verify the fixture version falls in scope).

Reproducibility: every request is cached to ``data/cache/nvd/<sha256>.json``
with a 30-day TTL. The first bench-run hits the network; subsequent runs
are deterministic. Rate limits: free tier = 5 req / 30 s (~6 s sleep);
with ``NVD_API_KEY`` set, 50 req / 30 s (~0.6 s sleep).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from vapt_orchestrator_safe.config import _load_dotenv_if_present
from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_TTL_SECONDS = 30 * 24 * 3600  # 30 days
_APPROX_CHARS_PER_TOKEN = 4

# Cross-instance rate-limit floor (process-wide). Threading lock so concurrent
# tool calls from a parallel dispatcher don't burst past the NVD ceiling.
_RATE_LOCK = threading.Lock()
_LAST_REQUEST_AT: List[float] = [0.0]  # mutable singleton


def _approx_tokens(text: str) -> int:
    return max(1, len(text) // _APPROX_CHARS_PER_TOKEN)


# ── args schema ──────────────────────────────────────────────────────────────
class _QueryCveArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve_id: Optional[str] = Field(
        default=None,
        description="Direct lookup, e.g. 'CVE-2019-20372'.",
    )
    keyword: Optional[str] = Field(
        default=None,
        description="Free-text search, e.g. 'nginx error_page smuggling'.",
    )
    component: Optional[str] = Field(
        default=None,
        description="Product name for CPE search, e.g. 'nginx'.",
    )
    vendor: Optional[str] = Field(
        default=None,
        description="Optional vendor for CPE search. If omitted, vendor is wildcarded.",
    )
    version: Optional[str] = Field(
        default=None,
        description="Optional version for CPE search, e.g. '1.17.6'. "
                    "Only used together with component.",
    )
    limit: int = Field(default=5, description="Max CVEs to return (1-20).")


# ── tool ─────────────────────────────────────────────────────────────────────
class QueryCveTool(BaseTool):
    name: str = "query_cve"
    description: str = (
        "Look up CVE entries on the National Vulnerability Database (NVD) by "
        "CVE id, free-text keyword, OR (component, version). Use this when "
        "the source/transcript reveals a specific component+version "
        "(e.g. 'nginx 1.17.6', 'spring-core 5.3.20', 'log4j 2.14.0') so you "
        "can map version → known CVE → CWE → exploitation technique. "
        "Returns the CVE id, summary, CWE, severity score, the affected "
        "version range, and reference URLs. Results are cached so repeated "
        "calls are free."
    )
    args_schema: Type[BaseModel] = _QueryCveArgs
    truncate_at: ClassVar[int] = 6000

    _api_key: Optional[str] = PrivateAttr(default=None)
    _cache_dir: Path = PrivateAttr()
    _timeout_s: float = PrivateAttr(default=15.0)
    _has_key: bool = PrivateAttr(default=False)

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        api_key: Optional[str] = None,
        timeout_s: float = 15.0,
        **data: Any,
    ) -> None:
        super().__init__(**data)
        # Pull in .env / .env.local so NVD_API_KEY set there is visible without
        # the caller having to invoke backend_factory first. Idempotent — only
        # populates os.environ keys that aren't already set.
        _load_dotenv_if_present()
        # Resolve cache dir relative to repo root unless explicitly set.
        if cache_dir is None:
            cache_dir = Path(__file__).resolve().parents[3] / "data" / "cache" / "nvd"
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._api_key = api_key or os.environ.get("NVD_API_KEY")
        self._has_key = bool(self._api_key)
        self._timeout_s = timeout_s

    # ── core dispatch ────────────────────────────────────────────────────────
    def _invoke(self, **kwargs: Any) -> ToolResult:
        limit = max(1, min(20, int(kwargs.get("limit", 5))))

        cve_id = (kwargs.get("cve_id") or "").strip()
        keyword = (kwargs.get("keyword") or "").strip()
        component = (kwargs.get("component") or "").strip()
        version = (kwargs.get("version") or "").strip()
        vendor = (kwargs.get("vendor") or "").strip() or "*"

        if cve_id:
            params = {"cveId": cve_id}
            mode = "cve_id"
        elif component:
            # Use NVD's `virtualMatchString` — it does CPE range matching
            # server-side, so passing `cpe:2.3:a:*:nginx:1.17.6` correctly
            # returns CVEs whose `versionEndExcluding` is 1.17.7. The strict
            # `cpeName` param requires exact vendor + version and is unusable
            # when the caller only knows the product name + a pinned version.
            ver_part = version or "*"
            vms = f"cpe:2.3:a:{vendor}:{component}:{ver_part}"
            params = {"virtualMatchString": vms, "resultsPerPage": str(limit)}
            mode = "component"
        elif keyword:
            params = {"keywordSearch": keyword, "resultsPerPage": str(limit)}
            mode = "keyword"
        else:
            return ToolResult(
                stderr="Pass at least one of: cve_id, component (+version), keyword.",
                exit_code=2,
            )

        try:
            raw = self._fetch(params)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                stderr=f"NVD lookup failed ({mode}): {type(exc).__name__}: {exc}",
                exit_code=1,
                metadata={"mode": mode, "params": params},
            )

        cves = self._summarise(raw, limit)
        # CPE returned nothing? Try a final keyword fallback so the model still
        # gets something to chew on for very obscure components.
        if not cves and mode == "component" and component:
            fallback_kw = component if not version else f"{component} {version}"
            fb_params = {"keywordSearch": fallback_kw, "resultsPerPage": str(limit)}
            try:
                raw = self._fetch(fb_params)
                cves = self._summarise(raw, limit)
                if cves:
                    params = fb_params
                    mode = "component_kw_fallback"
            except Exception:  # noqa: BLE001 — fallback is best-effort
                pass
        payload_text = self._render_text(cves)
        token_estimate = _approx_tokens(payload_text)
        payload = {
            "mode": mode,
            "query": params,
            "count": len(cves),
            "cves": cves,
            "text": payload_text,
            "approx_tokens": token_estimate,
        }
        return ToolResult(
            stdout=json.dumps(payload, ensure_ascii=False),
            exit_code=0,
            metadata={
                "approx_tokens": token_estimate,
                "count": len(cves),
                "mode": mode,
                "params": params,
            },
        )

    # ── HTTP + cache ─────────────────────────────────────────────────────────
    def _fetch(self, params: Dict[str, str]) -> Dict[str, Any]:
        cache_key = self._cache_key(params)
        cached = self._read_cache(cache_key)
        if cached is not None:
            return cached
        body = self._fetch_live(params)
        self._write_cache(cache_key, body)
        return body

    def _cache_key(self, params: Dict[str, str]) -> str:
        canon = json.dumps(params, sort_keys=True)
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:32]

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
        return blob.get("response")

    def _write_cache(self, key: str, response: Dict[str, Any]) -> None:
        path = self._cache_dir / f"{key}.json"
        try:
            path.write_text(
                json.dumps({"cached_at": time.time(), "response": response},
                           ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:  # noqa: BLE001
            pass  # cache write is best-effort

    def _fetch_live(self, params: Dict[str, str]) -> Dict[str, Any]:
        try:
            import requests
        except ImportError as exc:
            raise RuntimeError("requests package required (pip install requests)") from exc

        self._respect_rate_limit()

        headers = {"User-Agent": "DACN-vapt-orchestrator/1.0"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        r = requests.get(_NVD_BASE, params=params, headers=headers, timeout=self._timeout_s)
        if r.status_code == 403 or r.status_code == 429:
            # NVD rate limit; back off once and retry (still bounded by upper caller).
            time.sleep(30.0)
            self._respect_rate_limit(force=True)
            r = requests.get(_NVD_BASE, params=params, headers=headers, timeout=self._timeout_s)
        if r.status_code != 200:
            raise RuntimeError(f"NVD HTTP {r.status_code}: {r.text[:200]}")
        return r.json()

    def _respect_rate_limit(self, force: bool = False) -> None:
        """Sleep so we don't exceed NVD's per-window quota.

        Free tier: 5 / 30s → 6.5s between requests.
        With API key: 50 / 30s → 0.7s between requests.
        """
        interval = 0.7 if self._has_key else 6.5
        with _RATE_LOCK:
            now = time.monotonic()
            wait = (_LAST_REQUEST_AT[0] + interval) - now
            if wait > 0:
                time.sleep(wait)
            _LAST_REQUEST_AT[0] = time.monotonic()

    # ── response normalisation ───────────────────────────────────────────────
    def _summarise(self, raw: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for entry in (raw.get("vulnerabilities") or [])[:limit]:
            cve = entry.get("cve") or {}
            cve_id = cve.get("id", "")
            summary = ""
            for d in cve.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    summary = (d.get("value") or "")[:600]
                    break
            cwe = ""
            for w in cve.get("weaknesses", []) or []:
                for desc in w.get("description", []) or []:
                    if desc.get("lang") == "en":
                        v = desc.get("value", "")
                        if v.startswith("CWE-"):
                            cwe = v
                            break
                if cwe:
                    break
            severity = self._extract_severity(cve)
            affected = self._extract_affected(cve)
            refs = [r.get("url", "") for r in (cve.get("references") or [])][:3]
            out.append({
                "id": cve_id,
                "summary": summary,
                "published": cve.get("published", ""),
                "cwe": cwe,
                "severity": severity,
                "affected": affected,
                "references": refs,
            })
        return out

    @staticmethod
    def _extract_severity(cve: Dict[str, Any]) -> Dict[str, Any]:
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if not arr:
                continue
            data = arr[0].get("cvssData") or {}
            return {
                "version": data.get("version", ""),
                "score": data.get("baseScore"),
                "vector": data.get("vectorString", ""),
            }
        return {}

    @staticmethod
    def _extract_affected(cve: Dict[str, Any]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for cfg in cve.get("configurations", []) or []:
            for node in cfg.get("nodes", []) or []:
                for m in node.get("cpeMatch", []) or []:
                    crit = m.get("criteria", "")
                    parts = crit.split(":")
                    # cpe:2.3:a:<vendor>:<product>:<version>:...
                    vendor = parts[3] if len(parts) > 4 else ""
                    product = parts[4] if len(parts) > 5 else ""
                    version = parts[5] if len(parts) > 6 else ""
                    rows.append({
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "versionStartIncluding": m.get("versionStartIncluding"),
                        "versionStartExcluding": m.get("versionStartExcluding"),
                        "versionEndIncluding": m.get("versionEndIncluding"),
                        "versionEndExcluding": m.get("versionEndExcluding"),
                    })
        return rows[:10]

    @staticmethod
    def _render_text(cves: List[Dict[str, Any]]) -> str:
        if not cves:
            return "(no matching CVEs)"
        lines: List[str] = []
        for c in cves:
            head = f"{c['id']}"
            if c.get("cwe"):
                head += f" [{c['cwe']}]"
            sev = c.get("severity") or {}
            if sev.get("score") is not None:
                head += f" cvss={sev['score']}"
            lines.append(head)
            if c.get("summary"):
                lines.append(f"  {c['summary']}")
            if c.get("affected"):
                aff_text = ", ".join(
                    f"{a.get('vendor','*')}:{a.get('product','*')} "
                    f"({_range_text(a)})"
                    for a in c["affected"][:3]
                )
                lines.append(f"  affected: {aff_text}")
            if c.get("references"):
                lines.append(f"  refs: {' | '.join(c['references'][:2])}")
        return "\n".join(lines)


def _range_text(a: Dict[str, Any]) -> str:
    parts: List[str] = []
    if a.get("versionStartIncluding"):
        parts.append(f">={a['versionStartIncluding']}")
    if a.get("versionStartExcluding"):
        parts.append(f">{a['versionStartExcluding']}")
    if a.get("versionEndIncluding"):
        parts.append(f"<={a['versionEndIncluding']}")
    if a.get("versionEndExcluding"):
        parts.append(f"<{a['versionEndExcluding']}")
    if not parts:
        ver = a.get("version") or "*"
        if ver and ver != "*":
            return f"={ver}"
        return "any"
    return " ".join(parts)
