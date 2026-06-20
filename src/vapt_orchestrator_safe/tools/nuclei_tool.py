"""query_nuclei — fetch ProjectDiscovery Nuclei templates by CVE id.

Closes the loop between ``query_cve`` (identifies a CVE) and the PoC the
exploit agent has to generate. Nuclei community templates are structured
YAML files at ``projectdiscovery/nuclei-templates`` containing the exact
HTTP request bytes + matchers (oracle) that reproduce thousands of CVEs.

Path convention::

    http/cves/<year>/CVE-<year>-<num>.yaml

When a template exists, the model gets a ready-made request body + the
matchers list and can adapt it to the fixture (host/path/headers) rather
than guessing the exploit technique. Coverage is **partial** — ~3000
CVEs as of 2026; the tool reports ``found=False`` cleanly when the CVE
is missing so the caller can fall back to ``query_exploitdb`` or
``fetch_writeup``.

Cache: 90-day TTL at ``data/cache/nuclei/<cve_id>.json``. Templates for
old CVEs rarely change once committed; the long TTL avoids re-fetching
on every bench run. Set ``GITHUB_TOKEN`` to lift the 60/hr unauth cap.
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


_NUCLEI_RAW_BASE = (
    "https://raw.githubusercontent.com/projectdiscovery/"
    "nuclei-templates/main/http/cves/{year}/{cve_id}.yaml"
)
_CACHE_TTL_SECONDS = 90 * 24 * 3600  # 90 days
_APPROX_CHARS_PER_TOKEN = 4
_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$", re.IGNORECASE)

_RATE_LOCK = threading.Lock()
_LAST_REQUEST_AT: List[float] = [0.0]


def _approx_tokens(text: str) -> int:
    return max(1, len(text) // _APPROX_CHARS_PER_TOKEN)


class _QueryNucleiArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve_id: str = Field(
        ...,
        description=(
            "CVE identifier to look up, e.g. 'CVE-2021-44228' (Log4Shell). "
            "Case-insensitive; the tool normalises to upper-case."
        ),
    )


class QueryNucleiTool(BaseTool):
    name: str = "query_nuclei"
    description: str = (
        "Fetch a ProjectDiscovery Nuclei template for a given CVE id. "
        "Returns the structured HTTP request bytes + matchers (oracle "
        "equivalent) that reproduce the exploit, when a template exists "
        "for that CVE. Use this AFTER `query_cve`/`query_ghsa` has given "
        "you a CVE id, BEFORE writing your own PoC — Nuclei templates "
        "are the canonical machine-readable exploit recipe. Returns "
        "`found=false` if no template exists; in that case fall back to "
        "`query_exploitdb` or `fetch_writeup` on a reference URL."
    )
    args_schema: Type[BaseModel] = _QueryNucleiArgs
    truncate_at: ClassVar[int] = 8000

    _cache_dir: Path = PrivateAttr()
    _timeout_s: float = PrivateAttr(default=15.0)
    _token: Optional[str] = PrivateAttr(default=None)

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        timeout_s: float = 15.0,
        github_token: Optional[str] = None,
        **data: Any,
    ) -> None:
        super().__init__(**data)
        _load_dotenv_if_present()
        if cache_dir is None:
            cache_dir = Path(__file__).resolve().parents[3] / "data" / "cache" / "nuclei"
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._timeout_s = timeout_s
        # The raw.githubusercontent endpoint is anon-friendly (60/hr unauth);
        # a token lifts to 5000/hr. Shared with query_ghsa.
        self._token = github_token or os.environ.get("GITHUB_TOKEN")

    def _invoke(self, **kwargs: Any) -> ToolResult:
        cve_id_raw = (kwargs.get("cve_id") or "").strip().upper()
        m = _CVE_RE.match(cve_id_raw)
        if not m:
            return ToolResult(
                stderr=f"Invalid cve_id {cve_id_raw!r}. Expected 'CVE-YYYY-NNNN'.",
                exit_code=2,
            )
        year, num = m.group(1), m.group(2)
        cve_id = f"CVE-{year}-{num}"
        url = _NUCLEI_RAW_BASE.format(year=year, cve_id=cve_id)

        cached = self._read_cache(cve_id)
        if cached is not None:
            return self._render_result(cve_id, url, cached)

        try:
            template_text = self._fetch_live(url)
        except _NotFound:
            payload = {"cve_id": cve_id, "found": False, "url": url}
            self._write_cache(cve_id, payload)
            return ToolResult(
                stdout=json.dumps(payload, ensure_ascii=False),
                exit_code=0,
                metadata={"cve_id": cve_id, "found": False},
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                stderr=f"Nuclei fetch failed: {type(exc).__name__}: {exc}",
                exit_code=1,
                metadata={"cve_id": cve_id, "url": url},
            )

        parsed = _parse_template(template_text)
        payload = {
            "cve_id": cve_id,
            "found": True,
            "url": url,
            "template": parsed,
            "raw_yaml_preview": template_text[:1500],
        }
        self._write_cache(cve_id, payload)
        return self._render_result(cve_id, url, payload)

    # ── HTTP ──
    def _fetch_live(self, url: str) -> str:
        try:
            import requests
        except ImportError as exc:
            raise RuntimeError("requests package required (pip install requests)") from exc

        self._respect_rate_limit()

        headers = {"User-Agent": "DACN-vapt-orchestrator/1.0"}
        if self._token:
            # raw.githubusercontent.com honours Bearer tokens for higher quota
            headers["Authorization"] = f"Bearer {self._token}"

        r = requests.get(url, headers=headers, timeout=self._timeout_s)
        if r.status_code == 404:
            raise _NotFound(url)
        if r.status_code in (403, 429):
            time.sleep(10.0)
            r = requests.get(url, headers=headers, timeout=self._timeout_s)
        if r.status_code == 404:
            raise _NotFound(url)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
        return r.text

    def _respect_rate_limit(self) -> None:
        # raw.githubusercontent.com has separate quota from api.github.com but
        # share the same secondary-limit pool. Stay polite at 1 req/s when
        # authenticated, 1 req/10s unauth.
        interval = 1.0 if self._token else 10.0
        with _RATE_LOCK:
            now = time.monotonic()
            wait = (_LAST_REQUEST_AT[0] + interval) - now
            if wait > 0:
                time.sleep(wait)
            _LAST_REQUEST_AT[0] = time.monotonic()

    # ── cache ──
    def _cache_path(self, cve_id: str) -> Path:
        # cve_id is already normalised; safe filename.
        return self._cache_dir / f"{cve_id}.json"

    def _read_cache(self, cve_id: str) -> Optional[Dict[str, Any]]:
        path = self._cache_path(cve_id)
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

    def _write_cache(self, cve_id: str, payload: Dict[str, Any]) -> None:
        path = self._cache_path(cve_id)
        try:
            path.write_text(
                json.dumps({"cached_at": time.time(), "payload": payload}, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:  # noqa: BLE001
            pass

    # ── rendering ──
    def _render_result(self, cve_id: str, url: str, payload: Dict[str, Any]) -> ToolResult:
        if not payload.get("found"):
            text = f"(no Nuclei template for {cve_id})"
        else:
            text = _render_template_text(payload.get("template") or {})
        out = dict(payload)
        out["text"] = text
        out["approx_tokens"] = _approx_tokens(text)
        return ToolResult(
            stdout=json.dumps(out, ensure_ascii=False),
            exit_code=0,
            metadata={
                "cve_id": cve_id,
                "found": payload.get("found", False),
                "approx_tokens": out["approx_tokens"],
            },
        )


class _NotFound(Exception):
    """404 from the Nuclei raw endpoint — template doesn't exist for this CVE."""


def _parse_template(yaml_text: str) -> Dict[str, Any]:
    """Extract the parts of a Nuclei template the LLM actually needs.

    Returns a slim dict with info + http stages. Drops anything Nuclei-
    runtime-only (workflow, variables) since the model isn't executing
    Nuclei — it's adapting the request bytes by hand.
    """
    try:
        import yaml  # PyYAML
    except ImportError:
        return {"_parse_error": "PyYAML not installed", "_raw_first_chars": yaml_text[:1000]}

    try:
        doc = yaml.safe_load(yaml_text) or {}
    except Exception as exc:  # noqa: BLE001
        return {"_parse_error": f"{type(exc).__name__}: {exc}", "_raw_first_chars": yaml_text[:1000]}

    if not isinstance(doc, dict):
        return {"_parse_error": "template not a mapping", "_raw_first_chars": yaml_text[:1000]}

    info = doc.get("info") or {}
    info_out = {
        "name": info.get("name"),
        "author": info.get("author"),
        "severity": info.get("severity"),
        "description": info.get("description"),
        "reference": _coerce_list(info.get("reference")),
        "tags": _coerce_list(info.get("tags")),
        "classification": info.get("classification") or {},
    }

    http_stages: List[Dict[str, Any]] = []
    for stage in (doc.get("http") or doc.get("requests") or []):
        if not isinstance(stage, dict):
            continue
        http_stages.append({
            "method": stage.get("method"),
            "path": _coerce_list(stage.get("path")),
            "raw": _coerce_list(stage.get("raw")),
            "headers": stage.get("headers") or {},
            "body": stage.get("body"),
            "matchers_condition": stage.get("matchers-condition") or stage.get("matchers_condition"),
            "matchers": stage.get("matchers") or [],
            "extractors": stage.get("extractors") or [],
        })

    return {
        "id": doc.get("id"),
        "info": info_out,
        "http": http_stages,
    }


def _coerce_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _render_template_text(template: Dict[str, Any]) -> str:
    if not template or template.get("_parse_error"):
        err = (template or {}).get("_parse_error", "unparseable template")
        return f"(parse error: {err})"
    info = template.get("info") or {}
    lines: List[str] = []
    head = f"{template.get('id', '?')}"
    sev = info.get("severity")
    if sev:
        head += f" [{sev}]"
    lines.append(head)
    if info.get("name"):
        lines.append(f"  name: {info['name']}")
    if info.get("description"):
        lines.append(f"  desc: {info['description'][:300]}")
    if info.get("classification"):
        cls = info["classification"]
        cwe = cls.get("cwe-id") or cls.get("cwe_id")
        cvss = cls.get("cvss-score") or cls.get("cvss_score")
        if cwe or cvss:
            lines.append(f"  class: cwe={cwe} cvss={cvss}")
    if info.get("reference"):
        refs = info["reference"][:3]
        lines.append(f"  refs: {' | '.join(str(r) for r in refs)}")
    for i, stage in enumerate(template.get("http") or [], 1):
        lines.append(f"  -- http[{i}]")
        if stage.get("method"):
            lines.append(f"     method: {stage['method']}")
        for p in (stage.get("path") or [])[:3]:
            lines.append(f"     path: {p}")
        for raw in (stage.get("raw") or [])[:2]:
            raw_compact = raw if len(raw) <= 600 else (raw[:580] + "...(trunc)")
            lines.append("     raw |")
            for line in raw_compact.splitlines():
                lines.append(f"       {line}")
        if stage.get("body"):
            b = stage["body"]
            body_str = b if isinstance(b, str) else json.dumps(b)
            lines.append(f"     body: {body_str[:300]}")
        for matcher in (stage.get("matchers") or [])[:4]:
            mtype = matcher.get("type", "?")
            words = matcher.get("words") or matcher.get("regex") or matcher.get("status") or []
            lines.append(f"     match {mtype}: {words}")
    return "\n".join(lines)
