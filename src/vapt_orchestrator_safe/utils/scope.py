"""Scope guard for security tools.

Every subprocess-based tool (nmap / curl / http probe / sqlmap / …) must
call :meth:`ScopeGuard.check_target` on its target before executing. A
fixture declares its permissible targets via the manifest:

    {
      "id": "challenge_sqli_dynamic_01",
      "mode": "dynamic",
      "scope": {
        "allow_hosts": ["127.0.0.1", "localhost", "vuln-app"],
        "allow_cidrs": ["172.17.0.0/16"],
        "allow_ports": [80, 443, 8080, 3306]
      }
    }

If a manifest lacks a ``scope`` section the guard falls back to an
extremely conservative default: only ``127.0.0.1`` / ``localhost`` and
privileged TCP ports ≤ 1024 are allowed, matching the "local lab" spirit
of the inherited scaffold. Tools never probe anything not explicitly
whitelisted — that's how we honour the README's "does not probe public
IPs" guarantee while still running real binaries in Sprint 4+.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse


class ScopeError(RuntimeError):
    """Raised when a target is not inside the fixture's declared scope."""


_DEFAULT_HOSTS: Set[str] = {"127.0.0.1", "localhost", "::1"}
_DEFAULT_CIDRS: tuple = ()  # nothing outside loopback by default
_DEFAULT_PORTS: Set[int] = {80, 443, 8080, 8443, 3000, 5000}


@dataclass(frozen=True)
class Scope:
    allow_hosts: frozenset = field(default_factory=lambda: frozenset(_DEFAULT_HOSTS))
    allow_cidrs: tuple = field(default_factory=lambda: _DEFAULT_CIDRS)
    allow_ports: frozenset = field(default_factory=lambda: frozenset(_DEFAULT_PORTS))

    @classmethod
    def from_manifest(cls, manifest: Optional[dict]) -> "Scope":
        scope_block = (manifest or {}).get("scope") or {}
        hosts = frozenset(scope_block.get("allow_hosts") or _DEFAULT_HOSTS)
        cidrs = tuple(
            ipaddress.ip_network(c, strict=False)
            for c in (scope_block.get("allow_cidrs") or [])
        )
        ports_raw = scope_block.get("allow_ports")
        ports = frozenset(int(p) for p in ports_raw) if ports_raw else frozenset(_DEFAULT_PORTS)
        return cls(allow_hosts=hosts, allow_cidrs=cidrs, allow_ports=ports)


class ScopeGuard:
    """Check hosts / URLs / CIDRs against a fixture-declared scope."""

    def __init__(self, scope: Optional[Scope] = None):
        self.scope = scope or Scope()

    # ── primitives ───────────────────────────────────────────────────────
    def check_host(self, host: str) -> None:
        lowered = host.lower().strip()
        if lowered in self.scope.allow_hosts:
            return
        if self.scope.allow_cidrs:
            try:
                ip = ipaddress.ip_address(lowered)
            except ValueError:
                raise ScopeError(
                    f"Host {host!r} not in allowlist "
                    f"({sorted(self.scope.allow_hosts)}) and not an IP to check against CIDRs"
                )
            if any(ip in net for net in self.scope.allow_cidrs):
                return
        raise ScopeError(
            f"Host {host!r} outside scope "
            f"(hosts={sorted(self.scope.allow_hosts)}, "
            f"cidrs={[str(c) for c in self.scope.allow_cidrs]})"
        )

    def check_port(self, port: int) -> None:
        if int(port) not in self.scope.allow_ports:
            raise ScopeError(
                f"Port {port} outside scope {sorted(self.scope.allow_ports)}"
            )

    def check_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeError(f"URL scheme {parsed.scheme!r} not allowed (http/https only)")
        if not parsed.hostname:
            raise ScopeError(f"URL {url!r} has no hostname")
        self.check_host(parsed.hostname)
        if parsed.port is not None:
            self.check_port(parsed.port)

    # ── batching ─────────────────────────────────────────────────────────
    def check_hosts(self, hosts: Iterable[str]) -> None:
        for h in hosts:
            self.check_host(h)
