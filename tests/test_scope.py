"""ScopeGuard — deny-by-default target allowlist."""
from __future__ import annotations

import pytest

from vapt_orchestrator_safe.utils.scope import Scope, ScopeError, ScopeGuard


def test_default_scope_allows_loopback_host():
    ScopeGuard().check_host("127.0.0.1")
    ScopeGuard().check_host("localhost")


def test_default_scope_denies_public_host():
    with pytest.raises(ScopeError):
        ScopeGuard().check_host("example.com")


def test_scope_from_manifest_reads_allow_hosts():
    scope = Scope.from_manifest({"scope": {"allow_hosts": ["vuln-app", "127.0.0.1"]}})
    ScopeGuard(scope).check_host("vuln-app")
    ScopeGuard(scope).check_host("127.0.0.1")
    with pytest.raises(ScopeError):
        ScopeGuard(scope).check_host("example.com")


def test_scope_allow_cidrs_admits_containers_in_docker_bridge():
    scope = Scope.from_manifest({"scope": {"allow_cidrs": ["172.17.0.0/16"]}})
    ScopeGuard(scope).check_host("172.17.0.5")
    with pytest.raises(ScopeError):
        ScopeGuard(scope).check_host("10.0.0.1")


def test_scope_check_port_respects_allowlist():
    scope = Scope.from_manifest({"scope": {"allow_hosts": ["127.0.0.1"], "allow_ports": [80, 8080]}})
    ScopeGuard(scope).check_port(80)
    ScopeGuard(scope).check_port(8080)
    with pytest.raises(ScopeError):
        ScopeGuard(scope).check_port(22)


def test_scope_check_url_rejects_non_http():
    with pytest.raises(ScopeError):
        ScopeGuard().check_url("file:///etc/passwd")
    with pytest.raises(ScopeError):
        ScopeGuard().check_url("gopher://127.0.0.1/")


def test_scope_check_url_enforces_host_and_port():
    scope = Scope.from_manifest({"scope": {"allow_hosts": ["127.0.0.1"], "allow_ports": [8080]}})
    ScopeGuard(scope).check_url("http://127.0.0.1:8080/api")
    with pytest.raises(ScopeError):
        ScopeGuard(scope).check_url("http://127.0.0.1:22/")
    with pytest.raises(ScopeError):
        ScopeGuard(scope).check_url("http://example.com:8080/")


def test_scope_raises_on_bare_ip_when_not_in_hosts_and_no_cidrs():
    # An IP that isn't literally in allow_hosts and no CIDRs configured → denied.
    scope = Scope.from_manifest({"scope": {"allow_hosts": ["localhost"]}})
    with pytest.raises(ScopeError):
        ScopeGuard(scope).check_host("192.168.1.5")
