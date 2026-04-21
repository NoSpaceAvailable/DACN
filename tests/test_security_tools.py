"""Security tools — argv construction, scope gating, subprocess mocking."""
from __future__ import annotations

import json
import subprocess
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from vapt_orchestrator_safe.tools.base import ToolError
from vapt_orchestrator_safe.tools.security import CurlTool, HttpProbeTool, NmapTool
from vapt_orchestrator_safe.utils.scope import Scope, ScopeError, ScopeGuard


# ── NmapTool ────────────────────────────────────────────────────────────
def _scope_localhost_only() -> ScopeGuard:
    return ScopeGuard(Scope.from_manifest({
        "scope": {"allow_hosts": ["127.0.0.1", "localhost"], "allow_ports": [80, 8080]}
    }))


def test_nmap_build_argv_uses_top_ports_when_ports_omitted():
    tool = NmapTool(scope=_scope_localhost_only())
    argv = tool.build_argv(target="127.0.0.1")
    assert "-Pn" in argv and "-oX" in argv
    assert "--top-ports" in argv
    assert argv[-1] == "127.0.0.1"


def test_nmap_build_argv_accepts_explicit_ports():
    tool = NmapTool(scope=_scope_localhost_only())
    argv = tool.build_argv(target="127.0.0.1", ports=[80, 8080])
    assert "-p" in argv
    assert "80,8080" in argv


def test_nmap_refuses_out_of_scope_target():
    tool = NmapTool(scope=_scope_localhost_only())
    with pytest.raises(ScopeError):
        tool.build_argv(target="example.com")


def test_nmap_refuses_out_of_scope_port():
    tool = NmapTool(scope=_scope_localhost_only())
    with pytest.raises(ScopeError):
        tool.build_argv(target="127.0.0.1", ports=[22])


def test_nmap_adds_version_scan_when_requested():
    tool = NmapTool(scope=_scope_localhost_only())
    argv = tool.build_argv(target="127.0.0.1", version_scan=True)
    assert "-sV" in argv


def test_nmap_runs_subprocess_and_captures_output():
    tool = NmapTool(scope=_scope_localhost_only())
    fake_proc = MagicMock(stdout="<nmaprun/>", stderr="", returncode=0)
    with patch("vapt_orchestrator_safe.tools.shell.shutil.which", return_value="/usr/bin/nmap"), \
         patch("vapt_orchestrator_safe.tools.shell.subprocess.run", return_value=fake_proc) as run:
        out = tool.invoke({"target": "127.0.0.1"})
    assert "nmaprun" in out
    assert run.call_args.args[0][0] == "nmap"


def test_nmap_timeout_returns_124(tmp_path):
    tool = NmapTool(scope=_scope_localhost_only())
    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv[0], timeout=kwargs.get("timeout", 1))
    with patch("vapt_orchestrator_safe.tools.shell.shutil.which", return_value="/usr/bin/nmap"), \
         patch("vapt_orchestrator_safe.tools.shell.subprocess.run", side_effect=fake_run):
        out = tool.invoke({"target": "127.0.0.1"})
    assert "exit=124" in out
    assert "TIMEOUT" in out


def test_nmap_raises_tool_error_when_binary_missing():
    tool = NmapTool(scope=_scope_localhost_only())
    with patch("vapt_orchestrator_safe.tools.shell.shutil.which", return_value=None):
        with pytest.raises(ToolError):
            tool.invoke({"target": "127.0.0.1"})


# ── CurlTool ────────────────────────────────────────────────────────────
def test_curl_refuses_unknown_method():
    tool = CurlTool(scope=_scope_localhost_only())
    with pytest.raises(ValueError):
        tool.build_argv(url="http://127.0.0.1/", method="TRACE")


def test_curl_enforces_scope_on_url():
    tool = CurlTool(scope=_scope_localhost_only())
    with pytest.raises(ScopeError):
        tool.build_argv(url="http://example.com/")


def test_curl_builds_argv_with_headers_and_body():
    tool = CurlTool(scope=_scope_localhost_only())
    argv = tool.build_argv(
        url="http://127.0.0.1:8080/x",
        method="POST",
        headers={"X-Test": "1"},
        data="payload",
    )
    argv_str = " ".join(argv)
    assert "POST" in argv_str and "X-Test: 1" in argv_str and "payload" in argv_str
    assert argv[-1].endswith("/x")


# ── HttpProbeTool ───────────────────────────────────────────────────────
class _FakeResponse:
    def __init__(self, status=200, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


class _FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def test_http_probe_returns_structured_json():
    session = _FakeSession(_FakeResponse(status=200, headers={"X-A": "1"}, text="hello"))
    tool = HttpProbeTool(scope=_scope_localhost_only(), session=session)
    out = tool.invoke({"url": "http://127.0.0.1:8080/", "method": "GET"})
    # Parse the JSON payload that follows the "[exit=...]" header.
    json_part = out.split("\n", 1)[1]
    payload = json.loads(json_part)
    assert payload["status"] == 200 and payload["body"] == "hello"
    assert payload["headers"]["X-A"] == "1"


def test_http_probe_scope_violation_reports_failure():
    tool = HttpProbeTool(scope=_scope_localhost_only(), session=_FakeSession(_FakeResponse()))
    out = tool.invoke({"url": "http://evil.example/"})
    assert "exit=-1" in out
    assert "ScopeError" in out


def test_http_probe_rejects_both_data_and_json_body():
    tool = HttpProbeTool(scope=_scope_localhost_only(), session=_FakeSession(_FakeResponse()))
    out = tool.invoke({"url": "http://127.0.0.1/", "data": "x", "json_body": {"y": 1}})
    assert "exit=2" in out


def test_http_probe_truncates_body():
    long_body = "x" * 5000
    session = _FakeSession(_FakeResponse(text=long_body))
    tool = HttpProbeTool(scope=_scope_localhost_only(), session=session)
    out = tool.invoke({"url": "http://127.0.0.1/", "max_body_chars": 100})
    payload = json.loads(out.split("\n", 1)[1])
    assert payload["body_truncated"] is True
    assert len(payload["body"]) == 100


def test_http_probe_disables_redirect_follow_at_request_time():
    session = _FakeSession(_FakeResponse())
    tool = HttpProbeTool(scope=_scope_localhost_only(), session=session)
    tool.invoke({"url": "http://127.0.0.1/"})
    assert session.calls[0]["allow_redirects"] is False
