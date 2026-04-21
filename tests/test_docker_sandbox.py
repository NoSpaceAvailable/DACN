"""DockerSandbox + RunPythonInSandboxTool — mock-based, no docker needed for CI.

A real end-to-end run is gated behind DACN_RUN_DOCKER=1 so thesis
reproduction can actually exercise the container path on a dev box.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from vapt_orchestrator_safe.sandbox.docker_sandbox import (
    DockerSandbox,
    SandboxError,
    SandboxResult,
)
from vapt_orchestrator_safe.tools.sandbox_exec import RunPythonInSandboxTool


# ── DockerSandbox — subprocess mocked ───────────────────────────────────
def _fake_proc(stdout="ok", stderr="", rc=0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=rc)


def test_sandbox_raises_when_docker_missing():
    sbx = DockerSandbox()
    with patch("vapt_orchestrator_safe.sandbox.docker_sandbox.shutil.which", return_value=None):
        with pytest.raises(SandboxError):
            sbx.run_python("print(1)")


def test_sandbox_runs_docker_with_expected_flags():
    sbx = DockerSandbox(network="none", cpu_limit="0.5", mem_limit="256m", default_timeout=5)
    with patch("vapt_orchestrator_safe.sandbox.docker_sandbox.shutil.which", return_value="/usr/bin/docker"), \
         patch("vapt_orchestrator_safe.sandbox.docker_sandbox.subprocess.run",
               return_value=_fake_proc(stdout="hi", stderr="", rc=0)) as mocked:
        r = sbx.run_python("print('hi')")

    assert r.exit_code == 0 and r.stdout == "hi"
    argv = mocked.call_args.args[0]
    # Core safety flags
    assert "--rm" in argv
    assert "--network=none" in argv
    assert "--read-only" in argv
    assert "--security-opt" in argv and "no-new-privileges:true" in argv
    assert "--pids-limit" in argv
    # Resource limits
    assert "0.5" in argv and "256m" in argv
    # Python invocation
    assert argv[-3:] == ["python:3.11-slim", "python", "/sandbox/main.py"]


def test_sandbox_passes_env_into_container():
    sbx = DockerSandbox()
    with patch("vapt_orchestrator_safe.sandbox.docker_sandbox.shutil.which", return_value="/usr/bin/docker"), \
         patch("vapt_orchestrator_safe.sandbox.docker_sandbox.subprocess.run",
               return_value=_fake_proc()) as mocked:
        sbx.run_python("print(1)", env={"TOKEN": "abc"})
    argv = mocked.call_args.args[0]
    # -e TOKEN=abc must appear in argv
    assert "TOKEN=abc" in argv


def test_sandbox_timeout_kills_container_and_returns_124():
    sbx = DockerSandbox(default_timeout=1)
    def fake_run(argv, **kw):
        if argv[1] == "kill":
            return _fake_proc(rc=0)
        raise subprocess.TimeoutExpired(argv[0], timeout=1)
    with patch("vapt_orchestrator_safe.sandbox.docker_sandbox.shutil.which", return_value="/usr/bin/docker"), \
         patch("vapt_orchestrator_safe.sandbox.docker_sandbox.subprocess.run", side_effect=fake_run) as mocked:
        r = sbx.run_python("while True: pass")
    assert r.exit_code == 124
    assert r.timed_out is True
    # kill invoked at least once
    kill_calls = [c for c in mocked.call_args_list if len(c.args[0]) >= 2 and c.args[0][1] == "kill"]
    assert kill_calls


# ── RunPythonInSandboxTool — DockerSandbox mocked ───────────────────────
def test_tool_rejects_empty_script():
    tool = RunPythonInSandboxTool(sandbox=MagicMock())
    out = tool.invoke({"script": "   "})
    assert "exit=2" in out


def test_tool_rejects_oversized_script():
    tool = RunPythonInSandboxTool(sandbox=MagicMock())
    out = tool.invoke({"script": "x" * 30_000})
    assert "exit=2" in out and "too large" in out


def test_tool_wraps_sandbox_error_cleanly():
    fake = MagicMock()
    fake.run_python.side_effect = SandboxError("no docker")
    tool = RunPythonInSandboxTool(sandbox=fake)
    out = tool.invoke({"script": "print(1)"})
    assert "exit=-1" in out and "SandboxError" in out


def test_tool_returns_json_payload_with_exit_and_container():
    fake = MagicMock()
    fake.run_python.return_value = SandboxResult(
        stdout="hello\n", stderr="", exit_code=0, duration_ms=42,
        container="dacn-sbx-x", network="none",
    )
    tool = RunPythonInSandboxTool(sandbox=fake)
    out = tool.invoke({"script": "print('hello')"})
    assert "exit=0" in out
    payload = json.loads(out.split("\n", 1)[1])
    assert payload["stdout"] == "hello\n"
    assert payload["container"] == "dacn-sbx-x"
    assert payload["network"] == "none"


def test_tool_propagates_timeout_flag():
    fake = MagicMock()
    fake.run_python.return_value = SandboxResult(
        stdout="", stderr="TIMEOUT", exit_code=124, duration_ms=5000,
        container="c", network="none", timed_out=True,
    )
    tool = RunPythonInSandboxTool(sandbox=fake)
    out = tool.invoke({"script": "while True: pass"})
    payload = json.loads(out.split("\n", 1)[1])
    assert payload["timed_out"] is True
    assert payload["exit_code"] == 124


# ── Smoke (real docker) — opt-in only ──────────────────────────────────
@pytest.mark.skipif(
    os.environ.get("DACN_RUN_DOCKER") != "1" or shutil.which("docker") is None,
    reason="Set DACN_RUN_DOCKER=1 and install docker to run the real sandbox smoke test.",
)
def test_sandbox_real_docker_hello_world():
    sbx = DockerSandbox(default_timeout=30)
    r = sbx.run_python("print('from container', 1+1)")
    assert r.exit_code == 0
    assert "from container 2" in r.stdout
