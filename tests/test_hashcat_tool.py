"""HashcatTool tests -- argv construction + subprocess mocking."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.tools.base import ToolError
from vapt_orchestrator_safe.tools.security.hashcat import HashcatTool


def _bb(tmp_path: Path) -> Blackboard:
    return Blackboard(run_id="t", run_dir=tmp_path)


# ── argv construction ────────────────────────────────────────────────────
def test_hashcat_default_argv():
    tool = HashcatTool()
    argv = tool.build_argv(hash_value="5f4dcc3b5aa765d61d8327deb882cf99")
    assert argv[0] == "hashcat"
    assert "--quiet" in argv
    assert "--potfile-disable" in argv
    assert "-m" in argv
    idx = list(argv).index("-m")
    assert argv[idx + 1] == "0"  # md5 default
    assert "-a" in argv
    assert "5f4dcc3b5aa765d61d8327deb882cf99" in argv


def test_hashcat_sha256_mode():
    tool = HashcatTool()
    argv = tool.build_argv(hash_value="abc123", hash_type="sha256")
    idx = list(argv).index("-m")
    assert argv[idx + 1] == "1400"


def test_hashcat_numeric_mode():
    tool = HashcatTool()
    argv = tool.build_argv(hash_value="abc123", hash_type="3200")
    idx = list(argv).index("-m")
    assert argv[idx + 1] == "3200"


def test_hashcat_custom_wordlist():
    tool = HashcatTool()
    argv = tool.build_argv(
        hash_value="abc",
        wordlist="/tmp/custom.txt",
    )
    assert "/tmp/custom.txt" in argv


def test_hashcat_rules_appended():
    tool = HashcatTool()
    argv = tool.build_argv(
        hash_value="abc",
        rules="/usr/share/hashcat/rules/best64.rule",
    )
    assert "-r" in argv
    idx = list(argv).index("-r")
    assert argv[idx + 1] == "/usr/share/hashcat/rules/best64.rule"


def test_hashcat_runtime_capped():
    tool = HashcatTool()
    argv = tool.build_argv(hash_value="abc", max_runtime=999)
    idx = list(argv).index("--runtime")
    assert argv[idx + 1] == "120"  # capped at 120


def test_hashcat_rejects_invalid_attack_mode():
    tool = HashcatTool()
    with pytest.raises(ValueError, match="not allowed"):
        tool.build_argv(hash_value="abc", attack_mode=3)


def test_hashcat_rejects_unknown_hash_type():
    tool = HashcatTool()
    with pytest.raises(ValueError, match="Unknown hash_type"):
        tool.build_argv(hash_value="abc", hash_type="scrypt")


# ── subprocess integration (mocked) ─────────────────────────────────────
def test_hashcat_runs_and_returns_cracked_password(tmp_path):
    bb = _bb(tmp_path)
    tool = HashcatTool().bind_blackboard(bb)
    fake_proc = MagicMock(
        stdout="5f4dcc3b5aa765d61d8327deb882cf99:password",
        stderr="",
        returncode=0,
    )
    with patch("vapt_orchestrator_safe.tools.shell.shutil.which", return_value="/usr/bin/hashcat"), \
         patch("vapt_orchestrator_safe.tools.shell.subprocess.run", return_value=fake_proc) as run:
        out = tool.invoke({"hash_value": "5f4dcc3b5aa765d61d8327deb882cf99"})

    assert "exit=0" in out
    assert "password" in out
    assert run.call_args.args[0][0] == "hashcat"
    assert len(bb.artifacts) == 1
    assert bb.artifacts[0]["kind"] == "tool:hashcat_crack"


def test_hashcat_returns_nonzero_on_exhausted(tmp_path):
    bb = _bb(tmp_path)
    tool = HashcatTool().bind_blackboard(bb)
    fake_proc = MagicMock(stdout="", stderr="Status: Exhausted", returncode=1)
    with patch("vapt_orchestrator_safe.tools.shell.shutil.which", return_value="/usr/bin/hashcat"), \
         patch("vapt_orchestrator_safe.tools.shell.subprocess.run", return_value=fake_proc):
        out = tool.invoke({"hash_value": "abc123"})
    assert "exit=1" in out
    assert "Exhausted" in out


def test_hashcat_raises_tool_error_when_binary_missing():
    tool = HashcatTool()
    with patch("vapt_orchestrator_safe.tools.shell.shutil.which", return_value=None):
        with pytest.raises(ToolError):
            tool.invoke({"hash_value": "abc"})


# ── combinator mode ─────────────────────────────────────────────────────
def test_hashcat_combinator_mode_argv():
    tool = HashcatTool()
    argv = tool.build_argv(
        hash_value="abc",
        attack_mode=1,
        wordlist="/tmp/words.txt",
    )
    idx = list(argv).index("-a")
    assert argv[idx + 1] == "1"


# ── no scope gating needed ──────────────────────────────────────────────
def test_hashcat_has_no_scope():
    tool = HashcatTool()
    assert not hasattr(tool, '_scope') or tool._scope is None
