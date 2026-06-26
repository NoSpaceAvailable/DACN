"""Tests for grep_file — scratch-only regex search."""
from __future__ import annotations

from pathlib import Path

import pytest

from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.tools.grep_file_tool import GrepFileTool


def _bb_with_scratch(tmp_path: Path) -> tuple[Blackboard, Path]:
    bb = Blackboard(run_id="t", run_dir=tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    return bb, scratch


def test_grep_file_finds_pattern_with_context(tmp_path):
    bb, scratch = _bb_with_scratch(tmp_path)
    (scratch / "doc.txt").write_text(
        "intro line\n"
        "blah blah\n"
        "SCRIPT_NAME is set by gunicorn\n"
        "more text\n"
        "tail",
        encoding="utf-8",
    )
    tool = GrepFileTool().bind_blackboard(bb)
    out = tool.invoke({"path": "doc.txt", "pattern": "SCRIPT_NAME", "context_lines": 1})
    assert "SCRIPT_NAME is set by gunicorn" in out
    assert "blah blah" in out  # context before
    assert "more text" in out  # context after
    assert "intro line" not in out  # outside context window


def test_grep_file_refuses_path_outside_scratch(tmp_path):
    bb, _ = _bb_with_scratch(tmp_path)
    sibling = tmp_path / "outside.txt"
    sibling.write_text("nope", encoding="utf-8")
    tool = GrepFileTool().bind_blackboard(bb)
    out = tool.invoke({"path": str(sibling), "pattern": "nope"})
    assert "outside the scratch root" in out
    assert "exit=2" in out


def test_grep_file_refuses_traversal(tmp_path):
    bb, scratch = _bb_with_scratch(tmp_path)
    (tmp_path / "secret.txt").write_text("flag", encoding="utf-8")
    tool = GrepFileTool().bind_blackboard(bb)
    out = tool.invoke({"path": "../secret.txt", "pattern": "flag"})
    assert "outside the scratch root" in out


def test_grep_file_returns_no_match_clean(tmp_path):
    bb, scratch = _bb_with_scratch(tmp_path)
    (scratch / "doc.txt").write_text("hello world", encoding="utf-8")
    tool = GrepFileTool().bind_blackboard(bb)
    out = tool.invoke({"path": "doc.txt", "pattern": "absent"})
    assert "No matches" in out
    assert "exit=0" in out


def test_grep_file_invalid_regex_returns_error(tmp_path):
    bb, scratch = _bb_with_scratch(tmp_path)
    (scratch / "doc.txt").write_text("x", encoding="utf-8")
    tool = GrepFileTool().bind_blackboard(bb)
    out = tool.invoke({"path": "doc.txt", "pattern": "[unclosed"})
    assert "Invalid regex" in out


def test_grep_file_caps_at_max_matches(tmp_path):
    bb, scratch = _bb_with_scratch(tmp_path)
    (scratch / "doc.txt").write_text("\n".join(["hit"] * 50), encoding="utf-8")
    tool = GrepFileTool().bind_blackboard(bb)
    out = tool.invoke({"path": "doc.txt", "pattern": "hit", "max_matches": 5})
    # The header reports the count with a '+' when capped.
    assert "matches=5+" in out


def test_grep_file_missing_blackboard_errors():
    tool = GrepFileTool()  # not bound
    out = tool.invoke({"path": "x.txt", "pattern": "y"})
    assert "scratch directory" in out
