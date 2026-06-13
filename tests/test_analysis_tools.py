"""Tests for read_source / record_finding and dispatcher history compaction."""
from __future__ import annotations

import json
from pathlib import Path

from langchain_core.messages import ToolMessage

from vapt_orchestrator_safe.engine.dispatcher import Dispatcher
from vapt_orchestrator_safe.memory.shared_memory import Blackboard
from vapt_orchestrator_safe.tools.analysis_tools import ReadSourceTool, RecordFindingTool


def _bb(tmp_path: Path, files) -> Blackboard:
    bb = Blackboard(run_id="t", run_dir=tmp_path)
    bb.set_phase_context("intake", {"source_files": files})
    return bb


def _payload(raw: str) -> dict:
    # BaseTool prepends a one-line header; the JSON body follows.
    return json.loads(raw.split("\n", 1)[1])


def test_read_source_batch_returns_all_files(tmp_path):
    files = [{"path": "a.py", "content": "x" * 5000},
             {"path": "b.py", "content": "y" * 5000},
             {"path": "c.py", "content": "z" * 100}]
    tool = ReadSourceTool(); tool.bind_blackboard(_bb(tmp_path, files))
    out = _payload(tool.invoke({}))
    assert out["mode"] == "all"
    assert out["count"] == 3
    assert {f["path"] for f in out["files"]} == {"a.py", "b.py", "c.py"}


def test_read_source_single_file_suffix_match(tmp_path):
    files = [{"path": "src/services/auth.py", "content": "SECRET=1"}]
    tool = ReadSourceTool(); tool.bind_blackboard(_bb(tmp_path, files))
    out = _payload(tool.invoke({"path": "auth.py"}))
    assert out["path"] == "src/services/auth.py"
    assert "SECRET=1" in out["content"]


def test_record_finding_accumulates_on_blackboard(tmp_path):
    bb = _bb(tmp_path, [])
    tool = RecordFindingTool(); tool.bind_blackboard(bb)
    tool.invoke({"vuln_class": "LFI", "location": "x.py", "description": "d", "severity": "high"})
    tool.invoke({"vuln_class": "SSRF", "location": "y.py", "description": "d2"})
    items = bb.get_phase_context("findings")["items"]
    assert [f["vuln_class"] for f in items] == ["LFI", "SSRF"]


def test_history_compaction_stubs_stale_big_tool_messages(tmp_path):
    d = Dispatcher.__new__(Dispatcher)
    d.history_compaction = True
    d.keep_recent_tool_msgs = 3
    d.compact_over_chars = 800
    msgs = [
        ToolMessage(content="BIG" * 1000, tool_call_id="t1"),  # stale + big -> stubbed
        ToolMessage(content="r" * 900, tool_call_id="t2"),     # stale + big -> stubbed
        ToolMessage(content="r3" * 500, tool_call_id="t3"),    # recent -> kept
        ToolMessage(content="r4" * 500, tool_call_id="t4"),    # recent -> kept
        ToolMessage(content="r5" * 500, tool_call_id="t5"),    # recent -> kept
    ]
    d._compact_history(msgs)
    assert msgs[0].content.startswith("[omitted")
    assert msgs[1].content.startswith("[omitted")
    assert not msgs[2].content.startswith("[omitted")  # recent kept full
    assert msgs[4].content == "r5" * 500


def test_history_compaction_disabled_is_noop(tmp_path):
    d = Dispatcher.__new__(Dispatcher)
    d.history_compaction = False
    d.keep_recent_tool_msgs = 3
    d.compact_over_chars = 800
    msgs = [ToolMessage(content="BIG" * 1000, tool_call_id="t1")]
    d._compact_history(msgs)
    assert msgs[0].content == "BIG" * 1000
