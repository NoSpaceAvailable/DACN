"""Z3ConstraintSolver tests -- structured constraint solving without eval."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from vapt_orchestrator_safe.memory.shared_memory import Blackboard

z3_available = True
try:
    import z3
except ImportError:
    z3_available = False

from vapt_orchestrator_safe.tools.security.z3_solver import Z3ConstraintSolver

skip_no_z3 = pytest.mark.skipif(not z3_available, reason="z3-solver not installed")


def _bb(tmp_path: Path) -> Blackboard:
    return Blackboard(run_id="t", run_dir=tmp_path)


def _parse(out: str) -> dict:
    return json.loads(out.split("\n", 1)[1])


# ── happy path ───────────────────────────────────────────────────────────
@skip_no_z3
def test_simple_integer_sat(tmp_path):
    bb = _bb(tmp_path)
    tool = Z3ConstraintSolver().bind_blackboard(bb)
    out = tool.invoke({
        "variables": [{"name": "x", "type": "int"}],
        "constraints": [
            {"var": "x", "op": ">", "value": 10},
            {"var": "x", "op": "<", "value": 15},
        ],
    })
    assert "exit=0" in out
    payload = _parse(out)
    assert payload["status"] == "sat"
    assert payload["num_solutions"] == 1
    x = payload["solutions"][0]["x"]
    assert 10 < x < 15


@skip_no_z3
def test_multiple_solutions():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [{"name": "x", "type": "int"}],
        "constraints": [
            {"var": "x", "op": ">=", "value": 1},
            {"var": "x", "op": "<=", "value": 5},
        ],
        "num_solutions": 5,
    })
    payload = _parse(out)
    assert payload["num_solutions"] == 5
    xs = sorted(s["x"] for s in payload["solutions"])
    assert xs == [1, 2, 3, 4, 5]


@skip_no_z3
def test_modulo_constraint():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [{"name": "id", "type": "int"}],
        "constraints": [
            {"var": "id", "op": "%%", "value": 3, "mod_value": 7},
            {"var": "id", "op": ">", "value": 500},
            {"var": "id", "op": "<", "value": 520},
        ],
        "num_solutions": 3,
    })
    payload = _parse(out)
    assert payload["status"] == "sat"
    for sol in payload["solutions"]:
        assert sol["id"] % 7 == 3
        assert 500 < sol["id"] < 520


@skip_no_z3
def test_two_variables():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [
            {"name": "a", "type": "int"},
            {"name": "b", "type": "int"},
        ],
        "constraints": [
            {"var": "a", "op": ">", "value": 0},
            {"var": "b", "op": ">", "value": 0},
            {"var": "a", "op": "<", "value": 10},
            {"var": "b", "op": "<=", "value": 5},
        ],
    })
    payload = _parse(out)
    assert payload["status"] == "sat"
    sol = payload["solutions"][0]
    assert 0 < sol["a"] < 10
    assert 0 < sol["b"] <= 5


@skip_no_z3
def test_bitvec_constraint():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [{"name": "x", "type": "bitvec8"}],
        "constraints": [
            {"var": "x", "op": "&", "value": 0x0F},
            {"var": "x", "op": ">", "value": 0},
        ],
    })
    payload = _parse(out)
    assert payload["status"] == "sat"
    x = payload["solutions"][0]["x"]
    assert x & 0x0F == 0x0F


# ── unsat ────────────────────────────────────────────────────────────────
@skip_no_z3
def test_unsatisfiable_returns_exit_1():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [{"name": "x", "type": "int"}],
        "constraints": [
            {"var": "x", "op": ">", "value": 100},
            {"var": "x", "op": "<", "value": 50},
        ],
    })
    assert "exit=1" in out
    payload = _parse(out)
    assert payload["status"] == "unsat"
    assert payload["num_solutions"] == 0


# ── validation errors ────────────────────────────────────────────────────
@skip_no_z3
def test_unknown_variable_in_constraint():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [{"name": "x", "type": "int"}],
        "constraints": [
            {"var": "y", "op": ">", "value": 0},
        ],
    })
    assert "exit=2" in out
    assert "Unknown variable" in out


@skip_no_z3
def test_invalid_operator():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [{"name": "x", "type": "int"}],
        "constraints": [
            {"var": "x", "op": "**", "value": 2},
        ],
    })
    assert "exit=2" in out


@skip_no_z3
def test_no_variables_returns_error():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [],
        "constraints": [{"var": "x", "op": ">", "value": 0}],
    })
    assert "exit=2" in out


@skip_no_z3
def test_no_constraints_returns_error():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [{"name": "x", "type": "int"}],
        "constraints": [],
    })
    assert "exit=2" in out


@skip_no_z3
def test_modulo_without_mod_value_errors():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [{"name": "x", "type": "int"}],
        "constraints": [
            {"var": "x", "op": "%%", "value": 3},
        ],
    })
    assert "exit=2" in out
    assert "mod_value" in out


@skip_no_z3
def test_invalid_variable_type():
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [{"name": "x", "type": "float"}],
        "constraints": [{"var": "x", "op": ">", "value": 0}],
    })
    assert "exit=2" in out


# ── missing z3 graceful degradation ──────────────────────────────────────
def test_graceful_when_z3_missing(monkeypatch):
    """Even when z3 is installed, verify the import-check code path."""
    import vapt_orchestrator_safe.tools.security.z3_solver as mod

    original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

    def fake_import(name, *args, **kwargs):
        if name == "z3":
            raise ImportError("fake missing z3")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    tool = Z3ConstraintSolver()
    out = tool.invoke({
        "variables": [{"name": "x", "type": "int"}],
        "constraints": [{"var": "x", "op": ">", "value": 0}],
    })
    assert "exit=2" in out
    assert "z3-solver" in out


# ── blackboard recording ────────────────────────────────────────────────
@skip_no_z3
def test_z3_records_artifact(tmp_path):
    bb = _bb(tmp_path)
    tool = Z3ConstraintSolver().bind_blackboard(bb)
    tool.invoke({
        "variables": [{"name": "x", "type": "int"}],
        "constraints": [{"var": "x", "op": "==", "value": 42}],
    })
    assert len(bb.artifacts) == 1
    assert bb.artifacts[0]["kind"] == "tool:z3_solve"
