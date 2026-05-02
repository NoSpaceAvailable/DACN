"""Z3ConstraintSolver -- SMT solver for crypto / token / nonce challenges.

Useful when the LLM encounters:

- Hash-prefix challenges (find ``x`` such that ``SHA256(x)`` starts with
  ``0000``).
- Token arithmetic (``HMAC(secret, counter+1) == known_value``).
- Integer-constraint puzzles that arise from brute-force-unfriendly param
  spaces (e.g. "find an invoice_id such that ``id % 7 == 3 AND id > 500``").

The tool accepts a small, structured constraint language (NOT arbitrary
Python) so it avoids ``eval`` entirely. Each constraint is a dict with
``{"var", "op", "value"}`` keys, and the tool translates them into Z3
assertions.

If the caller needs full Z3 expressiveness, they should use
``run_python_sandbox`` to write a z3 script instead.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Type

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult


class _Variable(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = Field(description="Variable name (alphanumeric + underscore).")
    type: str = Field(
        default="int",
        description="Variable type: 'int' or 'bitvec' (with optional bit width, e.g. 'bitvec32').",
    )


class _Constraint(BaseModel):
    model_config = ConfigDict(extra="ignore")
    var: str = Field(description="Variable name (left-hand side).")
    op: str = Field(
        description=(
            "Operator: '==', '!=', '>', '>=', '<', '<=', '%%' (modulo equals), "
            "'&' (bitwise AND equals), '|' (bitwise OR equals)."
        ),
    )
    value: int = Field(description="Right-hand side integer value.")
    mod_value: Optional[int] = Field(
        default=None,
        description="For op='%%': the modulus. Constraint becomes (var %% mod_value) == value.",
    )


class _Z3Args(BaseModel):
    model_config = ConfigDict(extra="ignore")
    variables: List[_Variable] = Field(
        description="List of variables to solve for.",
    )
    constraints: List[_Constraint] = Field(
        description="List of constraints over the declared variables.",
    )
    num_solutions: int = Field(
        default=1,
        description="Number of distinct solutions to find (max 10).",
    )
    timeout_ms: int = Field(
        default=5000,
        description="Z3 solver timeout in milliseconds (max 30000).",
    )


_ALLOWED_OPS = {"==", "!=", ">", ">=", "<", "<=", "%%", "&", "|"}
_MAX_SOLUTIONS = 10
_MAX_TIMEOUT_MS = 30000
_MAX_VARIABLES = 20
_MAX_CONSTRAINTS = 50


class Z3ConstraintSolver(BaseTool):
    name: str = "z3_solve"
    description: str = (
        "Solve integer / bit-vector constraints using Z3 SMT solver. "
        "Declare variables and constraints; get satisfying assignments. "
        "Useful for crypto puzzles, token arithmetic, and parameter-space "
        "search that is infeasible via brute force."
    )
    args_schema: Type[BaseModel] = _Z3Args

    def _invoke(self, **kwargs: Any) -> ToolResult:
        try:
            import z3
        except ImportError:
            return ToolResult(
                stderr="z3-solver package not installed. Install via: pip install z3-solver",
                exit_code=2,
                metadata={"error": "missing_dependency"},
            )

        variables_raw = kwargs.get("variables", [])
        constraints_raw = kwargs.get("constraints", [])
        num_solutions = min(max(int(kwargs.get("num_solutions", 1)), 1), _MAX_SOLUTIONS)
        timeout_ms = min(max(int(kwargs.get("timeout_ms", 5000)), 100), _MAX_TIMEOUT_MS)

        if len(variables_raw) > _MAX_VARIABLES:
            return ToolResult(stderr=f"Too many variables (max {_MAX_VARIABLES})", exit_code=2)
        if len(constraints_raw) > _MAX_CONSTRAINTS:
            return ToolResult(stderr=f"Too many constraints (max {_MAX_CONSTRAINTS})", exit_code=2)
        if not variables_raw:
            return ToolResult(stderr="At least one variable required", exit_code=2)
        if not constraints_raw:
            return ToolResult(stderr="At least one constraint required", exit_code=2)

        z3_vars: Dict[str, Any] = {}
        for v in variables_raw:
            vname = v.get("name") if isinstance(v, dict) else v.name
            vtype = v.get("type", "int") if isinstance(v, dict) else v.type
            if not vname or not vname.replace("_", "").isalnum():
                return ToolResult(stderr=f"Invalid variable name: {vname!r}", exit_code=2)
            if vtype == "int":
                z3_vars[vname] = z3.Int(vname)
            elif vtype.startswith("bitvec"):
                bits_str = vtype.replace("bitvec", "") or "32"
                try:
                    bits = int(bits_str)
                except ValueError:
                    return ToolResult(stderr=f"Invalid bitvec width: {vtype!r}", exit_code=2)
                z3_vars[vname] = z3.BitVec(vname, bits)
            else:
                return ToolResult(stderr=f"Unknown variable type: {vtype!r}. Use 'int' or 'bitvec<N>'.", exit_code=2)

        solver = z3.Solver()
        solver.set("timeout", timeout_ms)

        for c in constraints_raw:
            var_name = c.get("var") if isinstance(c, dict) else c.var
            op = c.get("op") if isinstance(c, dict) else c.op
            value = c.get("value") if isinstance(c, dict) else c.value
            mod_value = c.get("mod_value") if isinstance(c, dict) else c.mod_value

            if var_name not in z3_vars:
                return ToolResult(stderr=f"Unknown variable in constraint: {var_name!r}", exit_code=2)
            if op not in _ALLOWED_OPS:
                return ToolResult(stderr=f"Unknown operator: {op!r}", exit_code=2)

            z3var = z3_vars[var_name]
            value = int(value)

            try:
                expr = _build_constraint(z3var, op, value, mod_value)
            except ValueError as exc:
                return ToolResult(stderr=str(exc), exit_code=2)
            solver.add(expr)

        solutions: List[Dict[str, int]] = []
        for _ in range(num_solutions):
            check = solver.check()
            if check == z3.sat:
                model = solver.model()
                sol = {}
                for vname, zvar in z3_vars.items():
                    val = model[zvar]
                    sol[vname] = val.as_long() if val is not None else None
                solutions.append(sol)
                block = z3.Or([zvar != model[zvar] for vname, zvar in z3_vars.items()
                               if model[zvar] is not None])
                solver.add(block)
            elif check == z3.unknown:
                break
            else:
                break

        status = "sat" if solutions else ("timeout" if solver.check() == z3.unknown else "unsat")

        payload = {
            "status": status,
            "num_solutions": len(solutions),
            "solutions": solutions,
            "variables": [
                {"name": v.get("name") if isinstance(v, dict) else v.name,
                 "type": v.get("type", "int") if isinstance(v, dict) else v.type}
                for v in variables_raw
            ],
        }

        return ToolResult(
            stdout=json.dumps(payload, ensure_ascii=False),
            exit_code=0 if solutions else 1,
            metadata={"status": status, "num_solutions": len(solutions)},
        )


def _build_constraint(z3var, op: str, value: int, mod_value: Optional[int]):
    if op == "==":
        return z3var == value
    elif op == "!=":
        return z3var != value
    elif op == ">":
        return z3var > value
    elif op == ">=":
        return z3var >= value
    elif op == "<":
        return z3var < value
    elif op == "<=":
        return z3var <= value
    elif op == "%%":
        if mod_value is None or mod_value == 0:
            raise ValueError("op='%%' requires a non-zero mod_value")
        return z3var % int(mod_value) == value
    elif op == "&":
        return z3var & value == value
    elif op == "|":
        return z3var | value == value
    else:
        raise ValueError(f"Unsupported operator: {op!r}")
