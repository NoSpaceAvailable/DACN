"""Tool layer.

Concrete tools (NmapTool, CurlTool, etc.) land in Sprint 4. This package
exposes only the base abstractions in Sprint 2.
"""
from vapt_orchestrator_safe.tools.base import BaseTool, ToolResult, ToolError

__all__ = ["BaseTool", "ToolResult", "ToolError"]
