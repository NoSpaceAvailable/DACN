"""Prompt templates loaded from .md files in this package.

Templates use ``$variable`` syntax (string.Template) so that JSON braces
in the prompt body don't conflict with .format() escaping rules.
"""
from __future__ import annotations

from pathlib import Path
from string import Template
from typing import Any

_PROMPTS_DIR = Path(__file__).resolve().parent
_CACHE: dict[str, str] = {}


def load_prompt(name: str) -> str:
    """Return the raw text of prompts/<name>.md."""
    if name not in _CACHE:
        path = _PROMPTS_DIR / f"{name}.md"
        if not path.exists():
            raise FileNotFoundError(f"Prompt not found: {path}")
        _CACHE[name] = path.read_text(encoding="utf-8")
    return _CACHE[name]


def render_prompt(name: str, **vars: Any) -> str:
    """Load prompt template and substitute ${var} placeholders."""
    return Template(load_prompt(name)).safe_substitute(**vars)
