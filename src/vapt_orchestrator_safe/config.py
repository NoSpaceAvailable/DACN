from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class LoadedProfiles:
    profiles: Dict[str, Dict[str, Any]]
    profile_sets: Dict[str, Dict[str, str]]


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROFILES = ROOT / "configs" / "model_profiles.json"
DEFAULT_SKILLS = ROOT / "configs" / "system_skills.json"
DEFAULT_KB = ROOT / "data" / "kb"
DEFAULT_FIXTURES = ROOT / "data" / "fixtures"
DEFAULT_OUTPUTS = ROOT / "outputs"


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_profiles(path: Path | None = None) -> LoadedProfiles:
    config_path = path or DEFAULT_PROFILES
    data = load_json(config_path)
    return LoadedProfiles(profiles=data["profiles"], profile_sets=data["profile_sets"])


# ── Ollama env loading ───────────────────────────────────────────────────────
def _load_dotenv_if_present() -> None:
    """Best-effort .env / .env.local loader. No external dep.

    Looks for .env.local then .env at repo root. Keys already in os.environ
    win, so user shell exports always override the file.
    """
    for name in (".env.local", ".env"):
        path = ROOT / name
        if not path.exists():
            continue
        try:
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
        except OSError:
            continue


def get_ollama_env() -> Dict[str, Optional[str]]:
    """Read OLLAMA_* env vars (loading .env files as a fallback)."""
    _load_dotenv_if_present()
    return {
        "base_url": os.environ.get("OLLAMA_BASE_URL"),
        "token": os.environ.get("OLLAMA_TOKEN"),
        "timeout": os.environ.get("OLLAMA_TIMEOUT"),
    }
