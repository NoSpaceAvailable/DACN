from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict


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
