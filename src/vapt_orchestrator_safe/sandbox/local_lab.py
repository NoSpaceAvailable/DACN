from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from vapt_orchestrator_safe.sandbox.adapters import BaseLabAdapter
from vapt_orchestrator_safe.utils.io import iter_files, read_json, read_text
from vapt_orchestrator_safe.utils.safety import SafetyGuard


class LocalLabAdapter(BaseLabAdapter):
    def __init__(self, project_root: Path):
        self.guard = SafetyGuard(project_root)

    def load_manifest(self, fixture_dir: Path) -> Dict[str, Any]:
        path = self.guard.ensure_path(fixture_dir / "manifest.json")
        return read_json(path)

    def load_http_transcript(self, fixture_dir: Path) -> Dict[str, Any]:
        path = self.guard.ensure_path(fixture_dir / "transcripts" / "http.json")
        return read_json(path)

    _FAKE_FLAG = "FAKE_FLAG{redacted_solve_for_real_one}"

    def load_source_files(self, fixture_dir: Path) -> List[Dict[str, Any]]:
        source_root = self.guard.ensure_path(fixture_dir / "source")
        # Send every file the wrapper kept in source/ — wrapper strips solve
        # scripts / writeups / challenge.json. Any literal occurrence of the
        # real flag inside source is replaced with a placeholder so the agent
        # gets file structure + code logic without the answer.
        real_flag = ""
        gt_path = fixture_dir / "ground_truth.json"
        if gt_path.exists():
            try:
                real_flag = (read_json(gt_path).get("flag") or "").strip()
            except Exception:  # noqa: BLE001
                real_flag = ""
        files: List[Dict[str, Any]] = []
        for path in source_root.rglob("*"):
            if not path.is_file():
                continue
            try:
                content = read_text(path)
            except (UnicodeDecodeError, OSError):
                continue
            if real_flag and real_flag in content:
                content = content.replace(real_flag, self._FAKE_FLAG)
            files.append({"path": str(path.relative_to(fixture_dir)), "content": content})
        return files

    def load_ground_truth(self, fixture_dir: Path) -> Dict[str, Any]:
        path = self.guard.ensure_path(fixture_dir / "ground_truth.json")
        return read_json(path)
