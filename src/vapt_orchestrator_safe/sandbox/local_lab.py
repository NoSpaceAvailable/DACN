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

    def load_source_files(self, fixture_dir: Path) -> List[Dict[str, Any]]:
        source_root = self.guard.ensure_path(fixture_dir / "source")
        files: List[Dict[str, Any]] = []
        for path in iter_files(source_root, suffixes={".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".conf"}):
            files.append({"path": str(path.relative_to(fixture_dir)), "content": read_text(path)})
        return files

    def load_ground_truth(self, fixture_dir: Path) -> Dict[str, Any]:
        path = self.guard.ensure_path(fixture_dir / "ground_truth.json")
        return read_json(path)
