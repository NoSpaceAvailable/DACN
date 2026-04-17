from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List


class BaseLabAdapter(ABC):
    @abstractmethod
    def load_manifest(self, fixture_dir: Path) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def load_http_transcript(self, fixture_dir: Path) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def load_source_files(self, fixture_dir: Path) -> List[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def load_ground_truth(self, fixture_dir: Path) -> Dict[str, Any]:
        raise NotImplementedError
