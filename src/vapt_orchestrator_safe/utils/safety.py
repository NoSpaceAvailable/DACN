from __future__ import annotations

from pathlib import Path


class SafetyError(RuntimeError):
    """Raised when an unsafe operation is requested."""


class SafetyGuard:
    def __init__(self, allowed_root: Path):
        self.allowed_root = allowed_root.resolve()

    def ensure_path(self, path: Path) -> Path:
        resolved = path.resolve()
        if self.allowed_root not in resolved.parents and resolved != self.allowed_root:
            raise SafetyError(f"Path outside allowed root: {resolved}")
        return resolved

    def ensure_local_fixture_only(self, target: str) -> None:
        lowered = target.lower()
        blocked = ["http://", "https://", "ftp://"]
        if any(lowered.startswith(prefix) for prefix in blocked):
            raise SafetyError(
                "Only offline fixture inputs are allowed in the safe lab scaffold."
            )
