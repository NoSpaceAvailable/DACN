"""LiveLab — boot a challenge's docker-compose, wait until reachable, tear down.

This enables the *live exploit* phase: instead of analysing an offline source
snapshot, the agent's HTTP tools talk to a real running instance of the
challenge and try to capture the flag.

A fixture opts in via a ``live`` block in its ``manifest.json``::

    "live": {
        "compose_file": "docker-compose.yml",   // relative to the fixture dir
        "target_url":   "http://127.0.0.1:8099", // where the service is exposed
        "ready_path":   "/",                      // polled until HTTP responds
        "ready_timeout_s": 60
    }

Safety: the compose file is expected to bind only to ``127.0.0.1`` (local lab).
LiveLab does not open any egress; it merely starts/stops the target container.
"""
from __future__ import annotations

import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class LiveLabError(RuntimeError):
    pass


@dataclass
class LiveTarget:
    target_url: str
    project: str
    compose_file: Path


class LiveLab:
    """Start/stop a challenge stack via ``docker compose`` (or ``podman``)."""

    def __init__(self, docker_bin: str = "docker", compose_subcmd: str = "compose"):
        self.docker_bin = docker_bin
        self.compose_subcmd = compose_subcmd
        self._target: Optional[LiveTarget] = None

    # ── lifecycle ─────────────────────────────────────────────────────────
    def launch(
        self,
        fixture_dir: Path,
        *,
        compose_file: str,
        target_url: str,
        ready_path: str = "/",
        ready_timeout_s: int = 60,
        build_timeout_s: int = 600,
    ) -> LiveTarget:
        fixture_dir = Path(fixture_dir).resolve()
        compose_path = (fixture_dir / compose_file).resolve()
        if not compose_path.exists():
            raise LiveLabError(f"compose file not found: {compose_path}")

        # Deterministic, fixture-scoped project name so teardown is exact.
        project = f"dacnlive_{fixture_dir.name}".lower().replace(" ", "_")

        up = subprocess.run(
            [self.docker_bin, self.compose_subcmd, "-f", str(compose_path),
             "-p", project, "up", "-d", "--build"],
            cwd=str(fixture_dir),
            capture_output=True, text=True, timeout=build_timeout_s,
        )
        if up.returncode != 0:
            raise LiveLabError(f"compose up failed (exit {up.returncode}):\n{up.stderr[-2000:]}")

        self._target = LiveTarget(target_url=target_url, project=project, compose_file=compose_path)

        ready_url = target_url.rstrip("/") + "/" + ready_path.lstrip("/")
        if not self._wait_ready(ready_url, ready_timeout_s):
            logs = self._logs(project, compose_path, fixture_dir)
            self.teardown()
            raise LiveLabError(
                f"target {ready_url} not reachable within {ready_timeout_s}s.\nLogs tail:\n{logs[-2000:]}"
            )
        return self._target

    def teardown(self) -> None:
        if self._target is None:
            return
        subprocess.run(
            [self.docker_bin, self.compose_subcmd, "-f", str(self._target.compose_file),
             "-p", self._target.project, "down", "-v", "--remove-orphans"],
            capture_output=True, text=True, timeout=120,
        )
        self._target = None

    # ── helpers ───────────────────────────────────────────────────────────
    @staticmethod
    def _wait_ready(url: str, timeout_s: int) -> bool:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=3) as resp:
                    if resp.status < 500:
                        return True
            except Exception:
                pass
            time.sleep(1.0)
        return False

    def _logs(self, project: str, compose_file: Path, cwd: Path) -> str:
        try:
            out = subprocess.run(
                [self.docker_bin, self.compose_subcmd, "-f", str(compose_file),
                 "-p", project, "logs", "--tail", "40"],
                cwd=str(cwd), capture_output=True, text=True, timeout=30,
            )
            return out.stdout + out.stderr
        except Exception:
            return "(could not fetch logs)"

    # ── context manager ───────────────────────────────────────────────────
    def __enter__(self) -> "LiveLab":
        return self

    def __exit__(self, *exc) -> None:
        self.teardown()
