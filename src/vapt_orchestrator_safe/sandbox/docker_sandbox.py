"""DockerSandbox — ephemeral per-job container for running untrusted code.

Matches the MAPTA ``Sandbox(N)`` pattern: one container per job, killed
at completion. Defaults to ``--network=none`` and read-only root so a
malicious (or confused) LLM-generated script can't reach anything that
isn't explicitly wired up.

Design choices:

- Pure subprocess on the ``docker`` CLI, no docker-py dependency. Keeps
  the image surface area small and lets users swap Podman without
  changing code (``DOCKER_BIN=podman`` env override).
- Source code is passed via a host-mounted tmp dir (ro-bind) rather than
  ``docker cp`` — one fewer step, simpler semantics.
- Timeout enforced at ``subprocess.run(timeout=...)`` layer; if the
  container outlives it, we issue ``docker kill`` so the tool returns
  cleanly instead of blocking.
- Container name is deterministic-per-invocation
  (``dacn-sbx-<run_id>-<n>``) so a crashed orchestrator leaves no
  zombie, and repeated runs of the tool inside the same pipeline are
  trivially traceable.

This module is imported lazily by the tool; if docker isn't installed
the tool returns a clear error instead of crashing at import.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence


_DEFAULT_IMAGE = "python:3.11-slim"
_DEFAULT_TIMEOUT = 20
_DEFAULT_CPU = "0.5"
_DEFAULT_MEM = "256m"


class SandboxError(RuntimeError):
    """Raised when the sandbox cannot start (docker missing, image pull failed, ...)."""


@dataclass
class SandboxResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    container: str
    network: str
    timed_out: bool = False
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class DockerSandbox:
    image: str = _DEFAULT_IMAGE
    network: str = "none"           # set "bridge" or a custom network for dynamic fixtures
    cpu_limit: str = _DEFAULT_CPU
    mem_limit: str = _DEFAULT_MEM
    default_timeout: int = _DEFAULT_TIMEOUT
    docker_bin: str = field(default_factory=lambda: os.environ.get("DOCKER_BIN", "docker"))

    # ── public ───────────────────────────────────────────────────────────
    def run_python(
        self,
        script: str,
        *,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        extra_args: Sequence[str] = (),
        container_name: Optional[str] = None,
    ) -> SandboxResult:
        """Execute ``script`` as ``python -c`` inside a throwaway container."""
        self._ensure_docker_available()
        container = container_name or f"dacn-sbx-{uuid.uuid4().hex[:10]}"
        t = int(timeout if timeout is not None else self.default_timeout)

        with tempfile.TemporaryDirectory(prefix="dacn-sbx-") as td:
            script_path = Path(td) / "main.py"
            script_path.write_text(textwrap.dedent(script), encoding="utf-8")

            argv: List[str] = [
                self.docker_bin, "run",
                "--rm",
                "--name", container,
                f"--network={self.network}",
                "--read-only",
                "--tmpfs", "/tmp:size=32m,mode=1777",
                "--cpus", self.cpu_limit,
                "--memory", self.mem_limit,
                "--pids-limit", "64",
                "--security-opt", "no-new-privileges:true",
                "-v", f"{td}:/sandbox:ro",
                "-w", "/sandbox",
            ]
            for key, value in (env or {}).items():
                argv.extend(["-e", f"{key}={value}"])
            argv.extend(extra_args)
            argv.extend([self.image, "python", "/sandbox/main.py"])

            started = time.perf_counter()
            timed_out = False
            try:
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=t,
                    check=False,
                )
                stdout, stderr, exit_code = proc.stdout, proc.stderr, proc.returncode
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                # Kill container if it outlived Popen's wait; best-effort.
                subprocess.run(
                    [self.docker_bin, "kill", container],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
                stderr = f"TIMEOUT after {t}s; container killed"
                exit_code = 124

            duration_ms = int((time.perf_counter() - started) * 1000)
            return SandboxResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration_ms=duration_ms,
                container=container,
                network=self.network,
                timed_out=timed_out,
                metadata={"image": self.image, "cpu": self.cpu_limit, "mem": self.mem_limit},
            )

    # ── internals ────────────────────────────────────────────────────────
    def _ensure_docker_available(self) -> None:
        if shutil.which(self.docker_bin) is None:
            raise SandboxError(
                f"Docker binary {self.docker_bin!r} not found on PATH. "
                f"Install Docker/Podman or set DOCKER_BIN."
            )
