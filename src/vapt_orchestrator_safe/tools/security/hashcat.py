"""HashcatTool -- password / hash cracking via hashcat binary.

Wraps the ``hashcat`` CLI with conservative defaults. No scope gating
needed since hashcat is purely local computation (no network I/O).

Supports dictionary attacks (mode 0), combinator (mode 1), and
rule-based (mode 0 + rules). Brute-force / mask attacks are
intentionally excluded to cap runtime.

The tool caps wall-clock time at ``default_timeout`` (120 s) and passes
``--runtime`` to hashcat so it self-terminates cleanly. On a CPU-only
VPS this limits feasibility to small wordlists or weak hashes, which
is exactly the lab scenario.
"""
from __future__ import annotations

from typing import Any, List, Optional, Sequence, Type

from pydantic import BaseModel, ConfigDict, Field

from vapt_orchestrator_safe.tools.shell import ShellTool


_ALLOWED_MODES = {0, 1}

_COMMON_HASH_TYPES = {
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "sha512": 1700,
    "bcrypt": 3200,
    "ntlm": 1000,
    "mysql": 300,
    "sha1_raw": 100,
}


class _HashcatArgs(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hash_value: str = Field(
        description="The hash to crack (single hash string).",
    )
    hash_type: str = Field(
        default="md5",
        description=(
            "Hash type: 'md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'ntlm', "
            "'mysql', or a numeric hashcat mode id."
        ),
    )
    wordlist: str = Field(
        default="/usr/share/wordlists/rockyou.txt",
        description="Path to the wordlist file.",
    )
    attack_mode: int = Field(
        default=0,
        description="Hashcat attack mode: 0 (dictionary), 1 (combinator).",
    )
    rules: Optional[str] = Field(
        default=None,
        description="Path to a hashcat rule file (e.g. /usr/share/hashcat/rules/best64.rule).",
    )
    max_runtime: int = Field(
        default=60,
        description="Hashcat --runtime cap in seconds (max 120).",
    )


class HashcatTool(ShellTool):
    name: str = "hashcat_crack"
    description: str = (
        "Attempt to crack a password hash using hashcat with a dictionary "
        "attack. Supports md5, sha1, sha256, sha512, bcrypt, ntlm, mysql. "
        "Returns cracked plaintext if found. CPU-only; best for weak "
        "passwords and small wordlists."
    )
    args_schema: Type[BaseModel] = _HashcatArgs
    binary: str = "hashcat"
    default_timeout: int = 180

    def build_argv(self, **kwargs: Any) -> Sequence[str]:
        hash_value: str = kwargs["hash_value"]
        hash_type_raw: str = str(kwargs.get("hash_type", "md5")).lower()
        attack_mode: int = int(kwargs.get("attack_mode", 0))
        wordlist: str = kwargs.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        rules: Optional[str] = kwargs.get("rules")
        max_runtime: int = min(int(kwargs.get("max_runtime", 60)), 120)

        if attack_mode not in _ALLOWED_MODES:
            raise ValueError(f"Attack mode {attack_mode} not allowed; use 0 (dictionary) or 1 (combinator)")

        if hash_type_raw in _COMMON_HASH_TYPES:
            mode_id = _COMMON_HASH_TYPES[hash_type_raw]
        else:
            try:
                mode_id = int(hash_type_raw)
            except ValueError:
                raise ValueError(
                    f"Unknown hash_type {hash_type_raw!r}. "
                    f"Use one of {sorted(_COMMON_HASH_TYPES)} or a numeric mode."
                )

        argv: List[str] = [
            self.binary,
            "--quiet",
            "--potfile-disable",
            "-m", str(mode_id),
            "-a", str(attack_mode),
            "--runtime", str(max_runtime),
            "-O",
            hash_value,
            wordlist,
        ]

        if rules is not None and attack_mode == 0:
            argv.extend(["-r", rules])

        return argv
