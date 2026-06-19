from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass
class ShellResult:
    args: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    timeout: int
    duration: float
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error

    @property
    def command(self) -> str:
        return " ".join(shlex.quote(arg) for arg in self.args)


class ShellRunner:
    def __init__(self, sudo: bool = True, interactive: bool = False):
        self.sudo = sudo
        self.interactive = interactive

    def run(
        self,
        args: Sequence[str],
        timeout: int,
        cwd: str | Path | None = None,
        sudo: bool | None = None,
        env: Mapping[str, str] | None = None,
        input_text: str | None = None,
    ) -> ShellResult:
        if not args:
            raise ValueError("Command args cannot be empty")

        command = [str(arg) for arg in args]
        use_sudo = self.sudo if sudo is None else sudo
        executable = command[0]
        if shutil.which(executable) is None and not Path(executable).exists():
            return ShellResult(
                args=command,
                returncode=127,
                stdout="",
                stderr=f"Tool not found: {executable}",
                timed_out=False,
                timeout=timeout,
                duration=0.0,
                error="tool_not_found",
            )

        if use_sudo and os.geteuid() != 0 and command[0] != "sudo":
            command = ["sudo", *command]

        if self.interactive and not _confirm(command):
            return ShellResult(
                args=command,
                returncode=None,
                stdout="",
                stderr="Command skipped by user",
                timed_out=False,
                timeout=timeout,
                duration=0.0,
                error="skipped",
            )

        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                env={**os.environ, **dict(env or {})},
                capture_output=True,
                text=True,
                input=input_text,
                timeout=timeout,
                check=False,
                errors="replace",
            )
            return ShellResult(
                args=command,
                returncode=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                timed_out=False,
                timeout=timeout,
                duration=time.monotonic() - started,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = _coerce_text(exc.stdout)
            stderr = _coerce_text(exc.stderr)
            return ShellResult(
                args=command,
                returncode=None,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
                timeout=timeout,
                duration=time.monotonic() - started,
                error="timeout",
            )
        except PermissionError as exc:
            return ShellResult(
                args=command,
                returncode=None,
                stdout="",
                stderr=str(exc),
                timed_out=False,
                timeout=timeout,
                duration=time.monotonic() - started,
                error="permission_denied",
            )
        except FileNotFoundError as exc:
            return ShellResult(
                args=command,
                returncode=127,
                stdout="",
                stderr=str(exc),
                timed_out=False,
                timeout=timeout,
                duration=time.monotonic() - started,
                error="tool_not_found",
            )

    def start_background(
        self,
        args: Sequence[str],
        cwd: str | Path | None = None,
        sudo: bool | None = None,
    ) -> subprocess.Popen[str]:
        command = [str(arg) for arg in args]
        use_sudo = self.sudo if sudo is None else sudo
        if use_sudo and os.geteuid() != 0 and command[0] != "sudo":
            command = ["sudo", *command]
        if self.interactive and not _confirm(command):
            raise RuntimeError("Command skipped by user")
        return subprocess.Popen(
            command,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )


def _coerce_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _confirm(command: Sequence[str]) -> bool:
    rendered = " ".join(shlex.quote(arg) for arg in command)
    answer = input(f"Run command? {rendered} [y/N] ").strip().lower()
    return answer in {"y", "yes"}
