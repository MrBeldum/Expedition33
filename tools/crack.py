from __future__ import annotations

from typing import Any

from config import PathConfig, TimeoutConfig
from tools.base import ToolResult
from tools.shell import ShellRunner


class CrackTools:
    def __init__(self, runner: ShellRunner, timeouts: TimeoutConfig, paths: PathConfig):
        self.runner = runner
        self.timeouts = timeouts
        self.paths = paths

    def john(self, hash_file: str, wordlist: str | None = None, format_name: str | None = None) -> ToolResult:
        args = ["john", "--wordlist", wordlist or str(self.paths.rockyou)]
        if format_name:
            args.append(f"--format={format_name}")
        args.append(hash_file)
        result = self.runner.run(args, timeout=self.timeouts.john)
        show = self.runner.run(["john", "--show", hash_file], timeout=30)
        stdout = result.stdout + "\n" + show.stdout
        return ToolResult(
            tool="john",
            command=result.command,
            ok=result.ok or bool(show.stdout.strip()),
            returncode=result.returncode,
            stdout=stdout,
            stderr=result.stderr + show.stderr,
            structured={"cracked": _parse_john_show(show.stdout)},
            error=result.error,
            timed_out=result.timed_out,
            duration=result.duration,
        )

    def hashcat(self, hash_file: str, mode: int, wordlist: str | None = None) -> ToolResult:
        args = ["hashcat", "-m", str(mode), hash_file, wordlist or str(self.paths.rockyou), "--potfile-disable"]
        result = self.runner.run(args, timeout=self.timeouts.hashcat)
        return _from_shell("hashcat", result, {"note": "hashcat output parsing is left to the planner summary"})

    def hydra(
        self,
        target: str,
        service: str,
        username: str | None = None,
        username_file: str | None = None,
        password: str | None = None,
        password_file: str | None = None,
        extra: list[str] | None = None,
    ) -> ToolResult:
        if not (username or username_file) or not (password or password_file):
            return ToolResult(
                tool="hydra",
                command=None,
                ok=False,
                error="Hydra requires concrete username/password context; speculative brute force is blocked.",
            )
        args = ["hydra"]
        if username:
            args.extend(["-l", username])
        if username_file:
            args.extend(["-L", username_file])
        if password:
            args.extend(["-p", password])
        if password_file:
            args.extend(["-P", password_file])
        if extra:
            args.extend(extra)
        args.extend([target, service])
        result = self.runner.run(args, timeout=self.timeouts.hydra)
        credentials = _parse_hydra(result.stdout)
        return _from_shell("hydra", result, {"credentials": credentials})


def _parse_john_show(text: str) -> list[dict[str, str]]:
    cracked: list[dict[str, str]] = []
    for line in text.splitlines():
        if ":" in line and not line.endswith("password hashes cracked"):
            user, secret, *_ = line.split(":")
            cracked.append({"username": user or None, "secret": secret})
    return cracked


def _parse_hydra(text: str) -> list[dict[str, str]]:
    credentials: list[dict[str, str]] = []
    for line in text.splitlines():
        if "login:" in line and "password:" in line:
            parts = line.split()
            login = None
            password = None
            for index, part in enumerate(parts):
                if part == "login:" and index + 1 < len(parts):
                    login = parts[index + 1]
                if part == "password:" and index + 1 < len(parts):
                    password = parts[index + 1]
            if password:
                credentials.append({"username": login, "secret": password})
    return credentials


def _from_shell(tool: str, result: Any, structured: dict[str, Any]) -> ToolResult:
    return ToolResult(
        tool=tool,
        command=result.command,
        ok=result.ok,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        structured=structured,
        error=result.error,
        timed_out=result.timed_out,
        duration=result.duration,
    )
