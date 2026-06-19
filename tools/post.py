from __future__ import annotations

import http.server
from functools import partial
import socketserver
import threading
from pathlib import Path
from typing import Any

from config import PathConfig, TimeoutConfig
from tools.base import ToolResult
from tools.shell import ShellRunner


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class PostTools:
    def __init__(self, runner: ShellRunner, timeouts: TimeoutConfig, paths: PathConfig):
        self.runner = runner
        self.timeouts = timeouts
        self.paths = paths

    def linpeas(self, path: str | None = None) -> ToolResult:
        script = Path(path) if path else self.paths.linpeas
        result = self.runner.run(["bash", str(script)], timeout=self.timeouts.linpeas)
        findings = _extract_interesting_lines(result.stdout)
        return _from_shell("linpeas", result, {"findings": findings})

    def winpeas(self, path: str | None = None) -> ToolResult:
        exe = Path(path) if path else self.paths.winpeas
        result = self.runner.run(["wine", str(exe)], timeout=self.timeouts.winpeas)
        findings = _extract_interesting_lines(result.stdout)
        return _from_shell("winpeas", result, {"findings": findings})

    def enum_linux(self) -> ToolResult:
        commands = [
            "id",
            "hostname",
            "uname -a",
            "sudo -l",
            "find / -perm -4000 -type f 2>/dev/null",
            "getcap -r / 2>/dev/null",
        ]
        # The command list is fixed by Expedition33, not model-controlled raw input.
        result = self.runner.run(["bash", "-lc", "; ".join(commands)], timeout=self.timeouts.shell_default)
        return _from_shell("enum_linux", result, {"findings": _extract_interesting_lines(result.stdout)})

    def start_http_server(self, directory: str, port: int = 8000) -> ToolResult:
        path = Path(directory)
        if not path.exists():
            return ToolResult(tool="http_server", command=None, ok=False, error=f"Directory not found: {directory}")
        handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(path))
        server = ReusableTCPServer(("0.0.0.0", port), handler)

        def serve() -> None:
            server.serve_forever()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return ToolResult(
            tool="http_server",
            command=f"python http.server {port} in {directory}",
            ok=True,
            structured={"url": f"http://0.0.0.0:{port}/", "directory": str(path)},
        )


def _extract_interesting_lines(text: str) -> list[str]:
    keywords = ("password", "passwd", "credential", "vulnerable", "suid", "capability", "token", "key", "flag")
    findings: list[str] = []
    for line in text.splitlines():
        lower = line.lower()
        if any(keyword in lower for keyword in keywords):
            findings.append(line[:500])
    return findings[:100]


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
