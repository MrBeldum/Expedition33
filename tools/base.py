from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolResult:
    tool: str
    command: str | None
    ok: bool
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    structured: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    timed_out: bool = False
    duration: float = 0.0

    def concise_output(self, max_chars: int = 6000) -> str:
        parts: list[str] = []
        if self.stdout:
            parts.append("STDOUT:\n" + self.stdout[:max_chars])
        if self.stderr:
            parts.append("STDERR:\n" + self.stderr[: max_chars // 2])
        if self.error:
            parts.append("ERROR:\n" + self.error)
        return "\n\n".join(parts)[:max_chars]
