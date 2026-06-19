from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any


class SessionLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def for_machine(cls, sessions_dir: Path, machine_name: str, date: str) -> "SessionLog":
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in machine_name)
        return cls(sessions_dir / f"{safe}_{date}.md")

    def initialize(self, machine: dict[str, Any]) -> None:
        if self.path.exists():
            return
        self.path.write_text(
            "# Expedition33 Session Log\n\n"
            f"- Machine: {machine.get('name', 'unknown')}\n"
            f"- IP: {machine.get('ip', 'unknown')}\n"
            f"- OS: {machine.get('os', 'unknown')}\n"
            f"- Difficulty: {machine.get('difficulty', 'unknown')}\n\n",
            encoding="utf-8",
        )

    def append_entry(
        self,
        phase: str,
        reasoning: str,
        command: str | None,
        stdout: str,
        stderr: str,
        flags: list[str] | None = None,
    ) -> None:
        timestamp = datetime.now().isoformat(timespec="seconds")
        parts = [f"\n## {timestamp} - {phase}\n", "### Reasoning\n", reasoning.strip(), "\n"]
        if command:
            parts.extend(["### Command\n", f"```bash\n{command}\n```\n"])
        if stdout:
            parts.extend(["### Stdout\n", "```text\n", _cap_lines(stdout, 500), "\n```\n"])
        if stderr:
            parts.extend(["### Stderr\n", "```text\n", _cap_lines(stderr, 200), "\n```\n"])
        if flags:
            parts.append("### Flags\n")
            parts.extend(f"- `{flag}`\n" for flag in flags)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("".join(parts))

    def append_summary(self, summary: str) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("\n# Session Summary\n\n")
            handle.write(summary.strip())
            handle.write("\n")


def _cap_lines(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[:max_lines]) + f"\n... truncated after {max_lines} lines"
