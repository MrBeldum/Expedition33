from __future__ import annotations

import json
from pathlib import Path

from agent.llm import LLMClient
from agent.prompts.writeup import WRITEUP_PROMPT
from db.session import SessionDB, SessionRecord


class WriteupGenerator:
    def __init__(self, db: SessionDB, llm: LLMClient | None, writeups_dir: Path, sessions_dir: Path):
        self.db = db
        self.llm = llm
        self.writeups_dir = writeups_dir
        self.sessions_dir = sessions_dir
        self.writeups_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, session: SessionRecord) -> Path:
        context = self.db.context(session.id)
        log_path = self._session_log_path(session)
        session_log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        prompt = (
            f"Structured context:\n```json\n{json.dumps(context, indent=2, sort_keys=True, default=str)[:120000]}\n```\n\n"
            f"Session log:\n```markdown\n{session_log[:120000]}\n```"
        )
        if self.llm:
            response = self.llm.provider.complete(WRITEUP_PROMPT, prompt)
            markdown = response.text if response.text and not response.rejected_tool_use else self._fallback_writeup(context, session_log)
        else:
            markdown = self._fallback_writeup(context, session_log)
        output = self.writeups_dir / f"{_safe(session.machine_name)}_writeup.md"
        output.write_text(markdown.strip() + "\n", encoding="utf-8")
        return output

    def _session_log_path(self, session: SessionRecord) -> Path:
        return self.sessions_dir / f"{_safe(session.machine_name)}_{session.date}.md"

    def _fallback_writeup(self, context: dict, session_log: str) -> str:
        machine = context.get("session", {})
        ports = context.get("ports", [])
        flags = context.get("flags", [])
        return (
            f"# {machine.get('machine_name', 'Machine')} Writeup\n\n"
            "## Enumeration\n\n"
            f"Discovered ports:\n\n{json.dumps(ports, indent=2)}\n\n"
            "## Foothold\n\nSee session log for exploitation details.\n\n"
            "## Privilege Escalation\n\nSee session log for privilege escalation details.\n\n"
            "## Flags\n\n"
            + "\n".join(f"- {flag.get('flag_type') or 'unknown'}: `{flag.get('value')}`" for flag in flags)
            + "\n\n## Key Takeaways\n\nReview the command timeline and dead ends in the session log.\n\n"
            + "## Session Log Excerpt\n\n"
            + session_log[:20000]
        )


def _safe(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)
