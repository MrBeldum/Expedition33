from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from db.session import SessionDB


@dataclass
class SessionContext:
    data: dict[str, Any]

    @classmethod
    def load(cls, db: SessionDB, session_id: str) -> "SessionContext":
        return cls(db.context(session_id))

    @property
    def machine_ip(self) -> str | None:
        return self.data.get("session", {}).get("machine_ip")

    @property
    def phase(self) -> str:
        return self.data.get("session", {}).get("phase", "recon")

    @property
    def machine_name(self) -> str:
        return self.data.get("session", {}).get("machine_name", "unknown")

    def to_prompt(self) -> str:
        compact = {
            "machine": {
                "name": self.machine_name,
                "ip": self.machine_ip,
                "os": self.data.get("session", {}).get("os"),
                "difficulty": self.data.get("session", {}).get("difficulty"),
                "status": self.data.get("session", {}).get("status"),
                "phase": self.phase,
            },
            "ports": self.data.get("ports", []),
            "vhosts": self.data.get("vhosts", []),
            "web_paths": self.data.get("web_paths", []),
            "credentials": self.data.get("credentials", []),
            "flags": self.data.get("flags", []),
            "attempted_vectors": self.data.get("vectors", [])[-20:],
            "recent_reasoning": self.data.get("recent_reasoning", [])[:10],
            "recent_outputs": self.data.get("recent_outputs", [])[:3],
        }
        return json.dumps(compact, indent=2, sort_keys=True, default=str)
