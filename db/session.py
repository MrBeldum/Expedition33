from __future__ import annotations

import base64
import json
import sqlite3
import uuid
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


COMPRESS_THRESHOLD = 100 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class SessionRecord:
    id: str
    session_key: str
    machine_name: str
    date: str
    status: str
    phase: str
    machine_ip: str | None = None
    machine_id: int | None = None
    os: str | None = None
    difficulty: str | None = None
    created_at: str = ""
    updated_at: str = ""


class SessionDB:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    session_key TEXT UNIQUE NOT NULL,
                    machine_name TEXT NOT NULL,
                    date TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'running',
                    phase TEXT NOT NULL DEFAULT 'recon',
                    machine_ip TEXT,
                    machine_id INTEGER,
                    os TEXT,
                    difficulty TEXT,
                    points INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service TEXT,
                    product TEXT,
                    version TEXT,
                    state TEXT,
                    raw_json TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(session_id, port, protocol)
                );

                CREATE TABLE IF NOT EXISTS vhosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    hostname TEXT NOT NULL,
                    ip TEXT,
                    source TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(session_id, hostname)
                );

                CREATE TABLE IF NOT EXISTS web_paths (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    url TEXT NOT NULL,
                    status_code INTEGER,
                    length INTEGER,
                    source TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(session_id, url)
                );

                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    username TEXT,
                    secret TEXT NOT NULL,
                    secret_type TEXT NOT NULL DEFAULT 'password',
                    service TEXT,
                    source TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(session_id, username, secret, service)
                );

                CREATE TABLE IF NOT EXISTS flags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    flag_type TEXT,
                    value TEXT NOT NULL,
                    source TEXT,
                    submitted INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    UNIQUE(session_id, value)
                );

                CREATE TABLE IF NOT EXISTS vectors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    phase TEXT NOT NULL,
                    vector TEXT NOT NULL,
                    outcome TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tool_outputs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    phase TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    command TEXT,
                    returncode INTEGER,
                    ok INTEGER NOT NULL,
                    timed_out INTEGER NOT NULL,
                    stdout BLOB,
                    stderr BLOB,
                    stdout_compressed INTEGER NOT NULL DEFAULT 0,
                    stderr_compressed INTEGER NOT NULL DEFAULT 0,
                    structured_json TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reasoning_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    phase TEXT NOT NULL,
                    reasoning TEXT NOT NULL,
                    tool TEXT,
                    args_json TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )

    def create_session(self, machine_name: str, metadata: dict[str, Any] | None = None) -> SessionRecord:
        metadata = metadata or {}
        today = datetime.now().strftime("%Y%m%d")
        session_key = f"{machine_name.lower()}_{today}"
        now = utc_now()
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT * FROM sessions WHERE session_key = ?", (session_key,)
            ).fetchone()
            if existing:
                return _row_to_session(existing)

            session_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO sessions (
                    id, session_key, machine_name, date, status, phase,
                    machine_ip, machine_id, os, difficulty, points, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'running', 'recon', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    session_key,
                    machine_name,
                    today,
                    metadata.get("ip"),
                    metadata.get("id"),
                    metadata.get("os"),
                    metadata.get("difficulty"),
                    metadata.get("points"),
                    now,
                    now,
                ),
            )
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            return _row_to_session(row)

    def get_session(self, session_id: str) -> SessionRecord | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        return _row_to_session(row) if row else None

    def get_latest_incomplete(self, machine_name: str | None = None) -> SessionRecord | None:
        query = "SELECT * FROM sessions WHERE status != 'completed'"
        args: list[Any] = []
        if machine_name:
            query += " AND lower(machine_name) = lower(?)"
            args.append(machine_name)
        query += " ORDER BY updated_at DESC LIMIT 1"
        with self.connect() as conn:
            row = conn.execute(query, args).fetchone()
        return _row_to_session(row) if row else None

    def latest_session(self, machine_name: str | None = None) -> SessionRecord | None:
        query = "SELECT * FROM sessions"
        args: list[Any] = []
        if machine_name:
            query += " WHERE lower(machine_name) = lower(?)"
            args.append(machine_name)
        query += " ORDER BY updated_at DESC LIMIT 1"
        with self.connect() as conn:
            row = conn.execute(query, args).fetchone()
        return _row_to_session(row) if row else None

    def update_phase(self, session_id: str, phase: str) -> None:
        self._update_session(session_id, phase=phase)

    def update_status(self, session_id: str, status: str) -> None:
        self._update_session(session_id, status=status)

    def _update_session(self, session_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = utc_now()
        assignments = ", ".join(f"{key} = ?" for key in fields)
        values = list(fields.values()) + [session_id]
        with self.connect() as conn:
            conn.execute(f"UPDATE sessions SET {assignments} WHERE id = ?", values)

    def add_port(self, session_id: str, item: dict[str, Any]) -> bool:
        with self.connect() as conn:
            before = conn.total_changes
            conn.execute(
                """
                INSERT OR REPLACE INTO ports (
                    session_id, port, protocol, service, product, version,
                    state, raw_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    int(item.get("port")),
                    item.get("protocol", "tcp"),
                    item.get("service"),
                    item.get("product"),
                    item.get("version"),
                    item.get("state", "open"),
                    json.dumps(item, sort_keys=True),
                    utc_now(),
                ),
            )
            changed = conn.total_changes > before
        self._touch(session_id)
        return changed

    def add_vhost(self, session_id: str, hostname: str, ip: str | None, source: str) -> bool:
        return self._insert_unique(
            "INSERT OR IGNORE INTO vhosts (session_id, hostname, ip, source, created_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, hostname, ip, source, utc_now()),
            session_id,
        )

    def add_web_path(
        self,
        session_id: str,
        url: str,
        status_code: int | None,
        length: int | None,
        source: str,
    ) -> bool:
        return self._insert_unique(
            "INSERT OR IGNORE INTO web_paths (session_id, url, status_code, length, source, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, url, status_code, length, source, utc_now()),
            session_id,
        )

    def add_credential(
        self,
        session_id: str,
        username: str | None,
        secret: str,
        secret_type: str,
        service: str | None,
        source: str,
    ) -> bool:
        return self._insert_unique(
            "INSERT OR IGNORE INTO credentials (session_id, username, secret, secret_type, service, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, username, secret, secret_type, service, source, utc_now()),
            session_id,
        )

    def add_flag(self, session_id: str, value: str, flag_type: str | None, source: str) -> bool:
        return self._insert_unique(
            "INSERT OR IGNORE INTO flags (session_id, flag_type, value, source, created_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, flag_type, value, source, utc_now()),
            session_id,
        )

    def mark_flag_submitted(self, session_id: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE flags SET submitted = 1 WHERE session_id = ? AND value = ?",
                (session_id, value),
            )
        self._touch(session_id)

    def add_vector(self, session_id: str, phase: str, vector: str, outcome: str | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO vectors (session_id, phase, vector, outcome, created_at) VALUES (?, ?, ?, ?, ?)",
                (session_id, phase, vector, outcome, utc_now()),
            )
        self._touch(session_id)

    def add_reasoning_step(
        self,
        session_id: str,
        phase: str,
        reasoning: str,
        tool: str | None,
        args: dict[str, Any] | None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO reasoning_steps (session_id, phase, reasoning, tool, args_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, phase, reasoning, tool, json.dumps(args or {}, sort_keys=True), utc_now()),
            )
        self._touch(session_id)

    def add_tool_output(
        self,
        session_id: str,
        phase: str,
        tool: str,
        command: str | None,
        returncode: int | None,
        ok: bool,
        timed_out: bool,
        stdout: str,
        stderr: str,
        structured: dict[str, Any] | None,
    ) -> None:
        stdout_blob, stdout_compressed = _encode_output(stdout)
        stderr_blob, stderr_compressed = _encode_output(stderr)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO tool_outputs (
                    session_id, phase, tool, command, returncode, ok, timed_out,
                    stdout, stderr, stdout_compressed, stderr_compressed,
                    structured_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    phase,
                    tool,
                    command,
                    returncode,
                    int(ok),
                    int(timed_out),
                    stdout_blob,
                    stderr_blob,
                    int(stdout_compressed),
                    int(stderr_compressed),
                    json.dumps(structured or {}, sort_keys=True),
                    utc_now(),
                ),
            )
        self._touch(session_id)

    def context(self, session_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            session = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            if not session:
                raise KeyError(f"Unknown session {session_id}")
            return {
                "session": dict(session),
                "ports": [dict(row) for row in conn.execute("SELECT * FROM ports WHERE session_id = ? ORDER BY port", (session_id,))],
                "vhosts": [dict(row) for row in conn.execute("SELECT * FROM vhosts WHERE session_id = ? ORDER BY hostname", (session_id,))],
                "web_paths": [dict(row) for row in conn.execute("SELECT * FROM web_paths WHERE session_id = ? ORDER BY url", (session_id,))],
                "credentials": [dict(row) for row in conn.execute("SELECT * FROM credentials WHERE session_id = ? ORDER BY created_at", (session_id,))],
                "flags": [dict(row) for row in conn.execute("SELECT * FROM flags WHERE session_id = ? ORDER BY created_at", (session_id,))],
                "vectors": [dict(row) for row in conn.execute("SELECT * FROM vectors WHERE session_id = ? ORDER BY created_at", (session_id,))],
                "recent_reasoning": [
                    dict(row)
                    for row in conn.execute(
                        "SELECT * FROM reasoning_steps WHERE session_id = ? ORDER BY id DESC LIMIT 10",
                        (session_id,),
                    )
                ],
                "recent_outputs": [
                    _tool_output_row_to_dict(row)
                    for row in conn.execute(
                        "SELECT * FROM tool_outputs WHERE session_id = ? ORDER BY id DESC LIMIT 5",
                        (session_id,),
                    )
                ],
            }

    def complete_session_if_flags_found(self, session_id: str) -> bool:
        context = self.context(session_id)
        flag_types = {row.get("flag_type") for row in context["flags"]}
        values = {row.get("value") for row in context["flags"]}
        has_user = "user" in flag_types
        has_root = "root" in flag_types
        if has_user and has_root or len(values) >= 2:
            self.update_status(session_id, "completed")
            return True
        return False

    def _insert_unique(self, sql: str, args: tuple[Any, ...], session_id: str) -> bool:
        with self.connect() as conn:
            before = conn.total_changes
            conn.execute(sql, args)
            changed = conn.total_changes > before
        if changed:
            self._touch(session_id)
        return changed

    def _touch(self, session_id: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE sessions SET updated_at = ? WHERE id = ?", (utc_now(), session_id))


def _row_to_session(row: sqlite3.Row) -> SessionRecord:
    return SessionRecord(
        id=row["id"],
        session_key=row["session_key"],
        machine_name=row["machine_name"],
        date=row["date"],
        status=row["status"],
        phase=row["phase"],
        machine_ip=row["machine_ip"],
        machine_id=row["machine_id"],
        os=row["os"],
        difficulty=row["difficulty"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _encode_output(text: str) -> tuple[bytes, bool]:
    raw = text.encode("utf-8", errors="replace")
    if len(raw) > COMPRESS_THRESHOLD:
        return base64.b64encode(zlib.compress(raw)), True
    return raw, False


def _decode_output(blob: bytes, compressed: bool) -> str:
    if compressed:
        return zlib.decompress(base64.b64decode(blob)).decode("utf-8", errors="replace")
    return blob.decode("utf-8", errors="replace")


def _tool_output_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["stdout"] = _decode_output(row["stdout"] or b"", bool(row["stdout_compressed"]))[:4000]
    data["stderr"] = _decode_output(row["stderr"] or b"", bool(row["stderr_compressed"]))[:2000]
    data.pop("stdout_compressed", None)
    data.pop("stderr_compressed", None)
    return data
