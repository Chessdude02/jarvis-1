"""Local, inspectable, user-deletable memory.

Deliberately separate from jarvis/security/audit.py: the audit log is
append-only and JARVIS can never erase it, because it exists to protect the
user FROM JARVIS/the LLM. Memory exists to make JARVIS more useful TO the
user, so the user is fully in control of it -- everything here has a
delete path.

A lightweight redaction pass (jarvis.security.secrets.redact, the same
deterministic scanner the audit log and command output use) runs on
anything stored in the conversation table so an accidentally pasted secret
doesn't linger in memory.db even though the LLM was never supposed to go
looking for one.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jarvis.security.secrets import redact

_SCHEMA = """
CREATE TABLE IF NOT EXISTS conversation (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS preferences (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS project_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS action_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, summary TEXT NOT NULL, status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
    grant_key TEXT PRIMARY KEY, ts REAL NOT NULL
);
"""


@dataclass
class ConversationMessage:
    role: str
    content: str
    ts: float


class Memory:
    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._session_grants: set[str] = set()

    # -- conversation ----------------------------------------------------

    def add_message(self, role: str, content: str) -> None:
        clean = redact(content)
        with self._lock:
            self._conn.execute("INSERT INTO conversation (ts, role, content) VALUES (?, ?, ?)", (time.time(), role, clean))
            self._conn.commit()

    def recent_messages(self, limit: int = 20) -> list[ConversationMessage]:
        cur = self._conn.execute("SELECT role, content, ts FROM conversation ORDER BY id DESC LIMIT ?", (limit,))
        rows = [ConversationMessage(role=r[0], content=r[1], ts=r[2]) for r in cur.fetchall()]
        return list(reversed(rows))

    # -- preferences -------------------------------------------------------

    def set_preference(self, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO preferences (key, value, ts) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, ts=excluded.ts",
                (key, json.dumps(value), time.time()),
            )
            self._conn.commit()

    def get_preference(self, key: str, default: Any = None) -> Any:
        cur = self._conn.execute("SELECT value FROM preferences WHERE key = ?", (key,))
        row = cur.fetchone()
        return json.loads(row[0]) if row else default

    # -- project cache -----------------------------------------------------

    def save_project_index(self, records: list[dict]) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM project_cache")
            self._conn.execute("INSERT INTO project_cache (ts, data) VALUES (?, ?)", (time.time(), json.dumps(records)))
            self._conn.commit()

    def load_project_index(self, max_age_seconds: float = 3600) -> list[dict] | None:
        cur = self._conn.execute("SELECT ts, data FROM project_cache ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        if not row or (time.time() - row[0]) > max_age_seconds:
            return None
        return json.loads(row[1])

    # -- observations / action history --------------------------------------

    def record_observation(self, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute("INSERT INTO observations (ts, key, value) VALUES (?, ?, ?)", (time.time(), key, json.dumps(value, default=str)))
            self._conn.commit()

    def record_action(self, summary: str, status: str) -> None:
        with self._lock:
            self._conn.execute("INSERT INTO action_history (ts, summary, status) VALUES (?, ?, ?)", (time.time(), redact(summary), status))
            self._conn.commit()

    def recent_actions(self, limit: int = 20) -> list[dict]:
        cur = self._conn.execute("SELECT ts, summary, status FROM action_history ORDER BY id DESC LIMIT ?", (limit,))
        return [{"ts": r[0], "summary": r[1], "status": r[2]} for r in cur.fetchall()]

    # -- grants (used by policy_engine.GrantStore protocol) -----------------

    def has_grant(self, grant_key: str) -> bool:
        if grant_key in self._session_grants:
            return True
        cur = self._conn.execute("SELECT 1 FROM grants WHERE grant_key = ?", (grant_key,))
        return cur.fetchone() is not None

    def add_session_grant(self, grant_key: str) -> None:
        self._session_grants.add(grant_key)

    def add_permanent_grant(self, grant_key: str) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO grants (grant_key, ts) VALUES (?, ?)", (grant_key, time.time()))
            self._conn.commit()

    def clear_session_grants(self) -> None:
        self._session_grants.clear()

    # -- user-facing inspect/delete ------------------------------------------

    def delete_all(self, category: str) -> None:
        """category in {'conversation','preferences','project_cache','observations','action_history','grants','all'}"""
        tables = {
            "conversation": ["conversation"], "preferences": ["preferences"],
            "project_cache": ["project_cache"], "observations": ["observations"],
            "action_history": ["action_history"], "grants": ["grants"],
            "all": ["conversation", "preferences", "project_cache", "observations", "action_history", "grants"],
        }
        with self._lock:
            for t in tables.get(category, []):
                self._conn.execute(f"DELETE FROM {t}")
            self._conn.commit()
        if category in ("grants", "all"):
            self._session_grants.clear()

    def close(self) -> None:
        self._conn.close()
