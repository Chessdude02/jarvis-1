"""Append-only, hash-chained audit log.

JARVIS's own code never exposes an update or delete path for this table --
there is no method on AuditLog that mutates or removes a row. Each row also
carries a SHA-256 hash over its own content plus the previous row's hash, so
`verify_chain()` can detect any out-of-band edit (someone opening the SQLite
file directly) even though the process itself cannot make one.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

_GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    data TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""


@dataclass
class AuditEvent:
    id: int
    ts: str
    event_type: str
    data: dict[str, Any]
    prev_hash: str
    hash: str


def _row_hash(prev_hash: str, ts: str, event_type: str, data_json: str) -> str:
    payload = f"{prev_hash}|{ts}|{event_type}|{data_json}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class AuditLog:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def _last_hash(self) -> str:
        cur = self._conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        return row[0] if row else _GENESIS_HASH

    def record(self, event_type: str, **data: Any) -> int:
        """Append one event. Returns the new row id. This is the ONLY way to
        write to this table; there is deliberately no update/delete method.
        """
        ts = datetime.now(timezone.utc).isoformat()
        data_json = json.dumps(data, default=str, sort_keys=True)
        with self._lock:
            prev_hash = self._last_hash()
            h = _row_hash(prev_hash, ts, event_type, data_json)
            cur = self._conn.execute(
                "INSERT INTO audit_log (ts, event_type, data, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
                (ts, event_type, data_json, prev_hash, h),
            )
            self._conn.commit()
            return cur.lastrowid

    def iter_events(self, limit: int | None = None) -> Iterator[AuditEvent]:
        q = "SELECT id, ts, event_type, data, prev_hash, hash FROM audit_log ORDER BY id ASC"
        if limit:
            q += f" LIMIT {int(limit)}"
        for row in self._conn.execute(q):
            yield AuditEvent(
                id=row[0], ts=row[1], event_type=row[2],
                data=json.loads(row[3]), prev_hash=row[4], hash=row[5],
            )

    def verify_chain(self) -> tuple[bool, int | None]:
        """Recomputes every row's hash. Returns (ok, first_bad_id)."""
        prev = _GENESIS_HASH
        for event in self.iter_events():
            data_json = json.dumps(event.data, default=str, sort_keys=True)
            expected = _row_hash(prev, event.ts, event.event_type, data_json)
            if event.prev_hash != prev or event.hash != expected:
                return False, event.id
            prev = event.hash
        return True, None

    def close(self) -> None:
        self._conn.close()
