"""Local SQLite audit trail. Zero cloud, zero telemetry.

Single table, append-only. Writes are serialized with a lock so the
watchdog thread and the analysis thread can share one connection.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL    NOT NULL,
    level     TEXT    NOT NULL,   -- INFO | WARNING | ALERT | ACTION
    category  TEXT    NOT NULL,   -- signal | verdict | mitigation | canary | system
    message   TEXT    NOT NULL,
    path      TEXT,
    pid       INTEGER,
    process   TEXT,
    details   TEXT                -- JSON blob
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category);

-- Live telemetry for the dashboard (a few Hz, pruned to METRICS_RETENTION).
CREATE TABLE IF NOT EXISTS metrics (
    ts             REAL PRIMARY KEY,
    velocity       REAL NOT NULL,   -- events / s (sliding window)
    entropy        REAL,            -- max bits/byte sampled since previous row
    events         INTEGER NOT NULL,-- FS events since previous row
    cpu            REAL,            -- agent process CPU %
    canary_state   TEXT,            -- one char per bait file: 1 intact, 0 tampered
    active_signals TEXT             -- comma-separated hot signal kinds
);
"""

METRICS_RETENTION = 600.0  # seconds


@dataclass
class AuditRecord:
    id: int
    ts: float
    level: str
    category: str
    message: str
    path: str | None
    pid: int | None
    process: str | None
    details: dict[str, Any]


class AuditLog:
    def __init__(self, db_path: str | Path = "sentinel_audit.db") -> None:
        self.db_path = Path(db_path)
        if str(db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._lock = threading.Lock()

    def write(
        self,
        level: str,
        category: str,
        message: str,
        *,
        path: str | Path | None = None,
        pid: int | None = None,
        process: str | None = None,
        details: dict[str, Any] | None = None,
        ts: float | None = None,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO audit_log (ts, level, category, message, path, pid, process, details)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    time.time() if ts is None else ts,
                    level, category, message,
                    None if path is None else str(path),
                    pid, process,
                    json.dumps(details, default=str) if details else None,
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def write_metrics(
        self,
        velocity: float,
        entropy: float | None,
        events: int,
        cpu: float | None,
        canary_state: str,
        active_signals: list[str],
        ts: float | None = None,
    ) -> None:
        now = time.time() if ts is None else ts
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO metrics VALUES (?, ?, ?, ?, ?, ?, ?)",
                (now, velocity, entropy, events, cpu, canary_state, ",".join(active_signals)),
            )
            self._conn.execute("DELETE FROM metrics WHERE ts < ?", (now - METRICS_RETENTION,))
            self._conn.commit()

    def recent(self, limit: int = 50, category: str | None = None) -> list[AuditRecord]:
        sql = "SELECT id, ts, level, category, message, path, pid, process, details FROM audit_log"
        args: tuple[Any, ...] = ()
        if category:
            sql += " WHERE category = ?"
            args = (category,)
        sql += " ORDER BY id DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, (*args, limit)).fetchall()
        return [
            AuditRecord(*row[:8], details=json.loads(row[8]) if row[8] else {})
            for row in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
