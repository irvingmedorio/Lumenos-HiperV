#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite-backed state persistence for bunker lifecycle."""

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("LUMENOS_SANDBOX")

_DEFAULT_DB = "lumenos_state.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS bunkers (
    bunker_id   TEXT PRIMARY KEY,
    config      TEXT NOT NULL,
    state       TEXT NOT NULL,
    vm_name     TEXT,
    switch_name TEXT,
    signing_key TEXT,
    created_at  TEXT,
    activated_at TEXT,
    terminated_at TEXT,
    updated_at  TEXT NOT NULL
);
"""


class BunkerStateStore:
    """Thread-safe SQLite store for bunker state.

    Uses WAL mode for concurrent reads during monitoring.
    """

    def __init__(self, db_path: str = _DEFAULT_DB):
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    # -- connection per-thread --

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute(_SCHEMA)
        conn.commit()

    # -- lifecycle --

    def close(self) -> None:
        """Close the thread-local connection. Safe to call multiple times."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- public API --

    def save(self, bunker_id: str, data: Dict[str, Any]) -> None:
        """Upsert bunker state."""
        now = datetime.now().isoformat()
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO bunkers
               (bunker_id, config, state, vm_name, switch_name,
                signing_key, created_at, activated_at, terminated_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(bunker_id) DO UPDATE SET
                 config=excluded.config,
                 state=excluded.state,
                 vm_name=excluded.vm_name,
                 switch_name=excluded.switch_name,
                 signing_key=excluded.signing_key,
                 created_at=excluded.created_at,
                 activated_at=excluded.activated_at,
                 terminated_at=excluded.terminated_at,
                 updated_at=excluded.updated_at""",
            (
                bunker_id,
                json.dumps(data.get("config", {}), default=str),
                data.get("state", "UNKNOWN"),
                data.get("vm_name"),
                data.get("switch_name"),
                data.get("signing_key"),
                data.get("created_at"),
                data.get("activated_at"),
                data.get("terminated_at"),
                now,
            ),
        )
        conn.commit()
        logger.debug("State saved for %s", bunker_id)

    def load(self, bunker_id: str) -> Optional[Dict[str, Any]]:
        """Load bunker state. Returns None if not found."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM bunkers WHERE bunker_id = ?", (bunker_id,)
        ).fetchone()
        if row is None:
            return None
        return {
            "bunker_id": row["bunker_id"],
            "config": json.loads(row["config"]),
            "state": row["state"],
            "vm_name": row["vm_name"],
            "switch_name": row["switch_name"],
            "signing_key": row["signing_key"],
            "created_at": row["created_at"],
            "activated_at": row["activated_at"],
            "terminated_at": row["terminated_at"],
            "updated_at": row["updated_at"],
        }

    def list_all(self) -> List[Dict[str, Any]]:
        """List all persisted bunker states."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT bunker_id, state, updated_at FROM bunkers ORDER BY updated_at DESC"
        ).fetchall()
        return [
            {"bunker_id": r["bunker_id"], "state": r["state"], "updated_at": r["updated_at"]}
            for r in rows
        ]

    def delete(self, bunker_id: str) -> bool:
        """Delete a bunker record. Returns True if deleted."""
        conn = self._get_conn()
        cur = conn.execute("DELETE FROM bunkers WHERE bunker_id = ?", (bunker_id,))
        conn.commit()
        return cur.rowcount > 0

    def migrate_from_json(self, snapshots_dir: str = "snapshots") -> int:
        """Import existing JSON state files into SQLite. Returns count imported."""
        count = 0
        snap_dir = Path(snapshots_dir)
        if not snap_dir.is_dir():
            return count

        for path in snap_dir.glob("*_state.json"):
            try:
                with open(path) as f:
                    data = json.load(f)
                bunker_id = path.stem.replace("_state", "")
                self.save(bunker_id, data)
                count += 1
                logger.info("Migrated JSON state: %s", bunker_id)
            except Exception as exc:
                logger.warning("Failed to migrate %s: %s", path, exc)

        return count
