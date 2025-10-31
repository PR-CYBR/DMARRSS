"""
SQLite storage layer for DMARRSS.

Manages persistent state for events, decisions, actions, and statistics.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .schemas import ActionResult, Decision, Event


class Store:
    """
    SQLite-based persistent storage for DMARRSS.

    Provides crash-safe storage for events, decisions, actions, and operational state.
    """

    def __init__(self, db_path: str = "data/state/dmarrss.db"):
        """Initialize store and create schema if needed"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _get_conn(self) -> Iterator[sqlite3.Connection]:
        """Context manager for database connections"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """Create database schema if it doesn't exist"""
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    threat_score REAL,
                    severity TEXT,
                    data TEXT NOT NULL,
                    created_at REAL DEFAULT (julianday('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
                CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);

                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    threat_score REAL NOT NULL,
                    timestamp REAL NOT NULL,
                    data TEXT NOT NULL,
                    created_at REAL DEFAULT (julianday('now')),
                    FOREIGN KEY (event_id) REFERENCES events(event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
                CREATE INDEX IF NOT EXISTS idx_decisions_severity ON decisions(severity);

                CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY,
                    decision_id TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    dry_run INTEGER NOT NULL,
                    executed INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    data TEXT NOT NULL,
                    created_at REAL DEFAULT (julianday('now')),
                    FOREIGN KEY (decision_id) REFERENCES decisions(decision_id)
                );
                CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON actions(timestamp);
                CREATE INDEX IF NOT EXISTS idx_actions_name ON actions(action_name);

                CREATE TABLE IF NOT EXISTS stats (
                    stat_key TEXT PRIMARY KEY,
                    stat_value REAL NOT NULL,
                    updated_at REAL DEFAULT (julianday('now'))
                );

                CREATE TABLE IF NOT EXISTS file_positions (
                    file_path TEXT PRIMARY KEY,
                    inode INTEGER,
                    offset INTEGER NOT NULL,
                    updated_at REAL DEFAULT (julianday('now'))
                );
                """
            )

    def insert_event(self, event: Event) -> None:
        """Insert or update an event"""
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO events
                (event_id, source, timestamp, src_ip, dst_ip, threat_score, severity, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id or f"{event.source}_{event.ts.timestamp()}",
                    event.source.value,
                    event.ts.timestamp(),
                    event.src_ip,
                    event.dst_ip,
                    event.threat_score,
                    event.severity.value if event.severity else None,
                    event.model_dump_json(),
                ),
            )

    def insert_decision(self, decision: Decision) -> None:
        """Insert a decision"""
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO decisions
                (decision_id, event_id, severity, confidence, threat_score, timestamp, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.decision_id,
                    decision.event_id,
                    decision.severity.value,
                    decision.confidence,
                    decision.threat_score,
                    decision.timestamp.timestamp(),
                    decision.model_dump_json(),
                ),
            )

    def insert_action(self, action: ActionResult) -> None:
        """Insert an action result"""
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO actions
                (action_id, decision_id, action_name, success, dry_run, executed, timestamp, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action.action_id,
                    action.decision_id,
                    action.action_name,
                    int(action.success),
                    int(action.dry_run),
                    int(action.executed),
                    action.timestamp.timestamp(),
                    action.model_dump_json(),
                ),
            )

    def get_events(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Query events with filters"""
        with self._get_conn() as conn:
            query = "SELECT * FROM events WHERE 1=1"
            params: List[Any] = []

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            if since:
                query += " AND timestamp >= ?"
                params.append(since.timestamp())

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """Get a decision by ID"""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_stat(self, key: str, value: float) -> None:
        """Update or insert a statistic"""
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO stats (stat_key, stat_value, updated_at)
                VALUES (?, ?, julianday('now'))
                """,
                (key, value),
            )

    def get_stat(self, key: str) -> Optional[float]:
        """Get a statistic value"""
        with self._get_conn() as conn:
            cursor = conn.execute("SELECT stat_value FROM stats WHERE stat_key = ?", (key,))
            row = cursor.fetchone()
            return row["stat_value"] if row else None

    def update_file_position(self, file_path: str, inode: int, offset: int) -> None:
        """Update file position for log tailer"""
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO file_positions (file_path, inode, offset, updated_at)
                VALUES (?, ?, ?, julianday('now'))
                """,
                (file_path, inode, offset),
            )

    def get_file_position(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get file position for log tailer"""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT * FROM file_positions WHERE file_path = ?", (file_path,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def vacuum(self) -> None:
        """Vacuum database to reclaim space"""
        with self._get_conn() as conn:
            conn.execute("VACUUM")
