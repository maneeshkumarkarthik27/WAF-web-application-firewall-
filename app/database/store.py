from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import Lock
from typing import Iterator

from app.models.dashboard import DashboardStats
from app.models.security import ActionTaken, SecurityAssessment


@dataclass(frozen=True)
class OffenderState:
    source_ip: str
    count: int
    status: str
    blocked_until: str | None


class DatabaseStore:
    """SQLite persistence for security events, offender tracking, and dashboard metrics."""

    def __init__(self, database_url: str) -> None:
        self.database_path = self._extract_path(database_url)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._initialize()

    def _extract_path(self, database_url: str) -> Path:
        if database_url.startswith("sqlite:///"):
            return Path(database_url.removeprefix("sqlite:///"))
        return Path(database_url)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    request_path TEXT NOT NULL,
                    method TEXT NOT NULL,
                    headers TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    detection_type TEXT NOT NULL,
                    threat_score INTEGER NOT NULL,
                    action_taken TEXT NOT NULL,
                    user_agent TEXT,
                    blocked_until TEXT,
                    block_reason TEXT
                );

                CREATE TABLE IF NOT EXISTS offenders (
                    source_ip TEXT PRIMARY KEY,
                    count INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    blocked_until TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS request_stats (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    total_requests INTEGER NOT NULL,
                    allowed_requests INTEGER NOT NULL,
                    blocked_requests INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                INSERT OR IGNORE INTO request_stats (id, total_requests, allowed_requests, blocked_requests, updated_at)
                VALUES (1, 0, 0, 0, CURRENT_TIMESTAMP);
                """
            )

    def record_assessment(self, assessment: SecurityAssessment) -> None:
        detection_type = ",".join(sorted({finding.finding_type for finding in assessment.findings})) or "clean"
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO security_events (
                    request_id, timestamp, source_ip, request_path, method, headers, payload,
                    detection_type, threat_score, action_taken, user_agent, blocked_until, block_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment.request_id,
                    assessment.timestamp.isoformat(),
                    assessment.source_ip,
                    assessment.path,
                    assessment.method,
                    json.dumps(assessment.headers, sort_keys=True),
                    assessment.body,
                    detection_type,
                    assessment.score,
                    assessment.action.value,
                    assessment.user_agent,
                    assessment.blocked_until.isoformat() if assessment.blocked_until else None,
                    assessment.block_reason,
                ),
            )
            stats = connection.execute("SELECT total_requests, allowed_requests, blocked_requests FROM request_stats WHERE id = 1").fetchone()
            total_requests = int(stats["total_requests"]) + 1
            blocked_actions = {ActionTaken.block.value, ActionTaken.temp_block.value, ActionTaken.permanent_block.value}
            allowed_requests = int(stats["allowed_requests"]) + (1 if assessment.action.value not in blocked_actions else 0)
            blocked_requests = int(stats["blocked_requests"]) + (1 if assessment.action.value in blocked_actions else 0)
            connection.execute(
                "UPDATE request_stats SET total_requests = ?, allowed_requests = ?, blocked_requests = ?, updated_at = ? WHERE id = 1",
                (total_requests, allowed_requests, blocked_requests, datetime.now(timezone.utc).isoformat()),
            )

    def get_offender(self, source_ip: str) -> OffenderState:
        with self._connection() as connection:
            row = connection.execute("SELECT source_ip, count, status, blocked_until FROM offenders WHERE source_ip = ?", (source_ip,)).fetchone()
            if row is None:
                return OffenderState(source_ip=source_ip, count=0, status="clean", blocked_until=None)
            return OffenderState(
                source_ip=row["source_ip"],
                count=int(row["count"]),
                status=row["status"],
                blocked_until=row["blocked_until"],
            )

    def increment_offender(self, source_ip: str, *, status: str, blocked_until: datetime | None) -> OffenderState:
        with self._lock, self._connection() as connection:
            current = connection.execute("SELECT count FROM offenders WHERE source_ip = ?", (source_ip,)).fetchone()
            count = int(current["count"]) + 1 if current else 1
            connection.execute(
                """
                INSERT INTO offenders (source_ip, count, status, blocked_until, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_ip) DO UPDATE SET
                    count = excluded.count,
                    status = excluded.status,
                    blocked_until = excluded.blocked_until,
                    updated_at = excluded.updated_at
                """,
                (source_ip, count, status, blocked_until.isoformat() if blocked_until else None, datetime.now(timezone.utc).isoformat()),
            )
        return OffenderState(source_ip=source_ip, count=count, status=status, blocked_until=blocked_until.isoformat() if blocked_until else None)

    def get_dashboard_stats(self) -> DashboardStats:
        with self._connection() as connection:
            stats = connection.execute("SELECT total_requests, allowed_requests, blocked_requests FROM request_stats WHERE id = 1").fetchone()
            total_events_row = connection.execute("SELECT COUNT(*) AS count FROM security_events").fetchone()
            attack_rows = connection.execute(
                """
                SELECT detection_type, COUNT(*) AS count
                FROM security_events
                WHERE detection_type != 'clean'
                GROUP BY detection_type
                ORDER BY count DESC, detection_type ASC
                LIMIT 10
                """
            ).fetchall()
            ip_rows = connection.execute(
                """
                SELECT source_ip, COUNT(*) AS count
                FROM security_events
                WHERE detection_type != 'clean'
                GROUP BY source_ip
                ORDER BY count DESC, source_ip ASC
                LIMIT 10
                """
            ).fetchall()
            alert_rows = connection.execute(
                """
                SELECT timestamp, source_ip, request_path, method, detection_type, threat_score, action_taken, block_reason
                FROM security_events
                ORDER BY id DESC
                LIMIT 20
                """
            ).fetchall()
        return DashboardStats(
            total_requests=int(stats["total_requests"]),
            allowed_requests=int(stats["allowed_requests"]),
            blocked_requests=int(stats["blocked_requests"]),
            total_events=int(total_events_row["count"]),
            top_attack_types=[{"name": row["detection_type"], "count": int(row["count"])} for row in attack_rows],
            top_offending_ips=[{"name": row["source_ip"], "count": int(row["count"])} for row in ip_rows],
            recent_alerts=[
                {
                    "timestamp": row["timestamp"],
                    "source_ip": row["source_ip"],
                    "request_path": row["request_path"],
                    "method": row["method"],
                    "detection_type": row["detection_type"],
                    "threat_score": int(row["threat_score"]),
                    "action_taken": row["action_taken"],
                    "block_reason": row["block_reason"],
                }
                for row in alert_rows
            ],
        )
