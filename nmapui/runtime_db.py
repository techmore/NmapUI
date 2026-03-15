from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(payload: Any) -> str:
    return json.dumps(payload if payload is not None else {}, sort_keys=True)


def _json_loads(payload: str | None) -> Any:
    if not payload:
        return {}
    return json.loads(payload)


SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS runtime_snapshots (
        key TEXT PRIMARY KEY,
        payload_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY,
        owner_sid TEXT,
        job_type TEXT NOT NULL,
        status TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_jobs_type_status
    ON jobs(job_type, status)
    """,
    """
    CREATE TABLE IF NOT EXISTS job_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        owner_sid TEXT,
        job_type TEXT NOT NULL,
        event_name TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_job_events_job_created
    ON job_events(job_id, id DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS report_artifacts (
        scan_path TEXT PRIMARY KEY,
        customer_id TEXT,
        target TEXT,
        html_path TEXT,
        pdf_path TEXT,
        xml_path TEXT,
        payload_json TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_report_artifacts_customer_target
    ON report_artifacts(customer_id, target)
    """,
    """
    CREATE TABLE IF NOT EXISTS runtime_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_runtime_logs_category_created
    ON runtime_logs(category, created_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS customer_scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id TEXT,
        timestamp TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_customer_scan_history_customer_timestamp
    ON customer_scan_history(customer_id, timestamp DESC)
    """,
)


class RuntimeStateStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            yield conn
            conn.commit()
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            for statement in SCHEMA_STATEMENTS:
                conn.execute(statement)

    def upsert_runtime_snapshot(self, key: str, payload: dict[str, Any]) -> None:
        now = utcnow_iso()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO runtime_snapshots(key, payload_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (key, _json_dumps(payload), now),
            )

    def get_runtime_snapshot(self, key: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM runtime_snapshots WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return _json_loads(row["payload_json"])

    def upsert_job(
        self,
        *,
        job_id: str,
        owner_sid: str | None,
        job_type: str,
        status: str,
        payload: dict[str, Any],
    ) -> None:
        now = utcnow_iso()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO jobs(job_id, owner_sid, job_type, status, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    owner_sid=excluded.owner_sid,
                    job_type=excluded.job_type,
                    status=excluded.status,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (job_id, owner_sid, job_type, status, _json_dumps(payload), now, now),
            )

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT job_id, owner_sid, job_type, status, payload_json, created_at, updated_at
                FROM jobs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "job_id": row["job_id"],
            "owner_sid": row["owner_sid"],
            "job_type": row["job_type"],
            "status": row["status"],
            "payload": _json_loads(row["payload_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_jobs(
        self,
        *,
        statuses: list[str] | tuple[str, ...] | None = None,
        job_type: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT job_id, owner_sid, job_type, status, payload_json, created_at, updated_at
            FROM jobs
        """
        conditions = []
        params: list[Any] = []
        if statuses:
            conditions.append(f"status IN ({','.join('?' for _ in statuses)})")
            params.extend(statuses)
        if job_type:
            conditions.append("job_type = ?")
            params.append(job_type)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [
            {
                "job_id": row["job_id"],
                "owner_sid": row["owner_sid"],
                "job_type": row["job_type"],
                "status": row["status"],
                "payload": _json_loads(row["payload_json"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def upsert_report_artifact(
        self,
        *,
        scan_path: str,
        customer_id: str,
        target: str,
        html_path: str | None,
        pdf_path: str | None,
        xml_path: str | None,
        payload: dict[str, Any],
    ) -> None:
        now = utcnow_iso()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO report_artifacts(
                    scan_path, customer_id, target, html_path, pdf_path, xml_path,
                    payload_json, generated_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_path) DO UPDATE SET
                    customer_id=excluded.customer_id,
                    target=excluded.target,
                    html_path=excluded.html_path,
                    pdf_path=excluded.pdf_path,
                    xml_path=excluded.xml_path,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    scan_path,
                    customer_id,
                    target,
                    html_path,
                    pdf_path,
                    xml_path,
                    _json_dumps(payload),
                    now,
                    now,
                ),
            )

    def list_report_artifacts(self, *, customer_id: str | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT scan_path, customer_id, target, html_path, pdf_path, xml_path, payload_json, generated_at, updated_at
            FROM report_artifacts
        """
        params: tuple[Any, ...] = ()
        if customer_id:
            query += " WHERE customer_id = ?"
            params = (customer_id,)
        query += " ORDER BY generated_at DESC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "scan_path": row["scan_path"],
                "customer_id": row["customer_id"],
                "target": row["target"],
                "html_path": row["html_path"],
                "pdf_path": row["pdf_path"],
                "xml_path": row["xml_path"],
                "payload": _json_loads(row["payload_json"]),
                "generated_at": row["generated_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def get_report_artifact(self, scan_path: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT scan_path, customer_id, target, html_path, pdf_path, xml_path, payload_json, generated_at, updated_at
                FROM report_artifacts
                WHERE scan_path = ?
                """,
                (scan_path,),
            ).fetchone()
        if row is None:
            return None
        return {
            "scan_path": row["scan_path"],
            "customer_id": row["customer_id"],
            "target": row["target"],
            "html_path": row["html_path"],
            "pdf_path": row["pdf_path"],
            "xml_path": row["xml_path"],
            "payload": _json_loads(row["payload_json"]),
            "generated_at": row["generated_at"],
            "updated_at": row["updated_at"],
        }

    def delete_report_artifact(self, scan_path: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "DELETE FROM report_artifacts WHERE scan_path = ?",
                (scan_path,),
            )

    def append_log(
        self,
        *,
        category: str,
        level: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> int:
        now = utcnow_iso()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO runtime_logs(category, level, message, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (category, level, message, _json_dumps(payload), now),
            )
            return int(cursor.lastrowid)

    def append_job_event(
        self,
        *,
        job_id: str,
        owner_sid: str | None,
        job_type: str,
        event_name: str,
        payload: Any = None,
        max_events: int = 200,
    ) -> int:
        now = utcnow_iso()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO job_events(job_id, owner_sid, job_type, event_name, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (job_id, owner_sid, job_type, event_name, _json_dumps(payload), now),
            )
            conn.execute(
                """
                DELETE FROM job_events
                WHERE job_id = ?
                  AND id NOT IN (
                    SELECT id FROM job_events
                    WHERE job_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                  )
                """,
                (job_id, job_id, max_events),
            )
            return int(cursor.lastrowid)

    def list_job_events(
        self,
        *,
        job_id: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, job_id, owner_sid, job_type, event_name, payload_json, created_at
                FROM job_events
                WHERE job_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (job_id, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "job_id": row["job_id"],
                "owner_sid": row["owner_sid"],
                "job_type": row["job_type"],
                "event_name": row["event_name"],
                "payload": _json_loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in reversed(rows)
        ]

    def get_recent_logs(
        self,
        *,
        category: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT id, category, level, message, payload_json, created_at
            FROM runtime_logs
        """
        params: tuple[Any, ...] = ()
        if category:
            query += " WHERE category = ?"
            params = (category,)
        query += " ORDER BY id DESC LIMIT ?"
        params += (limit,)
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": row["id"],
                "category": row["category"],
                "level": row["level"],
                "message": row["message"],
                "payload": _json_loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def append_customer_scan_history(
        self,
        *,
        customer_id: str | None,
        payload: dict[str, Any],
    ) -> int:
        now = utcnow_iso()
        timestamp = str(payload.get("timestamp", "") or now)
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO customer_scan_history(customer_id, timestamp, payload_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (customer_id, timestamp, _json_dumps(payload), now),
            )
            return int(cursor.lastrowid)

    def list_customer_scan_history(
        self,
        *,
        customer_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT id, customer_id, timestamp, payload_json, created_at
            FROM customer_scan_history
        """
        params: list[Any] = []
        if customer_id:
            query += " WHERE customer_id = ?"
            params.append(customer_id)
        query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [
            {
                "id": row["id"],
                "customer_id": row["customer_id"],
                "timestamp": row["timestamp"],
                "payload": _json_loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def count_report_artifacts(self) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM report_artifacts"
            ).fetchone()
        return int(row["count"] or 0)

    def count_customer_scan_history(self) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM customer_scan_history"
            ).fetchone()
        return int(row["count"] or 0)

    def count_runtime_logs(self) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM runtime_logs"
            ).fetchone()
        return int(row["count"] or 0)


def create_runtime_state_store(db_path: Path) -> RuntimeStateStore:
    store = RuntimeStateStore(db_path)
    store.initialize()
    return store
