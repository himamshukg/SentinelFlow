"""Structured audit events backed by a local SQLite database."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any, Iterator

DEFAULT_AUDIT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "sentinelflow-audit.sqlite3"
AUDIT_DB_ENV = "SENTINELFLOW_AUDIT_DB_PATH"


class AuditStorageError(RuntimeError):
    """Raised when the audit database cannot persist or read events."""


def resolve_audit_db_path(path: str | Path | None = None) -> Path:
    """Resolve configured paths relative to the project root for consistency."""

    configured = path if path is not None else os.getenv(AUDIT_DB_ENV)
    candidate = Path(configured).expanduser() if configured else DEFAULT_AUDIT_DB_PATH
    if not candidate.is_absolute():
        candidate = Path(__file__).resolve().parents[1] / candidate
    return candidate.resolve()


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class AuditEvent:
    """One recorded attempt: who asked, what was decided, and its outcome."""

    request_id: str
    event: str
    action: Any
    arguments: Any
    agent_id: Any
    decision: str
    rule_id: str
    reason: str
    executed: bool
    execution_success: bool
    pending: bool
    error: str | None = None
    timestamp: str = field(default_factory=_utc_timestamp)

    def to_dict(self) -> dict[str, Any]:
        """Plain dict form for printing or JSON export."""

        return asdict(self)


class AuditLog:
    """Append-only audit log with the same interface as the former list store.

    Connections are opened and closed per operation, making the log safe to use
    from FastAPI worker threads and ensuring data is committed before returning.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = resolve_audit_db_path(db_path)
        self._initialized = False
        self._init_lock = Lock()

    def _ensure_schema(self) -> None:
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            try:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                connection = sqlite3.connect(self.db_path, timeout=5.0)
                try:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS audit_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            request_id TEXT NOT NULL,
                            event_type TEXT NOT NULL,
                            action_json TEXT NOT NULL,
                            arguments_json TEXT NOT NULL,
                            agent_id_json TEXT NOT NULL,
                            decision TEXT NOT NULL,
                            rule_id TEXT NOT NULL,
                            reason TEXT NOT NULL,
                            executed INTEGER NOT NULL,
                            execution_success INTEGER NOT NULL,
                            pending INTEGER NOT NULL,
                            error TEXT,
                            timestamp TEXT NOT NULL
                        )
                        """
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS idx_audit_events_decision_id "
                        "ON audit_events (decision, id DESC)"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS idx_audit_events_action_id "
                        "ON audit_events (action_json, id DESC)"
                    )
                    connection.commit()
                finally:
                    connection.close()
                self._initialized = True
            except (OSError, sqlite3.Error) as exc:
                raise AuditStorageError("Could not initialize the audit database.") from exc

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._ensure_schema()
        try:
            connection = sqlite3.connect(self.db_path, timeout=5.0)
            connection.row_factory = sqlite3.Row
        except (OSError, sqlite3.Error) as exc:
            raise AuditStorageError("Could not open the audit database.") from exc
        try:
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise AuditStorageError("Could not access the audit database.") from exc
        finally:
            connection.close()

    @staticmethod
    def _encode(value: Any) -> str:
        return json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _decode_event(row: sqlite3.Row) -> AuditEvent:
        try:
            return AuditEvent(
                request_id=row["request_id"],
                event=row["event_type"],
                action=json.loads(row["action_json"]),
                arguments=json.loads(row["arguments_json"]),
                agent_id=json.loads(row["agent_id_json"]),
                decision=row["decision"],
                rule_id=row["rule_id"],
                reason=row["reason"],
                executed=bool(row["executed"]),
                execution_success=bool(row["execution_success"]),
                pending=bool(row["pending"]),
                error=row["error"],
                timestamp=row["timestamp"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuditStorageError("Audit event data could not be decoded.") from exc

    def append(self, event: AuditEvent) -> None:
        """Persist one event using the original append interface."""

        self._insert(event)

    def append_with_id(self, event: AuditEvent) -> int:
        """Persist an event and return its row ID after the transaction commits."""

        return self._insert(event)

    def _insert(self, event: AuditEvent) -> int:
        """Shared parameterized insert used by append and execution tracking."""

        values = (
            event.request_id,
            event.event,
            self._encode(event.action),
            self._encode(event.arguments),
            self._encode(event.agent_id),
            event.decision,
            event.rule_id,
            event.reason,
            int(event.executed),
            int(event.execution_success),
            int(event.pending),
            event.error,
            event.timestamp,
        )
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO audit_events (
                    request_id, event_type, action_json, arguments_json,
                    agent_id_json, decision, rule_id, reason, executed,
                    execution_success, pending, error, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            event_id = int(cursor.lastrowid)
        return event_id

    def update_execution(
        self,
        event_id: int,
        *,
        event: str,
        executed: bool,
        execution_success: bool,
        pending: bool,
        error: str | None,
    ) -> None:
        """Commit an execution outcome in a short, separate transaction."""

        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE audit_events
                SET event_type = ?, executed = ?, execution_success = ?,
                    pending = ?, error = ?
                WHERE id = ?
                """,
                (event, int(executed), int(execution_success), int(pending), error, event_id),
            )
            if cursor.rowcount != 1:
                raise AuditStorageError("The audit execution record could not be updated.")

    def __len__(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT COUNT(*) AS event_count FROM audit_events").fetchone()
        return int(row["event_count"])

    def __getitem__(self, index: int | slice) -> AuditEvent | list[AuditEvent]:
        """Keep chronological indexing behavior from the in-memory list."""

        return self.as_list()[index]

    def __iter__(self) -> Iterator[AuditEvent]:
        return iter(self.as_list())

    def as_list(self) -> list[AuditEvent]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
        return [self._decode_event(row) for row in rows]

    def recent(
        self,
        *,
        decision: str | None = None,
        action: str | None = None,
        agent_id: str | None = None,
        limit: int = 50,
    ) -> list[AuditEvent]:
        """Return newest-first events, with optional filters and a bounded limit."""

        safe_limit = max(1, min(limit, 200))
        clauses: list[str] = []
        parameters: list[Any] = []
        if decision:
            clauses.append("decision = ?")
            parameters.append(decision.upper())
        if action:
            clauses.append("action_json = ?")
            parameters.append(self._encode(action))
        if agent_id:
            clauses.append("agent_id_json = ?")
            parameters.append(self._encode(agent_id))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(safe_limit)
        query = f"SELECT * FROM audit_events{where} ORDER BY id DESC LIMIT ?"
        with self._connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._decode_event(row) for row in rows]
