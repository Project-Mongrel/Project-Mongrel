import json
import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

from app.services.findings_store import _get_connection
from app.services.target_normalizer import normalize_target_key


def create_investigation(user_id: int, target: str, name: str | None = None, client_name: str | None = None) -> dict:
    started_at = datetime.now(UTC)
    investigation_id = str(uuid4())
    stored_investigation = {
        "id": investigation_id,
        "user_id": user_id,
        "name": name or _default_investigation_name(target, started_at),
        "client_name": client_name,
        "target": target,
        "target_key": normalize_target_key(target),
        "started_at": started_at,
        "completed_at": None,
        "status": "open",
        "overall_risk": None,
        "summary": None,
        "metadata": {},
    }
    with _get_connection() as connection:
        _initialize_schema(connection)
        connection.execute(
            """
            INSERT INTO investigations (
                id, user_id, name, client_name, target, target_key, started_at,
                completed_at, status, overall_risk, summary, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id,
                user_id,
                stored_investigation["name"],
                client_name,
                target,
                stored_investigation["target_key"],
                _format_datetime(started_at),
                None,
                "open",
                None,
                None,
                _to_json(stored_investigation["metadata"]),
            ),
        )

    return dict(stored_investigation)


def get_or_create_latest_open_investigation(user_id: int, target: str) -> dict:
    investigation = get_latest_investigation_for_target(user_id, target, status="open")
    if investigation is not None:
        return investigation

    return create_investigation(user_id=user_id, target=target)


def get_user_investigations(user_id: int) -> list[dict]:
    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(
            "SELECT * FROM investigations WHERE user_id = ? ORDER BY started_at ASC, rowid ASC",
            (user_id,),
        )
    return [_row_to_investigation(row) for row in rows.fetchall()]


def get_investigation(investigation_id: str, user_id: int) -> dict | None:
    with _get_connection() as connection:
        _initialize_schema(connection)
        row = connection.execute(
            "SELECT * FROM investigations WHERE id = ? AND user_id = ?",
            (investigation_id, user_id),
        ).fetchone()
    if row is None:
        return None

    return _row_to_investigation(row)


def get_latest_investigation_for_target(user_id: int, target: str | None, status: str | None = None) -> dict | None:
    target_key = normalize_target_key(target)
    if target_key is None:
        return None

    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(
            "SELECT * FROM investigations WHERE user_id = ? ORDER BY started_at DESC, rowid DESC",
            (user_id,),
        )
    for row in rows.fetchall():
        if status is not None and row["status"] != status:
            continue
        investigation_target_key = row["target_key"] or normalize_target_key(row["target"])
        if investigation_target_key == target_key:
            return _row_to_investigation(row)

    return None


def add_investigation_event(
    investigation_id: str,
    user_id: int,
    target: str | None,
    event_type: str,
    tool: str | None = None,
    status: str = "completed",
    summary: str | None = None,
    metadata: dict | None = None,
) -> dict:
    created_at = datetime.now(UTC)
    event_id = str(uuid4())
    stored_event = {
        "id": event_id,
        "investigation_id": investigation_id,
        "user_id": user_id,
        "target": target,
        "event_type": event_type,
        "tool": tool,
        "status": status,
        "summary": summary,
        "metadata": metadata or {},
        "created_at": created_at,
    }
    with _get_connection() as connection:
        _initialize_schema(connection)
        connection.execute(
            """
            INSERT INTO investigation_events (
                id, investigation_id, user_id, target, event_type, tool, status,
                summary, metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                investigation_id,
                user_id,
                target,
                event_type,
                tool,
                status,
                summary,
                _to_json(stored_event["metadata"]),
                _format_datetime(created_at),
            ),
        )

    return dict(stored_event)


def get_investigation_events(investigation_id: str, user_id: int) -> list[dict]:
    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(
            """
            SELECT * FROM investigation_events
            WHERE investigation_id = ? AND user_id = ?
            ORDER BY created_at ASC, rowid ASC
            """,
            (investigation_id, user_id),
        )
    return [_row_to_event(row) for row in rows.fetchall()]


def complete_investigation(
    investigation_id: str,
    user_id: int,
    overall_risk: str | None = None,
    summary: str | None = None,
) -> dict | None:
    completed_at = datetime.now(UTC)
    investigation = get_investigation(investigation_id, user_id)
    if investigation is None:
        return None

    duration_seconds = max(0, int((completed_at - investigation["started_at"]).total_seconds()))
    metadata = {**(investigation.get("metadata") or {}), "duration_seconds": duration_seconds}
    with _get_connection() as connection:
        _initialize_schema(connection)
        connection.execute(
            """
            UPDATE investigations
            SET status = ?, completed_at = ?, overall_risk = COALESCE(?, overall_risk),
                summary = COALESCE(?, summary), metadata_json = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                "completed",
                _format_datetime(completed_at),
                overall_risk,
                summary,
                _to_json(metadata),
                investigation_id,
                user_id,
            ),
        )

    return get_investigation(investigation_id, user_id)


def update_investigation_summary(
    investigation_id: str,
    user_id: int,
    summary: str | None = None,
    overall_risk: str | None = None,
) -> dict | None:
    with _get_connection() as connection:
        _initialize_schema(connection)
        connection.execute(
            """
            UPDATE investigations
            SET summary = COALESCE(?, summary), overall_risk = COALESCE(?, overall_risk)
            WHERE id = ? AND user_id = ?
            """,
            (summary, overall_risk, investigation_id, user_id),
        )

    return get_investigation(investigation_id, user_id)


def clear_user_investigations(user_id: int) -> None:
    with _get_connection() as connection:
        _initialize_schema(connection)
        connection.execute("DELETE FROM investigation_events WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM investigations WHERE user_id = ?", (user_id,))


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            client_name TEXT,
            target TEXT,
            target_key TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL,
            overall_risk TEXT,
            summary TEXT,
            metadata_json TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS investigation_events (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            target TEXT,
            event_type TEXT NOT NULL,
            tool TEXT,
            status TEXT NOT NULL,
            summary TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(investigation_id) REFERENCES investigations(id)
        )
        """
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_investigations_user_started ON investigations(user_id, started_at)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_investigations_user_target_key ON investigations(user_id, target_key)")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_investigation_events_investigation_created ON investigation_events(investigation_id, created_at)"
    )
    connection.commit()


def _default_investigation_name(target: str, started_at: datetime) -> str:
    return f"Investigation - {target} - {started_at.astimezone(UTC):%d %b %Y}"


def _row_to_investigation(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "name": row["name"],
        "client_name": row["client_name"],
        "target": row["target"],
        "target_key": row["target_key"],
        "started_at": _parse_datetime(row["started_at"]),
        "completed_at": _parse_datetime(row["completed_at"]) if row["completed_at"] else None,
        "status": row["status"],
        "overall_risk": row["overall_risk"],
        "summary": row["summary"],
        "metadata": _from_json(row["metadata_json"] or "{}"),
    }


def _row_to_event(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "investigation_id": row["investigation_id"],
        "user_id": row["user_id"],
        "target": row["target"],
        "event_type": row["event_type"],
        "tool": row["tool"],
        "status": row["status"],
        "summary": row["summary"],
        "metadata": _from_json(row["metadata_json"] or "{}"),
        "created_at": _parse_datetime(row["created_at"]),
    }


def _to_json(value: dict) -> str:
    return json.dumps(value, default=_json_default, sort_keys=True)


def _from_json(value: str) -> dict:
    decoded = json.loads(value)
    return decoded if isinstance(decoded, dict) else {}


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return _format_datetime(value)

    return str(value)


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)
