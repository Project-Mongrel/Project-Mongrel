import json
import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

from app.services.findings_store import _get_connection
from app.services.target_normalizer import normalize_target_key


def add_observation(
    user_id: int,
    source: str,
    observation_type: str,
    value: str,
    investigation_id: str | None = None,
    target: str | None = None,
    target_key: str | None = None,
    confidence: str | None = None,
    risk_level: str | None = None,
    summary: str | None = None,
    metadata: dict | None = None,
) -> dict:
    created_at = datetime.now(UTC)
    observation_id = str(uuid4())
    stored_observation = {
        "id": observation_id,
        "user_id": user_id,
        "investigation_id": investigation_id,
        "source": source,
        "observation_type": observation_type,
        "value": value,
        "target": target,
        "target_key": target_key or normalize_target_key(target),
        "confidence": confidence,
        "risk_level": risk_level,
        "summary": summary,
        "metadata": metadata or {},
        "created_at": created_at,
    }

    with _get_connection() as connection:
        _initialize_schema(connection)
        connection.execute(
            """
            INSERT INTO observations (
                id, user_id, investigation_id, source, observation_type, value,
                target, target_key, confidence, risk_level, summary, metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observation_id,
                user_id,
                investigation_id,
                source,
                observation_type,
                value,
                target,
                stored_observation["target_key"],
                confidence,
                risk_level,
                summary,
                _to_json(stored_observation["metadata"]),
                _format_datetime(created_at),
            ),
        )

    return dict(stored_observation)


def add_observations(observations: list[dict]) -> list[dict]:
    return [add_observation(**observation) for observation in observations]


def get_user_observations(user_id: int, limit: int | None = None) -> list[dict]:
    query = "SELECT * FROM observations WHERE user_id = ? ORDER BY created_at ASC, rowid ASC"
    params: tuple[object, ...] = (user_id,)
    if limit is not None:
        query += " LIMIT ?"
        params = (user_id, limit)

    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(query, params).fetchall()

    return [_row_to_observation(row) for row in rows]


def get_investigation_observations(investigation_id: str, user_id: int, limit: int | None = None) -> list[dict]:
    query = """
        SELECT * FROM observations
        WHERE investigation_id = ? AND user_id = ?
        ORDER BY created_at ASC, rowid ASC
    """
    params: tuple[object, ...] = (investigation_id, user_id)
    if limit is not None:
        query += " LIMIT ?"
        params = (investigation_id, user_id, limit)

    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(query, params).fetchall()

    return [_row_to_observation(row) for row in rows]


def get_observations_by_type(user_id: int, observation_type: str, limit: int | None = None) -> list[dict]:
    query = """
        SELECT * FROM observations
        WHERE user_id = ? AND observation_type = ?
        ORDER BY created_at ASC, rowid ASC
    """
    params: tuple[object, ...] = (user_id, observation_type)
    if limit is not None:
        query += " LIMIT ?"
        params = (user_id, observation_type, limit)

    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(query, params).fetchall()

    return [_row_to_observation(row) for row in rows]


def clear_user_observations(user_id: int) -> None:
    with _get_connection() as connection:
        _initialize_schema(connection)
        connection.execute("DELETE FROM observations WHERE user_id = ?", (user_id,))


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS observations (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            investigation_id TEXT,
            source TEXT NOT NULL,
            observation_type TEXT NOT NULL,
            value TEXT NOT NULL,
            target TEXT,
            target_key TEXT,
            confidence TEXT,
            risk_level TEXT,
            summary TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_observations_user_created ON observations(user_id, created_at)")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_observations_investigation_created ON observations(investigation_id, user_id, created_at)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_observations_user_type ON observations(user_id, observation_type)")
    connection.commit()


def _row_to_observation(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "investigation_id": row["investigation_id"],
        "source": row["source"],
        "observation_type": row["observation_type"],
        "value": row["value"],
        "target": row["target"],
        "target_key": row["target_key"],
        "confidence": row["confidence"],
        "risk_level": row["risk_level"],
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
