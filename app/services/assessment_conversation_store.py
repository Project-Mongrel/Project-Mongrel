import json
import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

from app.services.assessment_store import get_user_assessment
from app.services.findings_store import _get_connection

MESSAGE_ROLES = {"user", "assistant"}
CONVERSATION_STATUS_VALUES = {"active", "archived"}


def create_conversation(
    assessment_id: int,
    user_id: int,
    title: str | None = None,
    status: str = "active",
    summary: str | None = None,
    metadata: dict | None = None,
) -> dict:
    _require_user_assessment(user_id, assessment_id)
    normalized_status = _normalize_status(status)
    now = datetime.now(UTC)
    conversation_id = str(uuid4())
    with _get_connection() as connection:
        _initialize_schema(connection)
        connection.execute(
            """
            INSERT INTO assessment_conversations (
                id, assessment_id, user_id, title, status, summary,
                created_at, updated_at, last_message_at, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                conversation_id,
                assessment_id,
                user_id,
                _normalize_optional_text(title),
                normalized_status,
                _normalize_optional_text(summary),
                _format_datetime(now),
                _format_datetime(now),
                _format_datetime(now),
                _to_json(_safe_mapping(metadata)),
            ),
        )

    conversation = get_user_conversation(user_id, conversation_id)
    if conversation is None:
        raise RuntimeError("Assessment conversation was not created.")
    return conversation


def get_user_conversation(user_id: int, conversation_id: str) -> dict | None:
    with _get_connection() as connection:
        _initialize_schema(connection)
        row = connection.execute(
            """
            SELECT * FROM assessment_conversations
            WHERE id = ? AND user_id = ?
            """,
            (str(conversation_id), user_id),
        ).fetchone()
    return _row_to_conversation(row) if row is not None else None


def get_latest_assessment_conversation(user_id: int, assessment_id: int) -> dict | None:
    _require_user_assessment(user_id, assessment_id)
    with _get_connection() as connection:
        _initialize_schema(connection)
        row = connection.execute(
            """
            SELECT * FROM assessment_conversations
            WHERE user_id = ? AND assessment_id = ? AND status = 'active'
            ORDER BY last_message_at DESC, created_at DESC, rowid DESC
            LIMIT 1
            """,
            (user_id, assessment_id),
        ).fetchone()
    return _row_to_conversation(row) if row is not None else None


def get_or_create_assessment_conversation(
    user_id: int,
    assessment_id: int,
    title: str | None = None,
    metadata: dict | None = None,
) -> dict:
    existing = get_latest_assessment_conversation(user_id, assessment_id)
    if existing is not None:
        return existing
    return create_conversation(assessment_id=assessment_id, user_id=user_id, title=title, metadata=metadata)


def list_user_conversations_for_assessment(user_id: int, assessment_id: int) -> list[dict]:
    _require_user_assessment(user_id, assessment_id)
    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(
            """
            SELECT * FROM assessment_conversations
            WHERE user_id = ? AND assessment_id = ?
            ORDER BY last_message_at DESC, created_at DESC, rowid DESC
            """,
            (user_id, assessment_id),
        ).fetchall()
    return [_row_to_conversation(row) for row in rows]


def append_message(
    conversation_id: str,
    user_id: int,
    role: str,
    content: str,
    *,
    assessment_id: int | None = None,
    evidence_refs: dict | None = None,
    evidence_context_digest: str | None = None,
    metadata: dict | None = None,
) -> dict:
    normalized_role = str(role or "").strip().lower()
    if normalized_role not in MESSAGE_ROLES:
        raise ValueError("Unsupported assessment conversation message role.")
    normalized_content = str(content or "").strip()
    if not normalized_content:
        raise ValueError("Assessment conversation message content is required.")

    conversation = get_user_conversation(user_id, conversation_id)
    if conversation is None:
        raise ValueError("Assessment conversation not found.")
    if assessment_id is not None and int(assessment_id) != int(conversation["assessment_id"]):
        raise ValueError("Assessment conversation does not belong to the requested assessment.")

    now = datetime.now(UTC)
    message_id = str(uuid4())
    with _get_connection() as connection:
        _initialize_schema(connection)
        connection.execute(
            """
            INSERT INTO assessment_conversation_messages (
                id, conversation_id, assessment_id, user_id, role, content,
                evidence_refs_json, evidence_context_digest, created_at, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message_id,
                conversation["id"],
                conversation["assessment_id"],
                user_id,
                normalized_role,
                normalized_content,
                _to_json(_safe_mapping(evidence_refs)),
                _normalize_optional_text(evidence_context_digest),
                _format_datetime(now),
                _to_json(_safe_mapping(metadata)),
            ),
        )
        connection.execute(
            """
            UPDATE assessment_conversations
            SET updated_at = ?, last_message_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (_format_datetime(now), _format_datetime(now), conversation["id"], user_id),
        )

    messages = [message for message in list_recent_messages(user_id, conversation_id, limit=1) if message["id"] == message_id]
    if not messages:
        raise RuntimeError("Assessment conversation message was not created.")
    return messages[0]


def list_recent_messages(user_id: int, conversation_id: str, limit: int = 20) -> list[dict]:
    conversation = get_user_conversation(user_id, conversation_id)
    if conversation is None:
        return []
    safe_limit = max(0, int(limit or 0))
    if safe_limit == 0:
        return []
    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(
            """
            SELECT * FROM assessment_conversation_messages
            WHERE conversation_id = ? AND user_id = ?
            ORDER BY created_at DESC, rowid DESC
            LIMIT ?
            """,
            (conversation["id"], user_id, safe_limit),
        ).fetchall()
    return [_row_to_message(row) for row in reversed(rows)]


def update_summary_status(
    user_id: int,
    conversation_id: str,
    *,
    summary: str | None = None,
    status: str | None = None,
    metadata: dict | None = None,
) -> dict:
    conversation = get_user_conversation(user_id, conversation_id)
    if conversation is None:
        raise ValueError("Assessment conversation not found.")

    next_summary = conversation["summary"] if summary is None else str(summary)
    next_status = conversation["status"] if status is None else _normalize_status(status)
    next_metadata = conversation["metadata"] if metadata is None else _safe_mapping(metadata)

    with _get_connection() as connection:
        _initialize_schema(connection)
        connection.execute(
            """
            UPDATE assessment_conversations
            SET summary = ?, status = ?, metadata_json = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                next_summary,
                next_status,
                _to_json(next_metadata),
                _format_datetime(datetime.now(UTC)),
                conversation["id"],
                user_id,
            ),
        )

    updated = get_user_conversation(user_id, conversation_id)
    if updated is None:
        raise RuntimeError("Assessment conversation was not updated.")
    return updated


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_conversations (
            id TEXT PRIMARY KEY,
            assessment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            title TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            summary TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_message_at TEXT NOT NULL,
            metadata_json TEXT,
            FOREIGN KEY(assessment_id) REFERENCES assessments(id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_conversation_messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            assessment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            evidence_refs_json TEXT,
            evidence_context_digest TEXT,
            created_at TEXT NOT NULL,
            metadata_json TEXT,
            FOREIGN KEY(conversation_id) REFERENCES assessment_conversations(id),
            FOREIGN KEY(assessment_id) REFERENCES assessments(id)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_conversations_user_assessment ON assessment_conversations(user_id, assessment_id, last_message_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_conversation_messages_conversation ON assessment_conversation_messages(conversation_id, created_at)"
    )
    connection.commit()


def _require_user_assessment(user_id: int, assessment_id: int) -> None:
    if get_user_assessment(user_id, assessment_id) is None:
        raise ValueError("Assessment not found for user.")


def _normalize_status(status: str) -> str:
    normalized = str(status or "").strip().lower()
    if normalized not in CONVERSATION_STATUS_VALUES:
        raise ValueError("Unsupported assessment conversation status.")
    return normalized


def _normalize_optional_text(value: object | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _safe_mapping(value: object | None) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def _to_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, default=_json_default)


def _from_json(value: str | None) -> dict:
    if not value:
        return {}
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _row_to_conversation(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "assessment_id": row["assessment_id"],
        "user_id": row["user_id"],
        "title": row["title"],
        "status": row["status"],
        "summary": row["summary"],
        "created_at": _parse_datetime(row["created_at"]),
        "updated_at": _parse_datetime(row["updated_at"]),
        "last_message_at": _parse_datetime(row["last_message_at"]),
        "metadata": _from_json(row["metadata_json"]),
    }


def _row_to_message(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "conversation_id": row["conversation_id"],
        "assessment_id": row["assessment_id"],
        "user_id": row["user_id"],
        "role": row["role"],
        "content": row["content"],
        "evidence_refs": _from_json(row["evidence_refs_json"]),
        "evidence_context_digest": row["evidence_context_digest"],
        "created_at": _parse_datetime(row["created_at"]),
        "metadata": _from_json(row["metadata_json"]),
    }


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return _format_datetime(value)
    return str(value)


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)
