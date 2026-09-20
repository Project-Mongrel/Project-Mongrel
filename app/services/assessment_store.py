import sqlite3
from datetime import UTC, datetime

from app.services.findings_store import _get_connection
from app.services.scan_status import TERMINAL_SCAN_STATUSES, normalize_scan_status
from app.services.sqlite_runtime import run_locked_transaction


ASSESSMENT_SCAN_RUNNING_STATUS = "running"
ASSESSMENT_SCAN_TERMINAL_STATUSES = TERMINAL_SCAN_STATUSES


def create_assessment(name: str, description: str | None = None, user_id: int | None = None) -> dict:
    normalized_name = str(name or "").strip()
    if not normalized_name:
        raise ValueError("Assessment name is required.")

    now = datetime.now(UTC)
    with _get_connection() as connection:
        _initialize_schema(connection)
        cursor = connection.execute(
            """
            INSERT INTO assessments (user_id, name, description, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, normalized_name, description, "active", _format_datetime(now), _format_datetime(now)),
        )
        assessment_id = int(cursor.lastrowid)

    assessment = get_assessment(assessment_id)
    if assessment is None:
        raise RuntimeError("Assessment was not created.")
    return assessment


def get_assessment(assessment_id: int) -> dict | None:
    with _get_connection() as connection:
        _initialize_schema(connection)
        row = connection.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
    return _row_to_assessment(row) if row is not None else None


def get_user_assessment(user_id: int, assessment_id: int) -> dict | None:
    with _get_connection() as connection:
        _initialize_schema(connection)
        row = connection.execute(
            "SELECT * FROM assessments WHERE id = ? AND user_id = ?",
            (assessment_id, user_id),
        ).fetchone()
    return _row_to_assessment(row) if row is not None else None


def list_assessments(status: str | None = None) -> list[dict]:
    with _get_connection() as connection:
        _initialize_schema(connection)
        if status is None:
            rows = connection.execute("SELECT * FROM assessments ORDER BY created_at ASC, id ASC").fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM assessments WHERE status = ? ORDER BY created_at ASC, id ASC",
                (status,),
            ).fetchall()
    return [_row_to_assessment(row) for row in rows]


def list_user_assessments(user_id: int, status: str | None = None) -> list[dict]:
    with _get_connection() as connection:
        _initialize_schema(connection)
        if status is None:
            rows = connection.execute(
                "SELECT * FROM assessments WHERE user_id = ? ORDER BY created_at ASC, id ASC",
                (user_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM assessments WHERE user_id = ? AND status = ? ORDER BY created_at ASC, id ASC",
                (user_id, status),
            ).fetchall()
    return [_row_to_assessment(row) for row in rows]


def add_assessment_target(
    assessment_id: int,
    address: str,
    name: str | None = None,
    target_type: str | None = None,
) -> dict:
    normalized_address = str(address or "").strip()
    if not normalized_address:
        raise ValueError("Assessment target address is required.")

    _require_assessment(assessment_id)
    now = datetime.now(UTC)
    with _get_connection() as connection:
        _initialize_schema(connection)
        cursor = connection.execute(
            """
            INSERT INTO assessment_targets (assessment_id, name, address, target_type, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (assessment_id, name, normalized_address, target_type, _format_datetime(now), _format_datetime(now)),
        )
        target_id = int(cursor.lastrowid)

    targets = [target for target in list_assessment_targets(assessment_id) if target["id"] == target_id]
    if not targets:
        raise RuntimeError("Assessment target was not created.")
    return targets[0]


def list_assessment_targets(assessment_id: int) -> list[dict]:
    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(
            """
            SELECT * FROM assessment_targets
            WHERE assessment_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (assessment_id,),
        ).fetchall()
    return [_row_to_target(row) for row in rows]


def record_assessment_scan(
    assessment_id: int,
    tool: str,
    status: str,
    target_id: int | None = None,
    finding_id: int | str | None = None,
    elapsed_seconds: int | None = None,
    risk: str | None = None,
    raw_reference: str | None = None,
) -> dict:
    normalized_tool = str(tool or "").strip().lower()
    normalized_status = normalize_scan_status(status, default="")
    if not normalized_tool:
        raise ValueError("Assessment scan tool is required.")
    if not normalized_status:
        raise ValueError("Assessment scan status is required.")

    _require_assessment(assessment_id)
    if target_id is not None:
        _require_target(assessment_id, target_id)

    now = datetime.now(UTC)
    completed_at = now if normalized_status in ASSESSMENT_SCAN_TERMINAL_STATUSES else None
    connection = _get_connection()

    def insert_scan(active_connection: sqlite3.Connection) -> int:
        _initialize_schema(active_connection)
        cursor = active_connection.execute(
            """
            INSERT INTO assessment_scans (
                assessment_id, target_id, tool, status, started_at, completed_at,
                elapsed_seconds, risk, finding_id, raw_reference, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                target_id,
                normalized_tool,
                normalized_status,
                _format_datetime(now),
                _format_datetime(completed_at) if completed_at else None,
                elapsed_seconds,
                risk,
                str(finding_id) if finding_id is not None else None,
                raw_reference,
                _format_datetime(now),
                _format_datetime(now),
            ),
        )
        return int(cursor.lastrowid)

    scan_id = run_locked_transaction(connection, insert_scan)

    scans = [scan for scan in list_assessment_scans(assessment_id) if scan["id"] == scan_id]
    if not scans:
        raise RuntimeError("Assessment scan was not recorded.")
    return scans[0]


def start_assessment_scan(
    assessment_id: int,
    tool: str,
    target_id: int | None = None,
) -> dict:
    """Durably record an assessment scan immediately before execution begins."""

    return record_assessment_scan(
        assessment_id=assessment_id,
        target_id=target_id,
        tool=tool,
        status=ASSESSMENT_SCAN_RUNNING_STATUS,
    )


def finalize_assessment_scan(
    assessment_id: int,
    scan_id: int,
    status: str,
    *,
    finding_id: int | str | None = None,
    elapsed_seconds: int | None = None,
    risk: str | None = None,
    raw_reference: str | None = None,
) -> dict:
    """Atomically finish a running scan without overwriting another terminal state."""

    normalized_status = normalize_scan_status(status, default="")
    if normalized_status not in ASSESSMENT_SCAN_TERMINAL_STATUSES:
        raise ValueError("Assessment scan terminal status is invalid.")

    now = datetime.now(UTC)
    connection = _get_connection()

    def finalize_scan(active_connection: sqlite3.Connection) -> dict:
        _initialize_schema(active_connection)
        cursor = active_connection.execute(
            """
            UPDATE assessment_scans
            SET status = ?, completed_at = ?, elapsed_seconds = ?, risk = ?,
                finding_id = ?, raw_reference = ?, updated_at = ?
            WHERE id = ? AND assessment_id = ? AND status = ?
            """,
            (
                normalized_status,
                _format_datetime(now),
                elapsed_seconds,
                risk,
                str(finding_id) if finding_id is not None else None,
                raw_reference,
                _format_datetime(now),
                scan_id,
                assessment_id,
                ASSESSMENT_SCAN_RUNNING_STATUS,
            ),
        )
        if cursor.rowcount != 1:
            row = active_connection.execute(
                "SELECT * FROM assessment_scans WHERE id = ? AND assessment_id = ?",
                (scan_id, assessment_id),
            ).fetchone()
            if row is None:
                raise ValueError("Assessment scan not found.")
            return _row_to_scan(row)
        row = active_connection.execute(
            "SELECT * FROM assessment_scans WHERE id = ? AND assessment_id = ?",
            (scan_id, assessment_id),
        ).fetchone()
        return _row_to_scan(row)

    return run_locked_transaction(connection, finalize_scan)


def recover_interrupted_assessment_scans() -> int:
    """Mark scans abandoned by a prior process as interrupted, once."""

    now = _format_datetime(datetime.now(UTC))
    connection = _get_connection()

    def interrupt_running(active_connection: sqlite3.Connection) -> int:
        _initialize_schema(active_connection)
        cursor = active_connection.execute(
            """
            UPDATE assessment_scans
            SET status = 'interrupted', completed_at = ?, updated_at = ?
            WHERE status = ?
            """,
            (now, now, ASSESSMENT_SCAN_RUNNING_STATUS),
        )
        return int(cursor.rowcount)

    return run_locked_transaction(connection, interrupt_running)


def list_assessment_scans(assessment_id: int) -> list[dict]:
    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(
            """
            SELECT * FROM assessment_scans
            WHERE assessment_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (assessment_id,),
        ).fetchall()
    return [_row_to_scan(row) for row in rows]


def add_assessment_artifact(
    assessment_id: int,
    artifact_type: str,
    title: str,
    content: str | None = None,
    scan_id: int | None = None,
    file_path: str | None = None,
) -> dict:
    normalized_type = str(artifact_type or "").strip()
    normalized_title = str(title or "").strip()
    if not normalized_type:
        raise ValueError("Assessment artifact type is required.")
    if not normalized_title:
        raise ValueError("Assessment artifact title is required.")

    _require_assessment(assessment_id)
    if scan_id is not None:
        _require_scan(assessment_id, scan_id)

    now = datetime.now(UTC)
    with _get_connection() as connection:
        _initialize_schema(connection)
        cursor = connection.execute(
            """
            INSERT INTO assessment_artifacts (
                assessment_id, scan_id, artifact_type, title, content, file_path, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (assessment_id, scan_id, normalized_type, normalized_title, content, file_path, _format_datetime(now)),
        )
        artifact_id = int(cursor.lastrowid)

    artifacts = [artifact for artifact in list_assessment_artifacts(assessment_id) if artifact["id"] == artifact_id]
    if not artifacts:
        raise RuntimeError("Assessment artifact was not created.")
    return artifacts[0]


def list_assessment_artifacts(assessment_id: int) -> list[dict]:
    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(
            """
            SELECT * FROM assessment_artifacts
            WHERE assessment_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (assessment_id,),
        ).fetchall()
    return [_row_to_artifact(row) for row in rows]


def add_assessment_note(assessment_id: int, content: str, note_type: str = "manual") -> dict:
    normalized_content = str(content or "").strip()
    normalized_type = str(note_type or "manual").strip() or "manual"
    if not normalized_content:
        raise ValueError("Assessment note content is required.")

    _require_assessment(assessment_id)
    now = datetime.now(UTC)
    with _get_connection() as connection:
        _initialize_schema(connection)
        cursor = connection.execute(
            """
            INSERT INTO assessment_notes (assessment_id, note_type, content, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (assessment_id, normalized_type, normalized_content, _format_datetime(now), _format_datetime(now)),
        )
        note_id = int(cursor.lastrowid)

    notes = [note for note in list_assessment_notes(assessment_id) if note["id"] == note_id]
    if not notes:
        raise RuntimeError("Assessment note was not created.")
    return notes[0]


def list_assessment_notes(assessment_id: int) -> list[dict]:
    with _get_connection() as connection:
        _initialize_schema(connection)
        rows = connection.execute(
            """
            SELECT * FROM assessment_notes
            WHERE assessment_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (assessment_id,),
        ).fetchall()
    return [_row_to_note(row) for row in rows]


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    _ensure_column(connection, "assessments", "user_id", "INTEGER")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            name TEXT,
            address TEXT NOT NULL,
            target_type TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(assessment_id) REFERENCES assessments(id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            target_id INTEGER,
            tool TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            elapsed_seconds INTEGER,
            risk TEXT,
            finding_id TEXT,
            raw_reference TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(assessment_id) REFERENCES assessments(id),
            FOREIGN KEY(target_id) REFERENCES assessment_targets(id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            scan_id INTEGER,
            artifact_type TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT,
            file_path TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(assessment_id) REFERENCES assessments(id),
            FOREIGN KEY(scan_id) REFERENCES assessment_scans(id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            note_type TEXT NOT NULL DEFAULT 'manual',
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(assessment_id) REFERENCES assessments(id)
        )
        """
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_assessment_targets_assessment ON assessment_targets(assessment_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_assessment_scans_assessment ON assessment_scans(assessment_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_assessment_scans_tool ON assessment_scans(tool)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_assessment_artifacts_assessment ON assessment_artifacts(assessment_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_assessment_notes_assessment ON assessment_notes(assessment_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_assessments_user_status ON assessments(user_id, status)")
    connection.commit()


def _require_assessment(assessment_id: int) -> None:
    if get_assessment(assessment_id) is None:
        raise ValueError("Assessment not found.")


def _require_target(assessment_id: int, target_id: int) -> None:
    if not any(target["id"] == target_id for target in list_assessment_targets(assessment_id)):
        raise ValueError("Assessment target not found.")


def _require_scan(assessment_id: int, scan_id: int) -> None:
    if not any(scan["id"] == scan_id for scan in list_assessment_scans(assessment_id)):
        raise ValueError("Assessment scan not found.")


def _ensure_column(connection: sqlite3.Connection, table_name: str, column_name: str, column_type: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()}
    if column_name not in columns:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")


def _row_to_assessment(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "name": row["name"],
        "description": row["description"],
        "status": row["status"],
        "created_at": _parse_datetime(row["created_at"]),
        "updated_at": _parse_datetime(row["updated_at"]),
    }


def _row_to_target(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "assessment_id": row["assessment_id"],
        "name": row["name"],
        "address": row["address"],
        "target_type": row["target_type"],
        "created_at": _parse_datetime(row["created_at"]),
        "updated_at": _parse_datetime(row["updated_at"]),
    }


def _row_to_scan(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "assessment_id": row["assessment_id"],
        "target_id": row["target_id"],
        "tool": row["tool"],
        "status": normalize_scan_status(row["status"]),
        "started_at": _parse_datetime(row["started_at"]) if row["started_at"] else None,
        "completed_at": _parse_datetime(row["completed_at"]) if row["completed_at"] else None,
        "elapsed_seconds": row["elapsed_seconds"],
        "risk": row["risk"],
        "finding_id": row["finding_id"],
        "raw_reference": row["raw_reference"],
        "created_at": _parse_datetime(row["created_at"]),
        "updated_at": _parse_datetime(row["updated_at"]),
    }


def _row_to_artifact(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "assessment_id": row["assessment_id"],
        "scan_id": row["scan_id"],
        "artifact_type": row["artifact_type"],
        "title": row["title"],
        "content": row["content"],
        "file_path": row["file_path"],
        "created_at": _parse_datetime(row["created_at"]),
    }


def _row_to_note(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "assessment_id": row["assessment_id"],
        "note_type": row["note_type"],
        "content": row["content"],
        "created_at": _parse_datetime(row["created_at"]),
        "updated_at": _parse_datetime(row["updated_at"]),
    }


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)
