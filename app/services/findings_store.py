import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.core.config import get_settings
from app.services.target_normalizer import normalize_target_key

_connection_state = threading.local()
_database_path_override: Path | None = None
_database_generation = 0


def configure_findings_database(database_path: Path | str | None) -> None:
    global _database_path_override, _database_generation
    close_findings_database()
    _database_path_override = Path(database_path) if database_path is not None else None
    _database_generation += 1


def close_findings_database() -> None:
    connection = getattr(_connection_state, "connection", None)
    if connection is not None:
        connection.close()
    _connection_state.connection = None
    _connection_state.generation = None


def add_finding(user_id: int, finding: dict) -> dict:
    created_at = datetime.now(UTC)
    finding_id = str(uuid4())
    scan_run_id = str(uuid4())
    stored_finding = {
        **finding,
        "id": finding_id,
        "scan_run_id": scan_run_id,
        "user_id": user_id,
        "created_at": created_at,
    }
    target = stored_finding.get("target")
    target_key = stored_finding.get("target_key") or normalize_target_key(target)
    if target_key is not None:
        stored_finding["target_key"] = target_key

    with _get_connection() as connection:
        connection.execute(
            """
            INSERT INTO scan_runs (
                id, user_id, source, target, target_key, risk_level, finding_count,
                status, summary, raw_output, data_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_run_id,
                user_id,
                stored_finding.get("source"),
                target,
                target_key,
                stored_finding.get("risk_level"),
                _derive_finding_count(stored_finding),
                stored_finding.get("status"),
                stored_finding.get("summary"),
                stored_finding.get("raw_output") or stored_finding.get("output"),
                _to_json(stored_finding),
                _format_datetime(created_at),
            ),
        )
        connection.execute(
            """
            INSERT INTO findings (
                id, scan_run_id, user_id, source, target, target_key, risk_level,
                finding_count, status, summary, data_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                scan_run_id,
                user_id,
                stored_finding.get("source"),
                target,
                target_key,
                stored_finding.get("risk_level"),
                _derive_finding_count(stored_finding),
                stored_finding.get("status"),
                stored_finding.get("summary"),
                _to_json(stored_finding),
                _format_datetime(created_at),
            ),
        )

    return dict(stored_finding)


def get_user_findings(user_id: int) -> list[dict]:
    rows = _get_connection().execute(
        "SELECT data_json FROM findings WHERE user_id = ? ORDER BY created_at ASC, rowid ASC",
        (user_id,),
    )
    return [_from_json(row["data_json"]) for row in rows.fetchall()]


def get_user_finding(user_id: int, finding_id: str) -> dict | None:
    row = _get_connection().execute(
        "SELECT data_json FROM findings WHERE user_id = ? AND id = ?",
        (user_id, finding_id),
    ).fetchone()
    if row is None:
        return None

    return _from_json(row["data_json"])


def get_latest_user_finding_for_target(
    user_id: int,
    target: str | None,
    sources: str | set[str] | list[str] | tuple[str, ...] | None = None,
) -> dict | None:
    target_key = normalize_target_key(target)
    if target_key is None:
        return None
    allowed_sources = _normalize_source_filter(sources)

    rows = _get_connection().execute(
        "SELECT data_json, target, target_key, source FROM findings WHERE user_id = ? ORDER BY created_at DESC, rowid DESC",
        (user_id,),
    )
    for row in rows.fetchall():
        if allowed_sources is not None and row["source"] not in allowed_sources:
            continue
        finding_target_key = row["target_key"] or normalize_target_key(row["target"])
        if finding_target_key == target_key:
            return _from_json(row["data_json"])

    return None


def clear_user_findings(user_id: int) -> None:
    with _get_connection() as connection:
        connection.execute("DELETE FROM findings WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM scan_runs WHERE user_id = ?", (user_id,))


def get_user_scan_runs(user_id: int) -> list[dict]:
    rows = _get_connection().execute(
        "SELECT data_json FROM scan_runs WHERE user_id = ? ORDER BY created_at ASC, rowid ASC",
        (user_id,),
    )
    return [_from_json(row["data_json"]) for row in rows.fetchall()]


def add_report_metadata(user_id: int, metadata: dict) -> dict:
    generated_at = metadata.get("generated_at") if isinstance(metadata.get("generated_at"), datetime) else datetime.now(UTC)
    report_id = str(uuid4())
    readable_report_id = metadata.get("report_id")
    with _get_connection() as connection:
        if not readable_report_id:
            readable_report_id = _generate_readable_report_id(connection, user_id, generated_at)
    stored_metadata = {
        **metadata,
        "report_id": readable_report_id,
        "id": report_id,
        "user_id": user_id,
        "generated_at": generated_at,
        "created_at": generated_at,
    }
    with _get_connection() as connection:
        connection.execute(
            """
            INSERT INTO report_metadata (
                id, user_id, target, report_type, title, summary, overall_risk,
                source_count, scan_count, metadata_json, data_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                user_id,
                stored_metadata.get("target"),
                stored_metadata.get("report_type"),
                stored_metadata.get("title"),
                stored_metadata.get("summary"),
                stored_metadata.get("overall_risk"),
                stored_metadata.get("source_count"),
                stored_metadata.get("scan_count"),
                _to_json(stored_metadata),
                _to_json(stored_metadata),
                _format_datetime(generated_at),
            ),
        )

    return dict(stored_metadata)


def get_user_reports(user_id: int) -> list[dict]:
    rows = _get_connection().execute(
        "SELECT metadata_json, data_json FROM report_metadata WHERE user_id = ? ORDER BY created_at ASC, rowid ASC",
        (user_id,),
    )
    return [_from_json(row["metadata_json"] or row["data_json"]) for row in rows.fetchall()]


def get_user_report(user_id: int, report_id: str) -> dict | None:
    row = _get_connection().execute(
        "SELECT metadata_json, data_json FROM report_metadata WHERE user_id = ? AND id = ?",
        (user_id, report_id),
    ).fetchone()
    if row is None:
        return None

    return _from_json(row["metadata_json"] or row["data_json"])


def get_latest_user_report(user_id: int) -> dict | None:
    row = _get_connection().execute(
        "SELECT metadata_json, data_json FROM report_metadata WHERE user_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    if row is None:
        return None

    return _from_json(row["metadata_json"] or row["data_json"])


def clear_user_reports(user_id: int) -> None:
    with _get_connection() as connection:
        connection.execute("DELETE FROM report_metadata WHERE user_id = ?", (user_id,))


def _get_connection() -> sqlite3.Connection:
    connection = getattr(_connection_state, "connection", None)
    connection_generation = getattr(_connection_state, "generation", None)
    if connection is not None and connection_generation != _database_generation:
        connection.close()
        connection = None

    if connection is None:
        database_path = _resolve_database_path()
        if str(database_path) != ":memory:":
            database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database_path)
        connection.row_factory = sqlite3.Row
        _initialize_schema(connection)
        _connection_state.connection = connection
        _connection_state.generation = _database_generation

    return connection


def _resolve_database_path() -> Path:
    if _database_path_override is not None:
        return _database_path_override

    return get_settings().database_path


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            source TEXT,
            target TEXT,
            target_key TEXT,
            risk_level TEXT,
            finding_count INTEGER,
            status TEXT,
            summary TEXT,
            raw_output TEXT,
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_run_id TEXT,
            user_id INTEGER NOT NULL,
            source TEXT,
            target TEXT,
            target_key TEXT,
            risk_level TEXT,
            finding_count INTEGER,
            status TEXT,
            summary TEXT,
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS report_metadata (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            target TEXT,
            report_type TEXT,
            title TEXT,
            status TEXT,
            summary TEXT,
            overall_risk TEXT,
            source_count INTEGER,
            scan_count INTEGER,
            metadata_json TEXT NOT NULL,
            data_json TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    _ensure_column(connection, "report_metadata", "target", "TEXT")
    _ensure_column(connection, "report_metadata", "report_type", "TEXT")
    _ensure_column(connection, "report_metadata", "status", "TEXT")
    _ensure_column(connection, "report_metadata", "summary", "TEXT")
    _ensure_column(connection, "report_metadata", "overall_risk", "TEXT")
    _ensure_column(connection, "report_metadata", "source_count", "INTEGER")
    _ensure_column(connection, "report_metadata", "scan_count", "INTEGER")
    _ensure_column(connection, "report_metadata", "metadata_json", "TEXT")
    _ensure_column(connection, "report_metadata", "data_json", "TEXT")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_findings_user_created ON findings(user_id, created_at)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_findings_user_target_key ON findings(user_id, target_key)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_user_created ON scan_runs(user_id, created_at)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_report_metadata_user_created ON report_metadata(user_id, created_at)")
    connection.commit()


def _ensure_column(connection: sqlite3.Connection, table_name: str, column_name: str, column_type: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()}
    if column_name not in columns:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")


def _generate_readable_report_id(connection: sqlite3.Connection, user_id: int, generated_at: datetime) -> str:
    report_count = connection.execute("SELECT COUNT(*) AS report_count FROM report_metadata WHERE user_id = ?", (user_id,)).fetchone()[
        "report_count"
    ]
    return f"PM-{generated_at.astimezone(UTC):%Y%m%d}-{int(report_count) + 1:04d}"


def _derive_finding_count(finding: dict) -> int:
    if finding.get("finding_count") is not None:
        return int(finding.get("finding_count") or 0)

    if isinstance(finding.get("nuclei_findings"), list):
        return len(finding.get("nuclei_findings") or [])

    if isinstance(finding.get("open_ports"), list):
        return len(finding.get("open_ports") or [])

    return 0


def _normalize_source_filter(sources: str | set[str] | list[str] | tuple[str, ...] | None) -> set[str] | None:
    if sources is None:
        return None
    if isinstance(sources, str):
        return {sources}

    return {str(source) for source in sources}


def _to_json(value: dict) -> str:
    return json.dumps(value, default=_json_default, sort_keys=True)


def _from_json(value: str) -> dict:
    decoded = json.loads(value)
    if isinstance(decoded.get("created_at"), str):
        decoded["created_at"] = _parse_datetime(decoded["created_at"])
    if isinstance(decoded.get("generated_at"), str):
        decoded["generated_at"] = _parse_datetime(decoded["generated_at"])

    return decoded


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return _format_datetime(value)

    return str(value)


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)
