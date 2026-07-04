import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

_connection_state = threading.local()
_database_path_override: Path | None = None
_key_override: str | None = None
_key_override_set = False
_database_generation = 0


class EvidenceVaultUnavailable(RuntimeError):
    pass


class EvidenceVaultDecryptError(RuntimeError):
    pass


def configure_evidence_vault(database_path: Path | str | None = None, key: str | None = None) -> None:
    global _database_path_override, _key_override, _key_override_set, _database_generation
    close_evidence_vault()
    _database_path_override = Path(database_path) if database_path is not None else None
    _key_override = key
    _key_override_set = database_path is not None or key is not None
    _database_generation += 1


def close_evidence_vault() -> None:
    connection = getattr(_connection_state, "connection", None)
    if connection is not None:
        connection.close()
    _connection_state.connection = None
    _connection_state.generation = None


def store_secret_evidence(
    *,
    assessment_id: str | None,
    finding_reference: dict,
    secret_payload: dict,
) -> dict:
    fernet = _get_fernet()
    created_at = _format_datetime(datetime.now(UTC))
    evidence_id = str(uuid4())
    encrypted_payload = fernet.encrypt(_to_json(secret_payload).encode("utf-8")).decode("utf-8")
    record = {
        "evidence_id": evidence_id,
        "assessment_id": assessment_id or "",
        "finding_reference": finding_reference,
        "encrypted_secret_payload": encrypted_payload,
        "created_at": created_at,
        "reveal_audit": [],
    }
    with _get_connection() as connection:
        connection.execute(
            """
            INSERT INTO secret_evidence_vault (
                evidence_id, assessment_id, finding_reference_json, encrypted_secret_payload,
                created_at, reveal_audit_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                record["evidence_id"],
                record["assessment_id"],
                _to_json(finding_reference),
                encrypted_payload,
                created_at,
                _to_json(record["reveal_audit"]),
            ),
        )
    return record


def reveal_secret_evidence(evidence_id: str, reveal_metadata: dict | None = None) -> dict:
    fernet = _get_fernet()
    row = _get_connection().execute(
        """
        SELECT evidence_id, assessment_id, finding_reference_json, encrypted_secret_payload,
               created_at, reveal_audit_json
        FROM secret_evidence_vault
        WHERE evidence_id = ?
        """,
        (evidence_id,),
    ).fetchone()
    if row is None:
        raise KeyError(evidence_id)
    try:
        payload = json.loads(fernet.decrypt(row["encrypted_secret_payload"].encode("utf-8")).decode("utf-8"))
    except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceVaultDecryptError("Unable to decrypt evidence vault payload.") from exc

    audit = _from_json(row["reveal_audit_json"]) or []
    audit_entry = {
        "revealed_at": _format_datetime(datetime.now(UTC)),
        "metadata": reveal_metadata or {},
    }
    audit.append(audit_entry)
    with _get_connection() as connection:
        connection.execute(
            "UPDATE secret_evidence_vault SET reveal_audit_json = ? WHERE evidence_id = ?",
            (_to_json(audit), evidence_id),
        )

    return {
        "evidence_id": row["evidence_id"],
        "assessment_id": row["assessment_id"],
        "finding_reference": _from_json(row["finding_reference_json"]) or {},
        "secret_payload": payload,
        "created_at": row["created_at"],
        "reveal_audit": audit,
    }


def _get_fernet() -> Fernet:
    key = _key_override if _key_override_set else get_settings().evidence_vault_key
    if not key:
        raise EvidenceVaultUnavailable("Evidence vault encryption key is not configured.")
    try:
        return Fernet(key.encode("utf-8") if isinstance(key, str) else key)
    except (TypeError, ValueError) as exc:
        raise EvidenceVaultUnavailable("Evidence vault encryption key is invalid.") from exc


def _get_connection() -> sqlite3.Connection:
    connection = getattr(_connection_state, "connection", None)
    generation = getattr(_connection_state, "generation", None)
    if connection is None or generation != _database_generation:
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
    return get_settings().evidence_vault_path


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS secret_evidence_vault (
            evidence_id TEXT PRIMARY KEY,
            assessment_id TEXT,
            finding_reference_json TEXT NOT NULL,
            encrypted_secret_payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            reveal_audit_json TEXT NOT NULL
        )
        """
    )
    connection.commit()


def _to_json(value: object) -> str:
    return json.dumps(value, default=str, sort_keys=True)


def _from_json(value: str | None) -> object:
    if not value:
        return None
    return json.loads(value)


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
