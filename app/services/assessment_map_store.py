"""Owner-scoped persistence primitives for the assessment relationship map."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from datetime import UTC, datetime
from typing import Any

from app.services.assessment_map_identity import (
    IDENTITY_SCHEMA_VERSION,
    CanonicalIdentity,
    ENTITY_TYPES,
    identity_from_payload,
)
from app.services.assessment_store import _initialize_schema as _initialize_assessment_schema
from app.services.findings_store import _get_connection
from app.services.sqlite_runtime import run_locked_transaction

MAP_SCHEMA_VERSION = 1
MAX_LOOKUP_LIMIT = 100
_PREDICATE_PATTERN = re.compile(r"[a-z][a-z0-9_:-]{0,63}")
_schema_lock = threading.Lock()
_MISSING = object()
_TERMINAL_VALIDATION_EXECUTION_STATES = frozenset(
    {"completed", "executed", "failed", "partial", "timed_out", "cancelled", "interrupted"}
)


class AssessmentMapScopeError(ValueError):
    pass


class AssessmentMapIdentityCollisionError(RuntimeError):
    pass


def initialize_assessment_map_schema() -> None:
    connection = _get_connection()
    with _schema_lock:
        if not _table_exists(connection, "assessments"):
            _initialize_assessment_schema(connection)
        run_locked_transaction(connection, _create_schema_transaction)


def _create_schema_transaction(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")
    _create_schema(connection)


def get_or_create_entity(
    *,
    user_id: int,
    assessment_id: int,
    identity: CanonicalIdentity,
    display_value: str | None = None,
    attributes: dict | None = None,
) -> dict:
    _prepare_scope(user_id, assessment_id)
    _validate_canonical_identity(identity)
    now = _now()
    connection = _get_connection()

    def operation(active: sqlite3.Connection) -> dict:
        existing = _entity_by_hash(
            active, user_id, assessment_id, identity.entity_type, identity.identity_hash
        )
        if existing is not None:
            _verify_identity(existing, identity)
            return _row_dict(existing)
        active.execute(
            """
            INSERT OR IGNORE INTO assessment_map_entities (
                assessment_id, user_id, entity_type, identity_version, identity_hash,
                canonical_key, display_value, attributes_json, first_seen_at, last_seen_at,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id, user_id, identity.entity_type, identity.version, identity.identity_hash,
                identity.canonical_key, _optional_text(display_value), _json(attributes or {}),
                now, now, now, now,
            ),
        )
        row = _entity_by_hash(
            active, user_id, assessment_id, identity.entity_type, identity.identity_hash
        )
        if row is None:
            raise RuntimeError("Assessment-map entity was not created.")
        _verify_identity(row, identity)
        return _row_dict(row)

    return run_locked_transaction(connection, operation)


def get_or_create_assertion(
    *,
    user_id: int,
    assessment_id: int,
    subject_entity_id: int,
    predicate: str,
    object_entity_id: int | None = None,
    value: Any = _MISSING,
    polarity: str = "observed",
    attributes: dict | None = None,
) -> dict:
    _prepare_scope(user_id, assessment_id)
    normalized_predicate = str(predicate or "").strip().lower()
    normalized_polarity = str(polarity or "").strip().lower()
    if not _PREDICATE_PATTERN.fullmatch(normalized_predicate):
        raise ValueError("Invalid assessment-map predicate.")
    if not normalized_polarity:
        raise ValueError("Assertion polarity is required.")
    if object_entity_id is None and value is _MISSING:
        raise ValueError("Assertion requires an object entity or explicit value.")
    connection = _get_connection()
    subject = _require_entity(connection, user_id, assessment_id, subject_entity_id)
    object_entity = (
        _require_entity(connection, user_id, assessment_id, object_entity_id)
        if object_entity_id is not None
        else None
    )
    value_json = None if value is _MISSING else _json(value)
    canonical = {
        "object_hash": object_entity["identity_hash"] if object_entity is not None else None,
        "polarity": normalized_polarity,
        "predicate": normalized_predicate,
        "subject_hash": subject["identity_hash"],
        "value": None if value is _MISSING else value,
        "value_present": value is not _MISSING,
        "version": "assessment-map.assertion.v1",
    }
    canonical_key = _json(canonical)
    assertion_hash = hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()
    now = _now()

    def operation(active: sqlite3.Connection) -> dict:
        existing = active.execute(
            """SELECT * FROM assessment_map_assertions
               WHERE assessment_id = ? AND user_id = ? AND assertion_hash = ?""",
            (assessment_id, user_id, assertion_hash),
        ).fetchone()
        if existing is not None:
            if existing["canonical_key"] != canonical_key:
                raise AssessmentMapIdentityCollisionError("Assessment-map assertion hash collision detected.")
            return _row_dict(existing)
        active.execute(
            """
            INSERT OR IGNORE INTO assessment_map_assertions (
                assessment_id, user_id, subject_entity_id, predicate, object_entity_id,
                normalized_value_json, polarity, assertion_hash, canonical_key,
                attributes_json, first_seen_at, last_seen_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id, user_id, subject_entity_id, normalized_predicate, object_entity_id,
                value_json, normalized_polarity, assertion_hash, canonical_key, _json(attributes or {}),
                now, now, now, now,
            ),
        )
        row = active.execute(
            """SELECT * FROM assessment_map_assertions
               WHERE assessment_id = ? AND user_id = ? AND assertion_hash = ?""",
            (assessment_id, user_id, assertion_hash),
        ).fetchone()
        if row is None:
            raise RuntimeError("Assessment-map assertion was not created.")
        if row["canonical_key"] != canonical_key:
            raise AssessmentMapIdentityCollisionError("Assessment-map assertion hash collision detected.")
        return _row_dict(row)

    return run_locked_transaction(connection, operation)


def attach_evidence(
    *,
    user_id: int,
    assessment_id: int,
    source_tool: str,
    evidence_kind: str,
    evidence_fingerprint: str,
    entity_id: int | None = None,
    assertion_id: int | None = None,
    scan_id: int | None = None,
    finding_id: str | None = None,
    artifact_id: int | None = None,
    evidence_path: str | None = None,
    observed_at: str | None = None,
    confidence: str | None = None,
    metadata: dict | None = None,
) -> dict:
    _prepare_scope(user_id, assessment_id)
    if (entity_id is None) == (assertion_id is None):
        raise ValueError("Evidence must target exactly one entity or assertion.")
    if scan_id is None and finding_id is None and artifact_id is None:
        raise ValueError("Evidence requires at least one stored source reference.")
    fingerprint = str(evidence_fingerprint or "").strip()
    tool = str(source_tool or "").strip().lower().removesuffix(".sh")
    kind = str(evidence_kind or "").strip().lower()
    if not fingerprint or not tool or not kind:
        raise ValueError("Evidence tool, kind and fingerprint are required.")
    connection = _get_connection()
    if entity_id is not None:
        _require_entity(connection, user_id, assessment_id, entity_id)
        destination_type, destination_id = "entity", entity_id
    else:
        _require_assertion(connection, user_id, assessment_id, int(assertion_id))
        destination_type, destination_id = "assertion", int(assertion_id)
    _require_evidence_sources(connection, user_id, assessment_id, scan_id, finding_id, artifact_id)
    now = _now()

    def operation(active: sqlite3.Connection) -> dict:
        existing = active.execute(
            """SELECT * FROM assessment_map_evidence_links
               WHERE assessment_id = ? AND user_id = ? AND destination_type = ?
                 AND destination_id = ? AND evidence_fingerprint = ?""",
            (assessment_id, user_id, destination_type, destination_id, fingerprint),
        ).fetchone()
        if existing is not None:
            _verify_evidence_identity(
                existing,
                scan_id=scan_id,
                finding_id=finding_id,
                artifact_id=artifact_id,
                source_tool=tool,
                evidence_kind=kind,
                evidence_path=_optional_text(evidence_path),
            )
            return _row_dict(existing)
        active.execute(
            """
            INSERT OR IGNORE INTO assessment_map_evidence_links (
                assessment_id, user_id, destination_type, destination_id, entity_id,
                assertion_id, scan_id, finding_id, artifact_id, source_tool,
                evidence_kind, evidence_path, evidence_fingerprint, observed_at,
                confidence, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id, user_id, destination_type, destination_id, entity_id,
                assertion_id, scan_id, finding_id, artifact_id, tool, kind,
                _optional_text(evidence_path), fingerprint, observed_at, _optional_text(confidence),
                _json(metadata or {}), now,
            ),
        )
        row = active.execute(
            """SELECT * FROM assessment_map_evidence_links
               WHERE assessment_id = ? AND user_id = ? AND destination_type = ?
                 AND destination_id = ? AND evidence_fingerprint = ?""",
            (assessment_id, user_id, destination_type, destination_id, fingerprint),
        ).fetchone()
        if row is None:
            raise RuntimeError("Assessment-map evidence link was not created.")
        _verify_evidence_identity(
            row,
            scan_id=scan_id,
            finding_id=finding_id,
            artifact_id=artifact_id,
            source_tool=tool,
            evidence_kind=kind,
            evidence_path=_optional_text(evidence_path),
        )
        return _row_dict(row)

    return run_locked_transaction(connection, operation)


def create_or_update_validation_attempt(
    *,
    user_id: int,
    assessment_id: int,
    attempt_key: str,
    tool: str,
    request_fingerprint: str,
    approval_status: str,
    execution_status: str,
    validation_state: str | None = None,
    proposal_id: str | None = None,
    target_entity_id: int | None = None,
    service_entity_id: int | None = None,
    finding_entity_id: int | None = None,
    scan_id: int | None = None,
    artifact_id: int | None = None,
    module: str | None = None,
    action_type: str | None = None,
    session_established: bool | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    limitations: list[str] | None = None,
) -> dict:
    _prepare_scope(user_id, assessment_id)
    key = str(attempt_key or "").strip()
    normalized_tool = str(tool or "").strip().lower().removesuffix(".sh")
    fingerprint = str(request_fingerprint or "").strip()
    if not key or not normalized_tool or not fingerprint:
        raise ValueError("Validation attempt key, tool and request fingerprint are required.")
    connection = _get_connection()
    for entity_id in (target_entity_id, service_entity_id, finding_entity_id):
        if entity_id is not None:
            _require_entity(connection, user_id, assessment_id, entity_id)
    _require_evidence_sources(connection, user_id, assessment_id, scan_id, None, artifact_id, allow_empty=True)
    if proposal_id is not None:
        proposal = connection.execute(
            "SELECT user_id, assessment_context_json FROM metasploit_proposals WHERE id = ?",
            (str(proposal_id),),
        ).fetchone()
        if (
            proposal is None
            or int(proposal["user_id"]) != int(user_id)
            or _proposal_assessment_id(proposal) != int(assessment_id)
        ):
            raise AssessmentMapScopeError("Validation proposal is outside the assessment owner scope.")
    now = _now()

    def operation(active: sqlite3.Connection) -> dict:
        existing = active.execute(
            """SELECT * FROM assessment_validation_attempts
               WHERE assessment_id = ? AND user_id = ? AND attempt_key = ?""",
            (assessment_id, user_id, key),
        ).fetchone()
        if existing is not None:
            _verify_validation_attempt_identity(
                existing,
                tool=normalized_tool,
                proposal_id=_optional_text(proposal_id),
                request_fingerprint=fingerprint,
                target_entity_id=target_entity_id,
                service_entity_id=service_entity_id,
                finding_entity_id=finding_entity_id,
                module=_optional_text(module),
                action_type=_optional_text(action_type),
            )
            _verify_validation_state_transition(
                existing,
                approval_status=str(approval_status),
                execution_status=str(execution_status),
                validation_state=_optional_text(validation_state),
            )
        active.execute(
            """
            INSERT INTO assessment_validation_attempts (
                assessment_id, user_id, attempt_key, tool, proposal_id, request_fingerprint,
                target_entity_id, service_entity_id, finding_entity_id, scan_id, artifact_id,
                approval_status, execution_status, validation_state, module, action_type,
                session_established, started_at, completed_at, limitations_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(assessment_id, user_id, attempt_key) DO UPDATE SET
                approval_status = excluded.approval_status,
                execution_status = excluded.execution_status,
                validation_state = excluded.validation_state,
                scan_id = COALESCE(excluded.scan_id, assessment_validation_attempts.scan_id),
                artifact_id = COALESCE(excluded.artifact_id, assessment_validation_attempts.artifact_id),
                session_established = excluded.session_established,
                completed_at = excluded.completed_at,
                limitations_json = excluded.limitations_json,
                updated_at = excluded.updated_at
            """,
            (
                assessment_id, user_id, key, normalized_tool, proposal_id, fingerprint,
                target_entity_id, service_entity_id, finding_entity_id, scan_id, artifact_id,
                str(approval_status), str(execution_status), _optional_text(validation_state),
                _optional_text(module), _optional_text(action_type),
                None if session_established is None else int(session_established),
                started_at, completed_at, _json(limitations or []), now, now,
            ),
        )
        row = active.execute(
            """SELECT * FROM assessment_validation_attempts
               WHERE assessment_id = ? AND user_id = ? AND attempt_key = ?""",
            (assessment_id, user_id, key),
        ).fetchone()
        return _row_dict(row)

    return run_locked_transaction(connection, operation)


def write_ingestion_ledger(
    *,
    user_id: int,
    assessment_id: int,
    scan_id: int,
    ingestion_version: int,
    source_digest: str,
    status: str,
    entity_count: int = 0,
    assertion_count: int = 0,
    evidence_count: int = 0,
    error_code: str | None = None,
) -> dict:
    _prepare_scope(user_id, assessment_id)
    _require_evidence_sources(_get_connection(), user_id, assessment_id, scan_id, None, None)
    digest = str(source_digest or "").strip()
    if int(ingestion_version) < 1 or not digest:
        raise ValueError("Ingestion version and source digest are required.")
    now = _now()
    connection = _get_connection()

    def operation(active: sqlite3.Connection) -> dict:
        existing = active.execute(
            """SELECT * FROM assessment_map_ingestions WHERE assessment_id = ? AND user_id = ?
               AND scan_id = ? AND ingestion_version = ? AND source_digest = ?""",
            (assessment_id, user_id, scan_id, int(ingestion_version), digest),
        ).fetchone()
        desired = (
            str(status), int(entity_count), int(assertion_count), int(evidence_count), _optional_text(error_code)
        )
        if existing is not None and (
            existing["status"], existing["entity_count"], existing["assertion_count"],
            existing["evidence_count"], existing["error_code"],
        ) == desired:
            return _row_dict(existing)
        active.execute(
            """
            INSERT INTO assessment_map_ingestions (
                assessment_id, user_id, scan_id, ingestion_version, source_digest,
                status, entity_count, assertion_count, evidence_count, error_code,
                ingested_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(assessment_id, user_id, scan_id, ingestion_version, source_digest)
            DO UPDATE SET status = excluded.status, entity_count = excluded.entity_count,
                assertion_count = excluded.assertion_count, evidence_count = excluded.evidence_count,
                error_code = excluded.error_code, updated_at = excluded.updated_at
            """,
            (
                assessment_id, user_id, scan_id, int(ingestion_version), digest, str(status),
                int(entity_count), int(assertion_count), int(evidence_count), _optional_text(error_code),
                now, now,
            ),
        )
        return _row_dict(active.execute(
            """SELECT * FROM assessment_map_ingestions WHERE assessment_id = ? AND user_id = ?
               AND scan_id = ? AND ingestion_version = ? AND source_digest = ?""",
            (assessment_id, user_id, scan_id, int(ingestion_version), digest),
        ).fetchone())

    return run_locked_transaction(connection, operation)


def get_ingestion_ledger(
    *, user_id: int, assessment_id: int, scan_id: int, ingestion_version: int, source_digest: str
) -> dict | None:
    _prepare_scope(user_id, assessment_id)
    row = _get_connection().execute(
        """SELECT * FROM assessment_map_ingestions WHERE assessment_id = ? AND user_id = ?
           AND scan_id = ? AND ingestion_version = ? AND source_digest = ?""",
        (assessment_id, user_id, scan_id, int(ingestion_version), str(source_digest)),
    ).fetchone()
    return _row_dict(row) if row is not None else None


def list_entities(
    *, user_id: int, assessment_id: int, entity_type: str | None = None, limit: int = 50
) -> list[dict]:
    _prepare_scope(user_id, assessment_id)
    bounded = _bounded_limit(limit)
    if entity_type is None:
        rows = _get_connection().execute(
            """SELECT * FROM assessment_map_entities WHERE assessment_id = ? AND user_id = ?
               ORDER BY entity_type, id LIMIT ?""",
            (assessment_id, user_id, bounded),
        ).fetchall()
    else:
        normalized = str(entity_type).strip().lower()
        if normalized not in ENTITY_TYPES:
            raise ValueError("Unsupported assessment-map entity type.")
        rows = _get_connection().execute(
            """SELECT * FROM assessment_map_entities WHERE assessment_id = ? AND user_id = ?
               AND entity_type = ? ORDER BY id LIMIT ?""",
            (assessment_id, user_id, normalized, bounded),
        ).fetchall()
    return [_row_dict(row) for row in rows]


def list_assertions(
    *,
    user_id: int,
    assessment_id: int,
    entity_id: int | None = None,
    predicate: str | None = None,
    limit: int = 50,
) -> list[dict]:
    _prepare_scope(user_id, assessment_id)
    normalized_predicate = str(predicate).strip().lower() if predicate is not None else None
    if entity_id is not None:
        _require_entity(_get_connection(), user_id, assessment_id, entity_id)
    rows = _get_connection().execute(
        """
        SELECT * FROM assessment_map_assertions
        WHERE assessment_id = ?
          AND user_id = ?
          AND (? IS NULL OR subject_entity_id = ? OR object_entity_id = ?)
          AND (? IS NULL OR predicate = ?)
        ORDER BY id
        LIMIT ?
        """,
        (
            assessment_id,
            user_id,
            entity_id,
            entity_id,
            entity_id,
            normalized_predicate,
            normalized_predicate,
            _bounded_limit(limit),
        ),
    ).fetchall()
    return [_row_dict(row) for row in rows]


def _prepare_scope(user_id: int, assessment_id: int) -> None:
    initialize_assessment_map_schema()
    row = _get_connection().execute(
        "SELECT user_id FROM assessments WHERE id = ?", (int(assessment_id),)
    ).fetchone()
    if row is None or row["user_id"] is None or int(row["user_id"]) != int(user_id):
        raise AssessmentMapScopeError("Assessment map is unavailable outside the owned assessment scope.")


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_assessments_id_user_unique ON assessments(id, user_id)")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_assessment_scans_id_assessment_unique ON assessment_scans(id, assessment_id)")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_assessment_artifacts_id_assessment_unique ON assessment_artifacts(id, assessment_id)")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_id_user_unique ON findings(id, user_id)")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_map_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            entity_type TEXT NOT NULL CHECK(entity_type IN ('hostname','ip','service','application','endpoint','technology','finding')),
            identity_version TEXT NOT NULL,
            identity_hash TEXT NOT NULL,
            canonical_key TEXT NOT NULL,
            display_value TEXT,
            attributes_json TEXT NOT NULL DEFAULT '{}',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(assessment_id, user_id, entity_type, identity_hash),
            UNIQUE(id, assessment_id, user_id),
            FOREIGN KEY(assessment_id, user_id) REFERENCES assessments(id, user_id) ON DELETE RESTRICT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_map_assertions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            subject_entity_id INTEGER NOT NULL,
            predicate TEXT NOT NULL,
            object_entity_id INTEGER,
            normalized_value_json TEXT,
            polarity TEXT NOT NULL,
            assertion_hash TEXT NOT NULL,
            canonical_key TEXT NOT NULL,
            attributes_json TEXT NOT NULL DEFAULT '{}',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            CHECK(object_entity_id IS NOT NULL OR normalized_value_json IS NOT NULL),
            UNIQUE(assessment_id, user_id, assertion_hash),
            UNIQUE(id, assessment_id, user_id),
            FOREIGN KEY(assessment_id, user_id) REFERENCES assessments(id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(subject_entity_id, assessment_id, user_id)
                REFERENCES assessment_map_entities(id, assessment_id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(object_entity_id, assessment_id, user_id)
                REFERENCES assessment_map_entities(id, assessment_id, user_id) ON DELETE RESTRICT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_map_evidence_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            destination_type TEXT NOT NULL CHECK(destination_type IN ('entity','assertion')),
            destination_id INTEGER NOT NULL,
            entity_id INTEGER,
            assertion_id INTEGER,
            scan_id INTEGER,
            finding_id TEXT,
            artifact_id INTEGER,
            source_tool TEXT NOT NULL,
            evidence_kind TEXT NOT NULL,
            evidence_path TEXT,
            evidence_fingerprint TEXT NOT NULL,
            observed_at TEXT,
            confidence TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            CHECK((destination_type = 'entity' AND entity_id = destination_id AND assertion_id IS NULL)
               OR (destination_type = 'assertion' AND assertion_id = destination_id AND entity_id IS NULL)),
            CHECK(scan_id IS NOT NULL OR finding_id IS NOT NULL OR artifact_id IS NOT NULL),
            UNIQUE(assessment_id, user_id, destination_type, destination_id, evidence_fingerprint),
            FOREIGN KEY(assessment_id, user_id) REFERENCES assessments(id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(entity_id, assessment_id, user_id)
                REFERENCES assessment_map_entities(id, assessment_id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(assertion_id, assessment_id, user_id)
                REFERENCES assessment_map_assertions(id, assessment_id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(scan_id, assessment_id) REFERENCES assessment_scans(id, assessment_id) ON DELETE RESTRICT,
            FOREIGN KEY(finding_id, user_id) REFERENCES findings(id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(artifact_id, assessment_id) REFERENCES assessment_artifacts(id, assessment_id) ON DELETE RESTRICT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_validation_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            attempt_key TEXT NOT NULL,
            tool TEXT NOT NULL,
            proposal_id TEXT,
            request_fingerprint TEXT NOT NULL,
            target_entity_id INTEGER,
            service_entity_id INTEGER,
            finding_entity_id INTEGER,
            scan_id INTEGER,
            artifact_id INTEGER,
            approval_status TEXT NOT NULL,
            execution_status TEXT NOT NULL,
            validation_state TEXT,
            module TEXT,
            action_type TEXT,
            session_established INTEGER,
            started_at TEXT,
            completed_at TEXT,
            limitations_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(assessment_id, user_id, attempt_key),
            FOREIGN KEY(assessment_id, user_id) REFERENCES assessments(id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(target_entity_id, assessment_id, user_id)
                REFERENCES assessment_map_entities(id, assessment_id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(service_entity_id, assessment_id, user_id)
                REFERENCES assessment_map_entities(id, assessment_id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(finding_entity_id, assessment_id, user_id)
                REFERENCES assessment_map_entities(id, assessment_id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(scan_id, assessment_id) REFERENCES assessment_scans(id, assessment_id) ON DELETE RESTRICT,
            FOREIGN KEY(artifact_id, assessment_id) REFERENCES assessment_artifacts(id, assessment_id) ON DELETE RESTRICT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_map_ingestions (
            assessment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            ingestion_version INTEGER NOT NULL,
            source_digest TEXT NOT NULL,
            status TEXT NOT NULL,
            entity_count INTEGER NOT NULL DEFAULT 0,
            assertion_count INTEGER NOT NULL DEFAULT 0,
            evidence_count INTEGER NOT NULL DEFAULT 0,
            error_code TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            ingested_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(assessment_id, user_id, scan_id, ingestion_version, source_digest),
            FOREIGN KEY(assessment_id, user_id) REFERENCES assessments(id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(scan_id, assessment_id) REFERENCES assessment_scans(id, assessment_id) ON DELETE RESTRICT
        ) WITHOUT ROWID
        """
    )
    ingestion_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(assessment_map_ingestions)").fetchall()
    }
    if "metadata_json" not in ingestion_columns:
        connection.execute(
            "ALTER TABLE assessment_map_ingestions "
            "ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'"
        )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_map_evidence_id_scope_unique "
        "ON assessment_map_evidence_links(id, assessment_id, user_id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_map_ingestion_heads (
            assessment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            ingestion_version INTEGER NOT NULL,
            source_digest TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(assessment_id, user_id, scan_id, ingestion_version),
            FOREIGN KEY(assessment_id, user_id) REFERENCES assessments(id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY(scan_id, assessment_id) REFERENCES assessment_scans(id, assessment_id) ON DELETE RESTRICT,
            FOREIGN KEY(assessment_id, user_id, scan_id, ingestion_version, source_digest)
                REFERENCES assessment_map_ingestions(
                    assessment_id, user_id, scan_id, ingestion_version, source_digest
                ) ON DELETE RESTRICT
        ) WITHOUT ROWID
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_map_ingestion_evidence (
            assessment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            ingestion_version INTEGER NOT NULL,
            source_digest TEXT NOT NULL,
            evidence_link_id INTEGER NOT NULL,
            PRIMARY KEY(
                assessment_id, user_id, scan_id, ingestion_version, source_digest, evidence_link_id
            ),
            FOREIGN KEY(assessment_id, user_id, scan_id, ingestion_version, source_digest)
                REFERENCES assessment_map_ingestions(
                    assessment_id, user_id, scan_id, ingestion_version, source_digest
                ) ON DELETE RESTRICT,
            FOREIGN KEY(evidence_link_id, assessment_id, user_id)
                REFERENCES assessment_map_evidence_links(id, assessment_id, user_id) ON DELETE RESTRICT
        ) WITHOUT ROWID
        """
    )
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_map_entities_scope_type ON assessment_map_entities(user_id, assessment_id, entity_type, id)",
        "CREATE INDEX IF NOT EXISTS idx_map_assertions_subject ON assessment_map_assertions(user_id, assessment_id, subject_entity_id, predicate)",
        "CREATE INDEX IF NOT EXISTS idx_map_assertions_object ON assessment_map_assertions(user_id, assessment_id, object_entity_id, predicate)",
        "CREATE INDEX IF NOT EXISTS idx_map_evidence_destination ON assessment_map_evidence_links(user_id, assessment_id, destination_type, destination_id)",
        "CREATE INDEX IF NOT EXISTS idx_map_evidence_scan ON assessment_map_evidence_links(assessment_id, scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_map_evidence_finding ON assessment_map_evidence_links(user_id, finding_id)",
        "CREATE INDEX IF NOT EXISTS idx_map_validation_finding ON assessment_validation_attempts(user_id, assessment_id, finding_entity_id, completed_at)",
        "CREATE INDEX IF NOT EXISTS idx_map_validation_state ON assessment_validation_attempts(user_id, assessment_id, validation_state)",
        "CREATE INDEX IF NOT EXISTS idx_map_ingestions_scan ON assessment_map_ingestions(user_id, assessment_id, scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_map_ingestion_evidence_link ON assessment_map_ingestion_evidence(evidence_link_id)",
    ):
        connection.execute(statement)
    _create_scope_triggers(connection)


def _create_scope_triggers(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS trg_map_evidence_finding_scope_insert
        BEFORE INSERT ON assessment_map_evidence_links
        WHEN NEW.finding_id IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM findings AS finding
            JOIN assessment_scans AS scan ON scan.finding_id = finding.id
            JOIN assessments AS assessment ON assessment.id = scan.assessment_id
            WHERE finding.id = NEW.finding_id
              AND finding.user_id = NEW.user_id
              AND scan.assessment_id = NEW.assessment_id
              AND assessment.user_id = NEW.user_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'assessment-map finding scope violation');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS trg_map_evidence_finding_scope_update
        BEFORE UPDATE ON assessment_map_evidence_links
        WHEN NEW.finding_id IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM findings AS finding
            JOIN assessment_scans AS scan ON scan.finding_id = finding.id
            JOIN assessments AS assessment ON assessment.id = scan.assessment_id
            WHERE finding.id = NEW.finding_id
              AND finding.user_id = NEW.user_id
              AND scan.assessment_id = NEW.assessment_id
              AND assessment.user_id = NEW.user_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'assessment-map finding scope violation');
        END
        """
    )
    if _table_exists(connection, "metasploit_proposals"):
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_map_validation_proposal_scope_insert
            BEFORE INSERT ON assessment_validation_attempts
            WHEN NEW.proposal_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM metasploit_proposals AS proposal
                WHERE proposal.id = NEW.proposal_id
                  AND proposal.user_id = NEW.user_id
                  AND CAST(json_extract(proposal.assessment_context_json, '$.assessment_id') AS INTEGER)
                      = NEW.assessment_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'assessment-map proposal scope violation');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_map_validation_proposal_scope_update
            BEFORE UPDATE ON assessment_validation_attempts
            WHEN NEW.proposal_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM metasploit_proposals AS proposal
                WHERE proposal.id = NEW.proposal_id
                  AND proposal.user_id = NEW.user_id
                  AND CAST(json_extract(proposal.assessment_context_json, '$.assessment_id') AS INTEGER)
                      = NEW.assessment_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'assessment-map proposal scope violation');
            END
            """
        )


def _entity_by_hash(
    connection: sqlite3.Connection,
    user_id: int,
    assessment_id: int,
    entity_type: str,
    identity_hash: str,
):
    return connection.execute(
        """SELECT * FROM assessment_map_entities
           WHERE assessment_id = ? AND user_id = ? AND entity_type = ? AND identity_hash = ?""",
        (assessment_id, user_id, entity_type, identity_hash),
    ).fetchone()


def _verify_identity(row: sqlite3.Row, identity: CanonicalIdentity) -> None:
    if (
        row["entity_type"] != identity.entity_type
        or row["identity_version"] != identity.version
        or row["canonical_key"] != identity.canonical_key
    ):
        raise AssessmentMapIdentityCollisionError("Assessment-map entity hash collision detected.")


def _validate_canonical_identity(identity: CanonicalIdentity) -> None:
    if not isinstance(identity, CanonicalIdentity) or identity.entity_type not in ENTITY_TYPES:
        raise ValueError("Unsupported assessment-map entity type.")
    if identity.version != IDENTITY_SCHEMA_VERSION:
        raise ValueError("Unsupported assessment-map identity version.")
    expected = identity_from_payload(identity.entity_type, identity.payload)
    if expected.canonical_key != identity.canonical_key or expected.identity_hash != identity.identity_hash:
        raise AssessmentMapIdentityCollisionError("Assessment-map canonical identity is inconsistent.")


def _verify_evidence_identity(
    row: sqlite3.Row,
    *,
    scan_id: int | None,
    finding_id: str | None,
    artifact_id: int | None,
    source_tool: str,
    evidence_kind: str,
    evidence_path: str | None,
) -> None:
    actual = (
        row["scan_id"], row["finding_id"], row["artifact_id"],
        row["source_tool"], row["evidence_kind"], row["evidence_path"],
    )
    expected = (scan_id, finding_id, artifact_id, source_tool, evidence_kind, evidence_path)
    if actual != expected:
        raise AssessmentMapIdentityCollisionError("Assessment-map evidence fingerprint changed provenance.")


def _verify_validation_attempt_identity(
    row: sqlite3.Row,
    *,
    tool: str,
    proposal_id: str | None,
    request_fingerprint: str,
    target_entity_id: int | None,
    service_entity_id: int | None,
    finding_entity_id: int | None,
    module: str | None,
    action_type: str | None,
) -> None:
    actual = (
        row["tool"], row["proposal_id"], row["request_fingerprint"],
        row["target_entity_id"], row["service_entity_id"], row["finding_entity_id"],
        row["module"], row["action_type"],
    )
    expected = (
        tool, proposal_id, request_fingerprint,
        target_entity_id, service_entity_id, finding_entity_id, module, action_type,
    )
    if actual != expected:
        raise AssessmentMapIdentityCollisionError("Validation attempt key changed immutable identity.")


def _verify_validation_state_transition(
    row: sqlite3.Row,
    *,
    approval_status: str,
    execution_status: str,
    validation_state: str | None,
) -> None:
    current_execution = str(row["execution_status"] or "").strip().lower()
    requested_execution = str(execution_status or "").strip().lower()
    if current_execution not in _TERMINAL_VALIDATION_EXECUTION_STATES:
        return
    if (
        requested_execution != current_execution
        or str(approval_status) != str(row["approval_status"])
        or validation_state != row["validation_state"]
    ):
        raise AssessmentMapIdentityCollisionError("Terminal validation attempt cannot regress or change result.")


def _proposal_assessment_id(row: sqlite3.Row | None) -> int | None:
    if row is None:
        return None
    try:
        context = json.loads(row["assessment_context_json"] or "{}")
        value = context.get("assessment_id") if isinstance(context, dict) else None
        return int(value) if value is not None else None
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (str(table_name),),
    ).fetchone() is not None


def _require_entity(connection: sqlite3.Connection, user_id: int, assessment_id: int, entity_id: int):
    row = connection.execute(
        """SELECT * FROM assessment_map_entities WHERE id = ? AND assessment_id = ? AND user_id = ?""",
        (int(entity_id), int(assessment_id), int(user_id)),
    ).fetchone()
    if row is None:
        raise AssessmentMapScopeError("Assessment-map entity is outside the owned assessment scope.")
    return row


def _require_assertion(connection: sqlite3.Connection, user_id: int, assessment_id: int, assertion_id: int):
    row = connection.execute(
        """SELECT * FROM assessment_map_assertions WHERE id = ? AND assessment_id = ? AND user_id = ?""",
        (int(assertion_id), int(assessment_id), int(user_id)),
    ).fetchone()
    if row is None:
        raise AssessmentMapScopeError("Assessment-map assertion is outside the owned assessment scope.")
    return row


def _require_evidence_sources(
    connection: sqlite3.Connection,
    user_id: int,
    assessment_id: int,
    scan_id: int | None,
    finding_id: str | None,
    artifact_id: int | None,
    *,
    allow_empty: bool = False,
) -> None:
    if not allow_empty and scan_id is None and finding_id is None and artifact_id is None:
        raise ValueError("Stored evidence source is required.")
    if scan_id is not None:
        row = connection.execute(
            "SELECT finding_id FROM assessment_scans WHERE id = ? AND assessment_id = ?",
            (int(scan_id), int(assessment_id)),
        ).fetchone()
        if row is None:
            raise AssessmentMapScopeError("Assessment scan is outside the assessment scope.")
        if finding_id is not None and str(row["finding_id"] or "") != str(finding_id):
            raise AssessmentMapScopeError("Finding is not linked to the selected assessment scan.")
    if finding_id is not None:
        finding = connection.execute(
            "SELECT id FROM findings WHERE id = ? AND user_id = ?", (str(finding_id), int(user_id))
        ).fetchone()
        linked = connection.execute(
            "SELECT 1 FROM assessment_scans WHERE assessment_id = ? AND finding_id = ? LIMIT 1",
            (int(assessment_id), str(finding_id)),
        ).fetchone()
        if finding is None or linked is None:
            raise AssessmentMapScopeError("Finding is outside the owned assessment scope.")
    if artifact_id is not None:
        artifact = connection.execute(
            "SELECT id FROM assessment_artifacts WHERE id = ? AND assessment_id = ?",
            (int(artifact_id), int(assessment_id)),
        ).fetchone()
        if artifact is None:
            raise AssessmentMapScopeError("Assessment artifact is outside the assessment scope.")


def _bounded_limit(value: int) -> int:
    return max(1, min(int(value), MAX_LOOKUP_LIMIT))


def _optional_text(value: object | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True, default=str)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _row_dict(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in row.keys()}
