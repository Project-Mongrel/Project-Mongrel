import json
import sqlite3
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.services.findings_store import _get_connection
from app.services.metasploit_policy import metasploit_request_fingerprint

APPROVAL_STATUSES = frozenset(
    {"proposed", "approved", "rejected", "expired", "executing", "executed", "failed", "timed_out", "cancelled"}
)
EXECUTION_STATES = frozenset({"not_started", "executing", "executed", "failed", "timed_out", "cancelled"})


class MetasploitApprovalError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MetasploitProposal:
    id: str
    user_id: int
    request: dict
    fingerprint: str
    status: str
    created_at: datetime
    expires_at: datetime
    approved_at: datetime | None = None
    approved_by_user_id: int | None = None
    rejected_at: datetime | None = None
    execution_state: str = "not_started"
    result_artifact_ref: str | None = None
    assessment_context: dict | None = None
    source_evidence_refs: list[str] | None = None
    reason: str | None = None


_proposals: dict[str, MetasploitProposal] = {}


def propose_metasploit_action(
    user_id: int,
    request: dict,
    ttl_seconds: int = 900,
    assessment_context: dict | None = None,
    source_evidence_refs: list[str] | None = None,
    reason: str | None = None,
) -> MetasploitProposal:
    if ttl_seconds < 30 or ttl_seconds > 86400:
        raise ValueError("Metasploit proposal TTL is outside the allowed range.")
    now = datetime.now(UTC)
    proposal = MetasploitProposal(
        id=str(uuid4()),
        user_id=int(user_id),
        request=dict(request),
        fingerprint=metasploit_request_fingerprint(request),
        status="proposed",
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        assessment_context=dict(assessment_context) if isinstance(assessment_context, dict) else None,
        source_evidence_refs=list(source_evidence_refs or []),
        reason=reason,
    )
    _save_proposal(proposal)
    return proposal


def approve_metasploit_proposal(proposal_id: str, *, user_id: int, actor: str = "human") -> MetasploitProposal:
    proposal = _get_existing_proposal(proposal_id)
    _refresh_expiry(proposal)
    if actor != "human":
        raise MetasploitApprovalError("Metasploit approval requires a human actor.")
    if proposal.user_id != int(user_id):
        raise MetasploitApprovalError("Metasploit proposal approval denied for user.")
    if proposal.status != "proposed":
        raise MetasploitApprovalError("Metasploit proposal is not awaiting approval.")
    approved = replace(
        proposal,
        status="approved",
        approved_at=datetime.now(UTC),
        approved_by_user_id=int(user_id),
    )
    _save_proposal(approved)
    return approved


def reject_metasploit_proposal(proposal_id: str, *, user_id: int) -> MetasploitProposal:
    proposal = _get_existing_proposal(proposal_id)
    if proposal.user_id != int(user_id):
        raise MetasploitApprovalError("Metasploit proposal rejection denied for user.")
    rejected = replace(proposal, status="rejected", rejected_at=datetime.now(UTC))
    _save_proposal(rejected)
    return rejected


def require_approved_metasploit_action(proposal_id: str, *, user_id: int, request: dict) -> MetasploitProposal:
    proposal = _get_existing_proposal(proposal_id)
    proposal = _refresh_expiry(proposal)
    if proposal.user_id != int(user_id):
        raise MetasploitApprovalError("Metasploit proposal execution denied for user.")
    if proposal.status != "approved":
        raise MetasploitApprovalError("Metasploit proposal has not been approved.")
    if proposal.fingerprint != metasploit_request_fingerprint(request):
        raise MetasploitApprovalError("Metasploit approved action details changed.")
    return proposal


def mark_metasploit_proposal_status(proposal_id: str, status: str) -> MetasploitProposal:
    normalized_status = str(status or "").strip().lower()
    if normalized_status not in APPROVAL_STATUSES:
        raise ValueError("Unsupported Metasploit proposal status.")
    proposal = _get_existing_proposal(proposal_id)
    execution_state = proposal.execution_state
    if normalized_status in EXECUTION_STATES:
        execution_state = normalized_status
    updated = replace(proposal, status=normalized_status, execution_state=execution_state)
    _save_proposal(updated)
    return updated


def record_metasploit_result_reference(proposal_id: str, artifact_ref: str | None) -> MetasploitProposal:
    proposal = _get_existing_proposal(proposal_id)
    updated = replace(proposal, result_artifact_ref=str(artifact_ref) if artifact_ref else None)
    _save_proposal(updated)
    return updated


def expire_stale_metasploit_proposals(now: datetime | None = None) -> int:
    current = now or datetime.now(UTC)
    _ensure_schema()
    rows = _get_connection().execute(
        "SELECT id FROM metasploit_proposals WHERE status IN ('proposed', 'approved') AND expires_at < ?",
        (_format_datetime(current),),
    ).fetchall()
    for row in rows:
        proposal = _load_proposal(row["id"])
        if proposal is not None:
            _save_proposal(replace(proposal, status="expired"))
    return len(rows)


def get_metasploit_proposal(proposal_id: str) -> MetasploitProposal | None:
    proposal = _proposals.get(str(proposal_id)) or _load_proposal(str(proposal_id))
    return _refresh_expiry(proposal) if proposal else None


def list_metasploit_proposals(*, user_id: int | None = None, status: str | None = None) -> list[MetasploitProposal]:
    _ensure_schema()
    if user_id is not None and status is not None:
        rows = _get_connection().execute(
            "SELECT id FROM metasploit_proposals WHERE user_id = ? AND status = ? ORDER BY created_at DESC",
            (int(user_id), str(status).strip().lower()),
        ).fetchall()
    elif user_id is not None:
        rows = _get_connection().execute(
            "SELECT id FROM metasploit_proposals WHERE user_id = ? ORDER BY created_at DESC",
            (int(user_id),),
        ).fetchall()
    elif status is not None:
        rows = _get_connection().execute(
            "SELECT id FROM metasploit_proposals WHERE status = ? ORDER BY created_at DESC",
            (str(status).strip().lower(),),
        ).fetchall()
    else:
        rows = _get_connection().execute("SELECT id FROM metasploit_proposals ORDER BY created_at DESC").fetchall()
    proposals: list[MetasploitProposal] = []
    for row in rows:
        proposal = get_metasploit_proposal(row["id"])
        if proposal is not None:
            proposals.append(proposal)
    return proposals


def clear_metasploit_proposals() -> None:
    _proposals.clear()
    _ensure_schema()
    with _get_connection() as connection:
        connection.execute("DELETE FROM metasploit_proposals")


def _get_existing_proposal(proposal_id: str) -> MetasploitProposal:
    proposal = _proposals.get(str(proposal_id)) or _load_proposal(str(proposal_id))
    if proposal is None:
        raise MetasploitApprovalError("Metasploit proposal was not found.")
    return proposal


def _refresh_expiry(proposal: MetasploitProposal) -> MetasploitProposal:
    if proposal.status in {"proposed", "approved"} and datetime.now(UTC) > proposal.expires_at:
        expired = replace(proposal, status="expired")
        _save_proposal(expired)
        return expired
    return proposal


def _save_proposal(proposal: MetasploitProposal) -> None:
    _ensure_schema()
    _proposals[proposal.id] = proposal
    with _get_connection() as connection:
        connection.execute(
            """
            INSERT INTO metasploit_proposals (
                id, user_id, request_json, fingerprint, status, created_at, expires_at,
                approved_at, approved_by_user_id, rejected_at, execution_state,
                result_artifact_ref, assessment_context_json, source_evidence_refs_json, reason, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                user_id = excluded.user_id,
                request_json = excluded.request_json,
                fingerprint = excluded.fingerprint,
                status = excluded.status,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                approved_at = excluded.approved_at,
                approved_by_user_id = excluded.approved_by_user_id,
                rejected_at = excluded.rejected_at,
                execution_state = excluded.execution_state,
                result_artifact_ref = excluded.result_artifact_ref,
                assessment_context_json = excluded.assessment_context_json,
                source_evidence_refs_json = excluded.source_evidence_refs_json,
                reason = excluded.reason,
                updated_at = excluded.updated_at
            """,
            (
                proposal.id,
                proposal.user_id,
                _to_json(proposal.request),
                proposal.fingerprint,
                proposal.status,
                _format_datetime(proposal.created_at),
                _format_datetime(proposal.expires_at),
                _format_optional_datetime(proposal.approved_at),
                proposal.approved_by_user_id,
                _format_optional_datetime(proposal.rejected_at),
                proposal.execution_state,
                proposal.result_artifact_ref,
                _to_json(proposal.assessment_context or {}),
                _to_json(proposal.source_evidence_refs or []),
                proposal.reason,
                _format_datetime(datetime.now(UTC)),
            ),
        )


def _load_proposal(proposal_id: str) -> MetasploitProposal | None:
    _ensure_schema()
    row = _get_connection().execute(
        "SELECT * FROM metasploit_proposals WHERE id = ?",
        (proposal_id,),
    ).fetchone()
    if row is None:
        return None
    proposal = _row_to_proposal(row)
    _proposals[proposal.id] = proposal
    return proposal


def _ensure_schema() -> None:
    connection = _get_connection()
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS metasploit_proposals (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            request_json TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            approved_at TEXT,
            approved_by_user_id INTEGER,
            rejected_at TEXT,
            execution_state TEXT,
            result_artifact_ref TEXT,
            assessment_context_json TEXT,
            source_evidence_refs_json TEXT,
            reason TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    _ensure_column(connection, "rejected_at", "TEXT")
    _ensure_column(connection, "execution_state", "TEXT")
    _ensure_column(connection, "result_artifact_ref", "TEXT")
    _ensure_column(connection, "assessment_context_json", "TEXT")
    _ensure_column(connection, "source_evidence_refs_json", "TEXT")
    _ensure_column(connection, "reason", "TEXT")
    _ensure_column(connection, "updated_at", "TEXT")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_metasploit_proposals_user_status ON metasploit_proposals(user_id, status)")
    connection.commit()


def _ensure_column(connection: sqlite3.Connection, column_name: str, column_type: str) -> None:
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(metasploit_proposals)").fetchall()}
    if column_name not in columns:
        connection.execute(f"ALTER TABLE metasploit_proposals ADD COLUMN {column_name} {column_type}")


def _row_to_proposal(row: sqlite3.Row) -> MetasploitProposal:
    assessment_context = _from_json(row["assessment_context_json"] or "{}")
    if not isinstance(assessment_context, dict) or not assessment_context:
        assessment_context = None
    source_refs = _from_json(row["source_evidence_refs_json"] or "[]")
    if not isinstance(source_refs, list):
        source_refs = []
    return MetasploitProposal(
        id=row["id"],
        user_id=int(row["user_id"]),
        request=_from_json(row["request_json"]),
        fingerprint=row["fingerprint"],
        status=row["status"],
        created_at=_parse_datetime(row["created_at"]),
        expires_at=_parse_datetime(row["expires_at"]),
        approved_at=_parse_optional_datetime(row["approved_at"]),
        approved_by_user_id=row["approved_by_user_id"],
        rejected_at=_parse_optional_datetime(row["rejected_at"]),
        execution_state=row["execution_state"] or "not_started",
        result_artifact_ref=row["result_artifact_ref"],
        assessment_context=assessment_context,
        source_evidence_refs=[str(value) for value in source_refs],
        reason=row["reason"],
    )


def _to_json(value: object) -> str:
    return json.dumps(value, default=str, sort_keys=True)


def _from_json(value: str) -> object:
    return json.loads(value)


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _format_optional_datetime(value: datetime | None) -> str | None:
    return _format_datetime(value) if value else None


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _parse_optional_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None
