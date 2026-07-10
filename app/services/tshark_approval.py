from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.services.tshark_policy import tshark_capture_request_fingerprint

APPROVAL_STATUSES = frozenset({"proposed", "approved", "rejected", "expired", "executing", "executed", "failed"})


class TSharkApprovalError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TSharkCaptureProposal:
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


_proposals: dict[str, TSharkCaptureProposal] = {}


def propose_tshark_capture(user_id: int, request: dict, ttl_seconds: int = 300) -> TSharkCaptureProposal:
    if ttl_seconds < 30 or ttl_seconds > 3600:
        raise ValueError("TShark capture proposal TTL is outside the allowed range.")
    now = datetime.now(UTC)
    proposal = TSharkCaptureProposal(
        id=str(uuid4()),
        user_id=int(user_id),
        request=dict(request),
        fingerprint=tshark_capture_request_fingerprint(request),
        status="proposed",
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
    )
    _proposals[proposal.id] = proposal
    return proposal


def approve_tshark_capture(proposal_id: str, *, user_id: int, actor: str = "human") -> TSharkCaptureProposal:
    proposal = _get_existing(proposal_id)
    proposal = _refresh_expiry(proposal)
    if actor != "human":
        raise TSharkApprovalError("TShark live capture approval requires a human actor.")
    if proposal.user_id != int(user_id):
        raise TSharkApprovalError("TShark capture proposal approval denied for user.")
    if proposal.status != "proposed":
        raise TSharkApprovalError("TShark capture proposal is not awaiting approval.")
    approved = replace(proposal, status="approved", approved_at=datetime.now(UTC), approved_by_user_id=int(user_id))
    _proposals[approved.id] = approved
    return approved


def reject_tshark_capture(proposal_id: str, *, user_id: int) -> TSharkCaptureProposal:
    proposal = _get_existing(proposal_id)
    if proposal.user_id != int(user_id):
        raise TSharkApprovalError("TShark capture proposal rejection denied for user.")
    rejected = replace(proposal, status="rejected", rejected_at=datetime.now(UTC))
    _proposals[rejected.id] = rejected
    return rejected


def require_approved_tshark_capture(proposal_id: str, *, user_id: int, request: dict) -> TSharkCaptureProposal:
    proposal = _get_existing(proposal_id)
    proposal = _refresh_expiry(proposal)
    if proposal.user_id != int(user_id):
        raise TSharkApprovalError("TShark capture execution denied for user.")
    if proposal.status != "approved":
        raise TSharkApprovalError("TShark capture proposal has not been approved.")
    if proposal.fingerprint != tshark_capture_request_fingerprint(request):
        raise TSharkApprovalError("TShark approved capture details changed.")
    return proposal


def mark_tshark_capture_status(proposal_id: str, status: str) -> TSharkCaptureProposal:
    normalized = str(status or "").strip().lower()
    if normalized not in APPROVAL_STATUSES:
        raise ValueError("Unsupported TShark capture proposal status.")
    proposal = _get_existing(proposal_id)
    execution_state = proposal.execution_state
    if normalized in {"executing", "executed", "failed"}:
        execution_state = normalized
    updated = replace(proposal, status=normalized, execution_state=execution_state)
    _proposals[updated.id] = updated
    return updated


def get_tshark_capture_proposal(proposal_id: str) -> TSharkCaptureProposal | None:
    proposal = _proposals.get(str(proposal_id))
    return _refresh_expiry(proposal) if proposal else None


def clear_tshark_capture_proposals() -> None:
    _proposals.clear()


def _get_existing(proposal_id: str) -> TSharkCaptureProposal:
    proposal = _proposals.get(str(proposal_id))
    if proposal is None:
        raise TSharkApprovalError("TShark capture proposal was not found.")
    return proposal


def _refresh_expiry(proposal: TSharkCaptureProposal) -> TSharkCaptureProposal:
    if proposal.status in {"proposed", "approved"} and datetime.now(UTC) > proposal.expires_at:
        expired = replace(proposal, status="expired")
        _proposals[expired.id] = expired
        return expired
    return proposal
