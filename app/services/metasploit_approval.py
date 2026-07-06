from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.services.metasploit_policy import metasploit_request_fingerprint

APPROVAL_STATUSES = frozenset({"proposed", "approved", "rejected", "expired", "executing", "executed", "failed"})


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


_proposals: dict[str, MetasploitProposal] = {}


def propose_metasploit_action(user_id: int, request: dict, ttl_seconds: int = 900) -> MetasploitProposal:
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
    )
    _proposals[proposal.id] = proposal
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
    _proposals[proposal.id] = approved
    return approved


def reject_metasploit_proposal(proposal_id: str, *, user_id: int) -> MetasploitProposal:
    proposal = _get_existing_proposal(proposal_id)
    if proposal.user_id != int(user_id):
        raise MetasploitApprovalError("Metasploit proposal rejection denied for user.")
    rejected = replace(proposal, status="rejected")
    _proposals[proposal.id] = rejected
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
    updated = replace(proposal, status=normalized_status)
    _proposals[proposal.id] = updated
    return updated


def get_metasploit_proposal(proposal_id: str) -> MetasploitProposal | None:
    proposal = _proposals.get(str(proposal_id))
    return _refresh_expiry(proposal) if proposal else None


def clear_metasploit_proposals() -> None:
    _proposals.clear()


def _get_existing_proposal(proposal_id: str) -> MetasploitProposal:
    proposal = _proposals.get(str(proposal_id))
    if proposal is None:
        raise MetasploitApprovalError("Metasploit proposal was not found.")
    return proposal


def _refresh_expiry(proposal: MetasploitProposal) -> MetasploitProposal:
    if proposal.status in {"proposed", "approved"} and datetime.now(UTC) > proposal.expires_at:
        expired = replace(proposal, status="expired")
        _proposals[proposal.id] = expired
        return expired
    return proposal
