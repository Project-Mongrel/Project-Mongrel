from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.services.metasploit_approval import (
    MetasploitApprovalError,
    approve_metasploit_proposal,
    clear_metasploit_proposals,
    propose_metasploit_action,
    require_approved_metasploit_action,
)
from app.services.metasploit_policy import build_metasploit_action_request


@pytest.fixture(autouse=True)
def clear_store() -> None:
    clear_metasploit_proposals()


def _request() -> dict:
    return build_metasploit_action_request(
        module="auxiliary/scanner/http/http_version",
        action_type="auxiliary_validation",
        target="example.com",
        port=80,
    )


def test_metasploit_approval_required_before_execution() -> None:
    request = _request()
    proposal = propose_metasploit_action(100, request)

    with pytest.raises(MetasploitApprovalError):
        require_approved_metasploit_action(proposal.id, user_id=100, request=request)


def test_metasploit_wrong_user_and_ai_approval_denied() -> None:
    proposal = propose_metasploit_action(100, _request())

    with pytest.raises(MetasploitApprovalError):
        approve_metasploit_proposal(proposal.id, user_id=101)
    with pytest.raises(MetasploitApprovalError):
        approve_metasploit_proposal(proposal.id, user_id=100, actor="ai")


def test_metasploit_expired_approval_denied() -> None:
    request = _request()
    proposal = propose_metasploit_action(100, request)
    approved = approve_metasploit_proposal(proposal.id, user_id=100)
    from app.services import metasploit_approval

    metasploit_approval._proposals[approved.id] = replace(approved, expires_at=datetime.now(UTC) - timedelta(seconds=1))

    with pytest.raises(MetasploitApprovalError):
        require_approved_metasploit_action(proposal.id, user_id=100, request=request)


def test_metasploit_mutation_after_approval_denied() -> None:
    request = _request()
    proposal = propose_metasploit_action(100, request)
    approve_metasploit_proposal(proposal.id, user_id=100)
    mutated = {**request, "port": 8080}

    with pytest.raises(MetasploitApprovalError):
        require_approved_metasploit_action(proposal.id, user_id=100, request=mutated)
