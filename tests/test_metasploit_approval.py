from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.services.metasploit_approval import (
    MetasploitApprovalError,
    approve_metasploit_proposal,
    clear_metasploit_proposals,
    expire_stale_metasploit_proposals,
    get_metasploit_proposal,
    mark_metasploit_proposal_status,
    propose_metasploit_action,
    record_metasploit_result_reference,
    require_approved_metasploit_action,
)
from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.metasploit_policy import build_metasploit_action_request


@pytest.fixture(autouse=True)
def clear_store(tmp_path) -> None:
    configure_findings_database(tmp_path / "mongrel.db")
    clear_metasploit_proposals()
    yield
    clear_metasploit_proposals()
    close_findings_database()
    configure_findings_database(None)


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


def test_metasploit_proposal_persists_across_store_recreation() -> None:
    request = _request()
    proposal = propose_metasploit_action(
        100,
        request,
        assessment_context={"assessment_id": 7, "tool": "metasploit"},
        source_evidence_refs=["finding:abc"],
        reason="validate scanner evidence",
    )
    from app.services import metasploit_approval

    metasploit_approval._proposals.clear()
    loaded = get_metasploit_proposal(proposal.id)

    assert loaded is not None
    assert loaded.id == proposal.id
    assert loaded.status == "proposed"
    assert loaded.assessment_context == {"assessment_id": 7, "tool": "metasploit"}
    assert loaded.source_evidence_refs == ["finding:abc"]
    assert loaded.reason == "validate scanner evidence"


def test_metasploit_approval_state_persists_but_restart_does_not_auto_approve_new_proposals() -> None:
    request = _request()
    approved = approve_metasploit_proposal(propose_metasploit_action(100, request).id, user_id=100)
    pending = propose_metasploit_action(100, request)
    from app.services import metasploit_approval

    metasploit_approval._proposals.clear()

    assert get_metasploit_proposal(approved.id).status == "approved"
    assert get_metasploit_proposal(pending.id).status == "proposed"
    with pytest.raises(MetasploitApprovalError):
        require_approved_metasploit_action(pending.id, user_id=100, request=request)


def test_metasploit_execution_and_result_reference_persist() -> None:
    request = _request()
    proposal = approve_metasploit_proposal(propose_metasploit_action(100, request).id, user_id=100)
    mark_metasploit_proposal_status(proposal.id, "executed")
    record_metasploit_result_reference(proposal.id, "assessment_artifact:42")
    from app.services import metasploit_approval

    metasploit_approval._proposals.clear()
    loaded = get_metasploit_proposal(proposal.id)

    assert loaded.status == "executed"
    assert loaded.execution_state == "executed"
    assert loaded.result_artifact_ref == "assessment_artifact:42"


def test_metasploit_stale_cleanup_marks_expired() -> None:
    proposal = propose_metasploit_action(100, _request())

    expired_count = expire_stale_metasploit_proposals(now=proposal.expires_at + timedelta(seconds=1))

    assert expired_count == 1
    assert get_metasploit_proposal(proposal.id).status == "expired"
