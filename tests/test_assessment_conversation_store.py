from datetime import datetime

import pytest

from app.services.assessment_conversation_store import (
    append_message,
    create_conversation,
    get_latest_assessment_conversation,
    get_or_create_assessment_conversation,
    get_user_conversation,
    list_recent_messages,
    list_user_conversations_for_assessment,
    update_summary_status,
)
from app.services.assessment_store import create_assessment
from app.services.findings_store import close_findings_database, configure_findings_database


@pytest.fixture(autouse=True)
def sqlite_assessment_conversation_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_owner_can_retrieve_conversation() -> None:
    assessment = create_assessment("Ask Assessment", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001, title="Investigation chat")

    assert conversation["assessment_id"] == assessment["id"]
    assert conversation["user_id"] == 1001
    assert conversation["title"] == "Investigation chat"
    assert conversation["status"] == "active"
    assert isinstance(conversation["created_at"], datetime)
    assert get_user_conversation(1001, conversation["id"]) == conversation


def test_different_user_cannot_retrieve_conversation_or_messages() -> None:
    assessment = create_assessment("Owned Assessment", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)
    append_message(conversation["id"], user_id=1001, role="user", content="What changed?")

    assert get_user_conversation(2002, conversation["id"]) is None
    assert list_recent_messages(2002, conversation["id"]) == []


def test_user_and_assistant_messages_persist_in_order() -> None:
    assessment = create_assessment("Ordered Assessment", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)

    first = append_message(conversation["id"], user_id=1001, role="user", content="Question")
    second = append_message(conversation["id"], user_id=1001, role="assistant", content="Answer")

    messages = list_recent_messages(1001, conversation["id"], limit=10)
    assert [message["id"] for message in messages] == [first["id"], second["id"]]
    assert [message["role"] for message in messages] == ["user", "assistant"]
    assert [message["content"] for message in messages] == ["Question", "Answer"]


def test_recent_message_limit_returns_latest_messages_in_chronological_order() -> None:
    assessment = create_assessment("Recent Assessment", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)
    for index in range(5):
        append_message(conversation["id"], user_id=1001, role="user", content=f"Message {index}")

    messages = list_recent_messages(1001, conversation["id"], limit=2)

    assert [message["content"] for message in messages] == ["Message 3", "Message 4"]


def test_summary_status_and_metadata_persist() -> None:
    assessment = create_assessment("Summary Assessment", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001, metadata={"seed": "initial"})

    updated = update_summary_status(
        1001,
        conversation["id"],
        summary="Older turns summarized.",
        status="archived",
        metadata={"phase": "2.2"},
    )

    assert updated["summary"] == "Older turns summarized."
    assert updated["status"] == "archived"
    assert updated["metadata"] == {"phase": "2.2"}


def test_metadata_and_evidence_refs_round_trip() -> None:
    assessment = create_assessment("Evidence Ref Assessment", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)

    message = append_message(
        conversation["id"],
        user_id=1001,
        role="assistant",
        content="Evidence-scoped answer.",
        evidence_refs={"scan_ids": [1], "artifact_ids": [2]},
        evidence_context_digest="sha256:abc123",
        metadata={"model": "test"},
    )

    assert message["evidence_refs"] == {"scan_ids": [1], "artifact_ids": [2]}
    assert message["evidence_context_digest"] == "sha256:abc123"
    assert message["metadata"] == {"model": "test"}


def test_invalid_role_rejected() -> None:
    assessment = create_assessment("Invalid Role Assessment", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)

    with pytest.raises(ValueError, match="role"):
        append_message(conversation["id"], user_id=1001, role="system", content="Do not store system prompts.")


def test_assessment_user_mismatch_rejected() -> None:
    assessment = create_assessment("Owner Assessment", user_id=1001)
    other_assessment = create_assessment("Other Assessment", user_id=2002)
    conversation = create_conversation(assessment["id"], user_id=1001)

    with pytest.raises(ValueError, match="Assessment conversation"):
        append_message(
            conversation["id"],
            user_id=1001,
            role="user",
            content="Wrong assessment.",
            assessment_id=other_assessment["id"],
        )
    with pytest.raises(ValueError, match="Assessment not found"):
        create_conversation(assessment["id"], user_id=2002)


def test_get_or_create_resumes_latest_active_assessment_conversation() -> None:
    assessment = create_assessment("Resume Assessment", user_id=1001)
    conversation = get_or_create_assessment_conversation(1001, assessment["id"], title="First")

    resumed = get_or_create_assessment_conversation(1001, assessment["id"], title="Second")

    assert resumed["id"] == conversation["id"]
    assert get_latest_assessment_conversation(1001, assessment["id"])["id"] == conversation["id"]
    assert list_user_conversations_for_assessment(1001, assessment["id"]) == [conversation]


def test_new_store_instance_retrieves_persisted_conversation(tmp_path) -> None:
    database_path = tmp_path / "mongrel.db"
    configure_findings_database(database_path)
    assessment = create_assessment("Restart Assessment", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)
    append_message(conversation["id"], user_id=1001, role="user", content="Persist me")

    close_findings_database()
    configure_findings_database(database_path)

    assert get_user_conversation(1001, conversation["id"])["id"] == conversation["id"]
    assert list_recent_messages(1001, conversation["id"])[0]["content"] == "Persist me"


def test_legacy_unowned_assessment_cannot_start_conversation() -> None:
    legacy_assessment = create_assessment("Legacy Assessment")

    with pytest.raises(ValueError, match="Assessment not found"):
        create_conversation(legacy_assessment["id"], user_id=1001)
