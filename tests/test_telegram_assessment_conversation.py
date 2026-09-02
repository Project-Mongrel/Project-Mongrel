import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.bot.handlers.assessment import ASSESSMENT_CHAT_STATE_KEY, assessment_callback_handler
from app.bot.handlers.scan import PENDING_NMAP_REQUEST_KEY, scan_target_handler
from app.services.assessment_conversation_ai import FALLBACK_ANSWER
from app.services.assessment_conversation_store import get_latest_assessment_conversation, list_recent_messages
from app.services.assessment_store import create_assessment
from app.services.chat_state import clear_ai_waiting, set_ai_waiting
from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.scan_manager import create_scan_request, mark_scan_request_awaiting_target


@pytest.fixture(autouse=True)
def sqlite_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _callback_update(assessment_id: int, user_id: int, action: str = "ask"):
    message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:{action}:{assessment_id}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=message,
    )
    return SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=user_id)), query


def _enter(assessment_id: int, user_id: int, context=None):
    context = context or SimpleNamespace(user_data={})
    update, query = _callback_update(assessment_id, user_id)
    asyncio.run(assessment_callback_handler(update, context))
    return context, query


def _text(text: str, user_id: int):
    message = SimpleNamespace(text=text, reply_text=AsyncMock())
    return SimpleNamespace(message=message, effective_user=SimpleNamespace(id=user_id)), message


def test_enter_and_restart_resume_latest_db_conversation() -> None:
    assessment = create_assessment("Restart-safe chat", user_id=1001)
    first_context, _ = _enter(assessment["id"], 1001)
    conversation_id = first_context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]

    restarted_context, query = _enter(assessment["id"], 1001, SimpleNamespace(user_data={}))

    assert restarted_context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"] == conversation_id
    assert get_latest_assessment_conversation(1001, assessment["id"])["id"] == conversation_id
    assert "Restart-safe chat" in query.message.reply_text.call_args.args[0]
    assert "history" not in query.message.reply_text.call_args.args[0].lower()


def test_turn_persists_user_assistant_refs_digest_and_provenance_and_stays_active() -> None:
    assessment = create_assessment("Persistent chat", user_id=1002)
    context, _ = _enter(assessment["id"], 1002)
    conversation_id = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    update, message = _text("What changed?", 1002)
    result = {
        "answer": "Observed Facts\nSSH was observed.",
        "evidence_refs": {"scan_ids": [7], "finding_ids": ["f-1"]},
        "evidence_context_digest": "digest-123",
        "provenance": {"assessment_id": assessment["id"], "included_scan_ids": [7]},
        "fallback_reason": None,
    }

    with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", return_value=result):
        asyncio.run(scan_target_handler(update, context))

    messages = list_recent_messages(1002, conversation_id)
    assert [(item["role"], item["content"]) for item in messages] == [
        ("user", "What changed?"),
        ("assistant", result["answer"]),
    ]
    assert messages[1]["evidence_refs"] == result["evidence_refs"]
    assert messages[1]["evidence_context_digest"] == "digest-123"
    assert messages[1]["metadata"]["provenance"] == result["provenance"]
    assert messages[0]["metadata"] == {"source": "telegram"}
    assert ASSESSMENT_CHAT_STATE_KEY in context.user_data
    assert message.reply_text.call_args_list[-1].args[0] == result["answer"]


def test_exit_and_back_to_assessment_clear_mode() -> None:
    for action in ("exit_conversation", "dashboard"):
        assessment = create_assessment(f"Exit {action}", user_id=1003)
        context, _ = _enter(assessment["id"], 1003)
        update, query = _callback_update(assessment["id"], 1003, action)

        asyncio.run(assessment_callback_handler(update, context))

        assert ASSESSMENT_CHAT_STATE_KEY not in context.user_data
        rendered = (query.message.reply_text.call_args.args[0] if query.message.reply_text.called else query.edit_message_text.call_args.args[0])
        assert "Exited" in rendered or "Assessment Dashboard" in rendered


def test_cross_user_assessment_entry_fails_without_state_or_conversation() -> None:
    assessment = create_assessment("Private chat", user_id=1004)
    context, query = _enter(assessment["id"], 2004)

    assert query.edit_message_text.call_args.args[0] == "Assessment not found."
    assert ASSESSMENT_CHAT_STATE_KEY not in context.user_data
    assert get_latest_assessment_conversation(1004, assessment["id"]) is None


def test_pending_scan_input_is_not_stolen_by_assessment_or_generic_ask() -> None:
    user_id = 1005
    assessment = create_assessment("Routing chat", user_id=user_id)
    context, _ = _enter(assessment["id"], user_id)
    request = create_scan_request(user_id=user_id, scan_type="nmap")
    mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=request.id)
    context.user_data[PENDING_NMAP_REQUEST_KEY] = request.id
    set_ai_waiting(user_id)
    update, message = _text("not a valid target!", user_id)

    with (
        patch("app.bot.handlers.assessment.answer_assessment_conversation_question") as assessment_ai,
        patch("app.bot.handlers.scan.ask_ai") as generic_ai,
    ):
        asyncio.run(scan_target_handler(update, context))

    assessment_ai.assert_not_called()
    generic_ai.assert_not_called()
    assert message.reply_text.call_args.args[0].startswith("Invalid NMAP target:")
    clear_ai_waiting(user_id)


def test_metasploit_approval_input_is_not_stolen_by_conversation() -> None:
    user_id = 1006
    assessment = create_assessment("Approval routing", user_id=user_id)
    context, _ = _enter(assessment["id"], user_id)
    request = create_scan_request(user_id=user_id, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=request.id)
    context.user_data[PENDING_NMAP_REQUEST_KEY] = request.id
    update, _ = _text("auxiliary/scanner/http/http_version example.com", user_id)

    with (
        patch("app.bot.handlers.scan._handle_metasploit_request", new=AsyncMock()) as approval_input,
        patch("app.bot.handlers.assessment.answer_assessment_conversation_question") as assessment_ai,
    ):
        asyncio.run(scan_target_handler(update, context))

    approval_input.assert_awaited_once()
    assessment_ai.assert_not_called()


def test_assessment_conversation_wins_generic_ask_collision() -> None:
    user_id = 1007
    assessment = create_assessment("Collision", user_id=user_id)
    context, _ = _enter(assessment["id"], user_id)
    set_ai_waiting(user_id)
    update, _ = _text("Explain the evidence", user_id)
    result = {"answer": "Evidence answer", "evidence_refs": {}, "evidence_context_digest": "d", "provenance": {}}

    with (
        patch("app.bot.handlers.assessment.answer_assessment_conversation_question", return_value=result) as assessment_ai,
        patch("app.bot.handlers.scan.ask_ai") as generic_ai,
    ):
        asyncio.run(scan_target_handler(update, context))

    assessment_ai.assert_called_once()
    generic_ai.assert_not_called()
    clear_ai_waiting(user_id)


def test_ai_failure_preserves_user_and_persists_safe_fallback() -> None:
    assessment = create_assessment("AI failure", user_id=1008)
    context, _ = _enter(assessment["id"], 1008)
    conversation_id = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    update, message = _text("Question survives", 1008)

    with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", side_effect=RuntimeError("boom")):
        asyncio.run(scan_target_handler(update, context))

    messages = list_recent_messages(1008, conversation_id)
    assert [item["content"] for item in messages] == ["Question survives", FALLBACK_ANSWER]
    assert messages[1]["metadata"]["fallback_reason"] == "exception"
    assert message.reply_text.call_args_list[-1].args[0] == FALLBACK_ANSWER


def test_user_persistence_failure_does_not_call_ai_or_claim_saved() -> None:
    assessment = create_assessment("Write failure", user_id=1009)
    context, _ = _enter(assessment["id"], 1009)
    update, message = _text("Do not lose me", 1009)

    with (
        patch("app.bot.handlers.assessment.append_message", side_effect=RuntimeError("disk full")),
        patch("app.bot.handlers.assessment.answer_assessment_conversation_question") as assessment_ai,
    ):
        asyncio.run(scan_target_handler(update, context))

    assessment_ai.assert_not_called()
    assert "could not save your question" in message.reply_text.call_args.args[0]


def test_assistant_persistence_failure_surfaces_unsaved_response() -> None:
    assessment = create_assessment("Assistant write failure", user_id=1010)
    context, _ = _enter(assessment["id"], 1010)
    update, message = _text("Save the response", 1010)
    result = {"answer": "Unsaved generated text", "evidence_refs": {}, "evidence_context_digest": "d", "provenance": {}}

    with (
        patch("app.bot.handlers.assessment.append_message", side_effect=[{"id": "user"}, RuntimeError("disk full")]),
        patch("app.bot.handlers.assessment.answer_assessment_conversation_question", return_value=result),
    ):
        asyncio.run(scan_target_handler(update, context))

    assert "could not save it" in message.reply_text.call_args_list[-1].args[0]
    assert "Unsaved generated text" not in message.reply_text.call_args_list[-1].args[0]


def test_successful_turn_emits_safe_complete_timing_summary(caplog) -> None:
    assessment = create_assessment("Sensitive assessment label", user_id=1011)
    context, _ = _enter(assessment["id"], 1011)
    update, message = _text("private raw conversation question", 1011)
    result = {
        "answer": "private generated response",
        "evidence_refs": {"scan_ids": [7]},
        "evidence_context_digest": "digest-safe",
        "provenance": {"assessment_id": assessment["id"]},
        "fallback_reason": None,
        "instrumentation": {
            "context_ms": 12.5,
            "prompt_ms": 1.25,
            "ai_ms": 42000.0,
            "postprocess_ms": 0.75,
            "engine_ms": 42014.5,
            "prompt_chars": 12345,
            "context_chars": 9876,
            "history_message_count": 4,
            "evidence_scan_count": 3,
            "evidence_finding_count": 2,
            "evidence_artifact_count": 1,
            "output_token_budget": 900,
        },
    }

    caplog.set_level("INFO", logger="app.bot.handlers.assessment")
    with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", return_value=result):
        asyncio.run(scan_target_handler(update, context))

    timing_logs = [record.getMessage() for record in caplog.records if "assessment_ask_timing" in record.getMessage()]
    assert len(timing_logs) == 1
    logged = timing_logs[0]
    for stage in (
        "lookup_ms=", "context_ms=12.500", "prompt_ms=1.250", "ai_ms=42000.000",
        "postprocess_ms=0.750", "user_persistence_ms=", "assistant_persistence_ms=",
        "persistence_ms=", "total_ms=",
    ):
        assert stage in logged
    for metadata in (
        "prompt_chars=12345", "context_chars=9876", "history_message_count=4",
        "evidence_scan_count=3", "evidence_finding_count=2", "evidence_artifact_count=1",
        "output_token_budget=900",
    ):
        assert metadata in logged
    assert "private raw conversation question" not in logged
    assert "private generated response" not in logged
    assert "Sensitive assessment label" not in logged
    assert "digest-safe" not in logged
    assert message.reply_text.call_args_list[-1].args[0] == result["answer"]
