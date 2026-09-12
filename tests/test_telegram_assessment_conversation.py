import asyncio
import inspect
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.bot.handlers.assessment import (
    ASSESSMENT_ASK_TASK_KEY,
    ASSESSMENT_CHAT_STATE_KEY,
    MAX_ACTIVE_ASSESSMENT_ASK_WORKERS,
    active_assessment_ask_worker_count,
    assessment_callback_handler,
    new_assessment_handler,
    previous_assessments_handler,
)
from app.bot.handlers.ask import cancel_handler
from app.bot.handlers.home import build_home_text, home_handler
from app.bot.handlers.scan import PENDING_NMAP_REQUEST_KEY, scan_handler, scan_target_handler
from app.services.assessment_conversation_ai import FALLBACK_ANSWER
from app.services.assessment_conversation_store import append_message, get_latest_assessment_conversation, list_recent_messages
from app.services.assessment_conversation_store import create_conversation
from app.services.assessment_store import add_assessment_target, create_assessment, record_assessment_scan
from app.services.findings_store import add_finding
from app.services.chat_state import clear_ai_waiting, set_ai_waiting
from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.scan_manager import create_scan_request, mark_scan_request_awaiting_target
from app.services.scan_manager import get_user_scan_requests


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


def _run_text_handler(update, context) -> None:
    async def run() -> None:
        await scan_target_handler(update, context)
        task = context.user_data.get(ASSESSMENT_ASK_TASK_KEY)
        if isinstance(task, asyncio.Task):
            await task

    asyncio.run(run())


def _test1_assessment(user_id: int) -> dict:
    assessment = create_assessment("Test1", user_id=user_id)
    add_assessment_target(assessment["id"], "Hellosundaykids.com")
    evidence_by_tool = {
        "nmap": {"open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}, {"port": 443, "protocol": "tcp", "service": "https"}, {"port": 8080, "protocol": "tcp", "service": "http-proxy"}]},
        "nuclei": {"nuclei_findings": [{"template_id": "tech-detect", "severity": "info", "matched_at": "https://Hellosundaykids.com"}]},
        "httpx": {"httpx_results": [{"url": "https://Hellosundaykids.com", "status_code": 403}]},
        "testssl.sh": {"testssl_findings": [{"id": "early_data", "severity": "HIGH", "finding": "potentially VULNERABLE"}]},
        "metasploit": {"metasploit_evidence": {"execution_state": "completed", "session_established": False}},
        "tshark": {"tshark_evidence": {"packet_count": 76, "observed_protocols": [{"protocol": "tls", "packet_count": 24}], "handshake_success": "not established"}},
    }
    for tool, evidence in evidence_by_tool.items():
        finding = add_finding(
            user_id=user_id,
            finding={"source": tool, "target": "Hellosundaykids.com", "status": "completed", **evidence},
        )
        record_assessment_scan(assessment["id"], tool=tool, status="completed", finding_id=finding["id"])
    return assessment


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
        _run_text_handler(update, context)

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
        _run_text_handler(update, context)

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
        _run_text_handler(update, context)

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
        _run_text_handler(update, context)

    assessment_ai.assert_called_once()
    generic_ai.assert_not_called()
    clear_ai_waiting(user_id)


def test_live_test1_conversation_recovers_safe_answers_through_telegram_path() -> None:
    user_id = 1017
    assessment = _test1_assessment(user_id)
    context, _ = _enter(assessment["id"], user_id)
    conversation_id = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    # Persisted history reproduces the production condition before these turns.
    append_message(conversation_id, user_id=user_id, role="user", content="What does httpx do?")
    append_message(
        conversation_id,
        user_id=user_id,
        role="assistant",
        content="httpx records observed HTTP response metadata; that does not prove a vulnerability.",
    )
    generated = iter(
        [
            "The site is vulnerable, so run Katana next.",
            "The target appears insecure because web ports are exposed.",
            "The application is vulnerable because Katana has not run.",
            "Yes, that is a vulnerability.",
            "The target is secure because the completed scans found nothing critical.",
        ]
    )

    answers = []
    fallback_reasons = []
    with patch("app.services.assessment_conversation_ai.ask_ai", side_effect=lambda *_args, **_kwargs: next(generated)):
        for question in ("Ok what next?", "Anything worrying so far?", "Why?", "Is that a vulnerability?", "So are we secure?"):
            update, message = _text(question, user_id)
            _run_text_handler(update, context)
            answers.append(message.reply_text.call_args_list[-1].args[0])

    stored = list_recent_messages(user_id, conversation_id)
    fallback_reasons = [
        item.get("metadata", {}).get("fallback_reason")
        for item in stored
        if item.get("role") == "assistant" and item.get("content") in answers
    ]
    assert "Katana next" in answers[0]
    assert "httpx next" not in answers[0]
    assert "Gitleaks" not in answers[0] and "Prowler" not in answers[0]
    assert "worth investigating" in answers[1]
    assert "does not by itself establish" in answers[1]
    assert "Katana was suggested because" in answers[2]
    assert "confirmed vulnerability" in answers[3]
    assert "not enough to conclude" in answers[4]
    assert all("withheld" not in answer.lower() for answer in answers)
    assert all(reason in {None, "grounded_conversation_fallback"} for reason in fallback_reasons)
    assert [item["content"] for item in stored if item["role"] == "user"][-5:] == [
        "Ok what next?", "Anything worrying so far?", "Why?", "Is that a vulnerability?", "So are we secure?",
    ]


def test_round_one_state_authority_chain_through_public_telegram_path() -> None:
    user_id = 1018
    assessment = _test1_assessment(user_id)
    context, _ = _enter(assessment["id"], user_id)
    questions = (
        "What would you do next?",
        "Why that one?",
        "Why that onw?",
        "What exactly will this tell us?",
        "Anything else you think we should check?",
        "Which tools haven't we run would you prioritise?",
        "Why wouldn't you use Gitleaks here?",
        "What about Prowler?",
        "Explain all that like I'm completely new to cybersecurity",
    )
    answers = []
    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        for question in questions:
            update, message = _text(question, user_id)
            _run_text_handler(update, context)
            answers.append(message.reply_text.call_args_list[-1].args[0])

    assert "Katana next" in answers[0] and "httpx" in answers[0]
    assert "Katana was suggested" in answers[1]
    assert "Katana was suggested" in answers[2]
    assert "Katana was suggested" in answers[3]
    assert all(tool in answers[4] for tool in ("bbot", "katana", "playwright", "ffuf"))
    assert "Katana next" in answers[5]
    assert "Gitleaks has not been run" in answers[6]
    assert "no conclusion about the presence or absence of secrets" in answers[6]
    assert "Prowler has not been run" in answers[7]
    assert "no cloud security or compliance result can be inferred" in answers[7]
    assert "Katana is the sensible next choice" in answers[8]
    assert "httpx" in answers[8]  # Listed only as completed evidence collection, never as the next action.
    assert all("withheld" not in answer.lower() for answer in answers)
    assert all("httpx next" not in answer.lower() for answer in answers)
    assert all("no further evidence gaps" not in answer.lower() for answer in answers)
    ask_ai.assert_not_called()


def test_grounded_summary_and_highlight_variants_use_public_telegram_path() -> None:
    user_id = 1019
    assessment = _test1_assessment(user_id)
    context, _ = _enter(assessment["id"], user_id)
    questions = (
        "What have we actually established about this target?",
        "What have we actually established about this targer",
        "What do we actually know?",
        "What is the most interesting thing we have observed?",
        "What stands out?",
    )
    answers = []
    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        for question in questions:
            update, message = _text(question, user_id)
            _run_text_handler(update, context)
            answers.append(message.reply_text.call_args_list[-1].args[0])

    assert all("withheld" not in answer.lower() for answer in answers)
    assert "Nmap recorded exposed TCP services" in answers[0]
    assert "scanner severity INFO" in answers[0]
    assert "Relevant unperformed coverage remains" in answers[0]
    assert "Nmap recorded exposed TCP services" in answers[1]
    assert "Nmap recorded exposed TCP services" in answers[2]
    assert "prioritization of an observed surface" in answers[3]
    assert "prioritization of an observed surface" in answers[4]
    assert all("secure overall" not in answer.lower() for answer in answers)
    ask_ai.assert_not_called()


def test_cancel_during_delayed_assessment_ask_suppresses_stale_answer_and_resumes() -> None:
    user_id = 1020
    assessment = _test1_assessment(user_id)
    context, _ = _enter(assessment["id"], user_id)
    conversation_id = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    started = threading.Event()
    release = threading.Event()

    def delayed_answer(**_kwargs):
        started.set()
        release.wait(timeout=5)
        return {"answer": "STALE ANSWER", "evidence_refs": {}, "evidence_context_digest": "stale", "provenance": {}}

    async def scenario() -> tuple:
        question_update, question_message = _text("Explain the assessment", user_id)
        with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", side_effect=delayed_answer):
            await scan_target_handler(question_update, context)
            for _ in range(200):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert started.is_set()
            cancel_update, cancel_message = _text("Cancel", user_id)
            await cancel_handler(cancel_update, context)
            duplicate_messages = []
            for _ in range(3):
                duplicate_update, duplicate_message = _text("Cancel", user_id)
                await cancel_handler(duplicate_update, context)
                duplicate_messages.append(duplicate_message)
            reenter_update, _ = _callback_update(assessment["id"], user_id)
            await assessment_callback_handler(reenter_update, context)
            second_update, second_message = _text("Start another question", user_id)
            await scan_target_handler(second_update, context)
            assert active_assessment_ask_worker_count(user_id) == 1
            release.set()
            for _ in range(200):
                if active_assessment_ask_worker_count(user_id) == 0:
                    break
                await asyncio.sleep(0.01)
        return question_message, cancel_message, duplicate_messages, second_message

    question_message, cancel_message, duplicate_messages, second_message = asyncio.run(scenario())
    assert cancel_message.reply_text.call_count == 1
    assert cancel_message.reply_text.call_args.args[0] == "Ask Mongrel session closed."
    assert all(call.args[0] != "STALE ANSWER" for call in question_message.reply_text.call_args_list)
    assert sum(message.reply_text.call_count for message in duplicate_messages) == 0
    assert "previous Ask Mongrel request is still finishing" in second_message.reply_text.call_args.args[0]
    assert active_assessment_ask_worker_count(user_id) == 0
    assert active_assessment_ask_worker_count() <= MAX_ACTIVE_ASSESSMENT_ASK_WORKERS
    messages = list_recent_messages(user_id, conversation_id)
    assert [(item["role"], item["content"]) for item in messages[-1:]] == [("user", "Explain the assessment")]

    resumed_context, _ = _enter(assessment["id"], user_id, SimpleNamespace(user_data={}))
    assert resumed_context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"] == conversation_id


def test_home_cancels_delayed_ask_and_repeated_cancel_is_idempotent() -> None:
    user_id = 1021
    assessment = _test1_assessment(user_id)
    context, _ = _enter(assessment["id"], user_id)
    started = threading.Event()
    release = threading.Event()

    def delayed_answer(**_kwargs):
        started.set()
        release.wait(timeout=5)
        return {"answer": "LATE HOME ANSWER", "evidence_refs": {}, "evidence_context_digest": "late", "provenance": {}}

    async def scenario() -> tuple:
        question_update, question_message = _text("Tell me more", user_id)
        with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", side_effect=delayed_answer):
            await scan_target_handler(question_update, context)
            for _ in range(200):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert started.is_set()
            home_update, home_message = _text("Home", user_id)
            await home_handler(home_update, context)
            release.set()
            await asyncio.sleep(0.05)
        return question_message, home_message

    question_message, home_message = asyncio.run(scenario())
    assert home_message.reply_text.call_args.args[0] == build_home_text()
    assert all(call.args[0] != "LATE HOME ANSWER" for call in question_message.reply_text.call_args_list)


@pytest.mark.parametrize("action", ("dashboard", "exit_conversation", "list"))
def test_inline_navigation_during_delayed_ask_invalidates_stale_result(action) -> None:
    user_id = 1030 if action == "dashboard" else 1031
    assessment = create_assessment(f"Delayed {action}", user_id=user_id)
    context, _ = _enter(assessment["id"], user_id)
    conversation_id = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    started = threading.Event()
    release = threading.Event()

    def delayed_answer(**_kwargs):
        started.set()
        release.wait(timeout=5)
        return {"answer": f"STALE {action}", "evidence_refs": {}, "provenance": {}}

    async def scenario():
        question_update, question_message = _text("Delayed question", user_id)
        with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", side_effect=delayed_answer):
            await scan_target_handler(question_update, context)
            for _ in range(200):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            navigation_update, navigation_query = _callback_update(assessment["id"], user_id, action)
            await assessment_callback_handler(navigation_update, context)
            release.set()
            for _ in range(200):
                if active_assessment_ask_worker_count(user_id) == 0:
                    break
                await asyncio.sleep(0.01)
        return question_message, navigation_query

    question_message, navigation_query = asyncio.run(scenario())
    assert ASSESSMENT_CHAT_STATE_KEY not in context.user_data
    assert all(f"STALE {action}" != call.args[0] for call in question_message.reply_text.call_args_list)
    assert [item["role"] for item in list_recent_messages(user_id, conversation_id)] == ["user"]
    assert navigation_query.answer.called


@pytest.mark.parametrize(
    "label,handler",
    (
        ("Previous Assessments", previous_assessments_handler),
        ("Scan", scan_handler),
        ("New Assessment", new_assessment_handler),
    ),
)
def test_main_menu_navigation_during_delayed_ask_invalidates_stale_result(label, handler) -> None:
    user_id = {"Previous Assessments": 1051, "Scan": 1052, "New Assessment": 1053}[label]
    assessment = create_assessment(f"Navigate to {label}", user_id=user_id)
    context, _ = _enter(assessment["id"], user_id)
    conversation_id = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    started = threading.Event()
    release = threading.Event()

    def delayed_answer(**_kwargs):
        started.set()
        release.wait(timeout=5)
        return {"answer": "STALE MENU ANSWER", "evidence_refs": {}, "provenance": {}}

    async def scenario():
        question_update, question_message = _text("Delayed menu question", user_id)
        with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", side_effect=delayed_answer):
            await scan_target_handler(question_update, context)
            for _ in range(200):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            navigation_update, navigation_message = _text(label, user_id)
            await handler(navigation_update, context)
            release.set()
            for _ in range(200):
                if active_assessment_ask_worker_count(user_id) == 0:
                    break
                await asyncio.sleep(0.01)
        return question_message, navigation_message

    question_message, navigation_message = asyncio.run(scenario())
    assert ASSESSMENT_CHAT_STATE_KEY not in context.user_data
    assert navigation_message.reply_text.called
    assert all(call.args[0] != "STALE MENU ANSWER" for call in question_message.reply_text.call_args_list)
    assert [item["role"] for item in list_recent_messages(user_id, conversation_id)] == ["user"]


def test_switching_assessment_during_generation_cancels_old_turn_without_cross_delivery() -> None:
    user_id = 1032
    first = create_assessment("First", user_id=user_id)
    second = create_assessment("Second", user_id=user_id)
    context, _ = _enter(first["id"], user_id)
    first_conversation = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    started = threading.Event()
    release = threading.Event()

    def delayed_answer(**_kwargs):
        started.set()
        release.wait(timeout=5)
        return {"answer": "FIRST ASSESSMENT STALE", "evidence_refs": {}, "provenance": {}}

    async def scenario():
        question_update, question_message = _text("Question for first", user_id)
        with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", side_effect=delayed_answer):
            await scan_target_handler(question_update, context)
            for _ in range(200):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            switch_update, _ = _callback_update(second["id"], user_id, "ask")
            await assessment_callback_handler(switch_update, context)
            second_conversation = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
            release.set()
            for _ in range(200):
                if active_assessment_ask_worker_count(user_id) == 0:
                    break
                await asyncio.sleep(0.01)
        return question_message, second_conversation

    question_message, second_conversation = asyncio.run(scenario())
    state = context.user_data[ASSESSMENT_CHAT_STATE_KEY]
    assert state["assessment_id"] == second["id"]
    assert state["conversation_id"] == second_conversation
    assert all(call.args[0] != "FIRST ASSESSMENT STALE" for call in question_message.reply_text.call_args_list)
    assert [item["content"] for item in list_recent_messages(user_id, first_conversation)] == ["Question for first"]
    assert list_recent_messages(user_id, second_conversation) == []


@pytest.mark.parametrize("foreign_kind", ("other_user", "other_assessment"))
def test_forged_conversation_state_is_rejected_before_worker_or_persistence(foreign_kind) -> None:
    owner = 1033
    attacker = 1034
    selected = create_assessment("Selected", user_id=attacker)
    if foreign_kind == "other_user":
        foreign_assessment = create_assessment("Owner private", user_id=owner)
        foreign = create_conversation(foreign_assessment["id"], owner)
    else:
        foreign_assessment = create_assessment("Other attacker assessment", user_id=attacker)
        foreign = create_conversation(foreign_assessment["id"], attacker)
    context = SimpleNamespace(user_data={ASSESSMENT_CHAT_STATE_KEY: {
        "assessment_chat": True,
        "active_assessment_id": selected["id"],
        "assessment_id": selected["id"],
        "conversation_id": foreign["id"],
    }})
    update, message = _text("Show private evidence", attacker)

    with patch("app.bot.handlers.assessment.answer_assessment_conversation_question") as assessment_ai:
        _run_text_handler(update, context)

    assessment_ai.assert_not_called()
    assert message.reply_text.call_args.args[0] == "Assessment conversation not found."
    assert ASSESSMENT_CHAT_STATE_KEY not in context.user_data
    assert list_recent_messages(owner if foreign_kind == "other_user" else attacker, foreign["id"]) == []
    assert active_assessment_ask_worker_count(attacker) == 0


def test_malformed_worker_result_returns_safe_fallback_and_cleans_turn_state() -> None:
    user_id = 1035
    assessment = create_assessment("Malformed", user_id=user_id)
    context, _ = _enter(assessment["id"], user_id)
    conversation_id = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    update, message = _text("Malformed please", user_id)

    with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", return_value=None):
        _run_text_handler(update, context)

    assert message.reply_text.call_args_list[-1].args[0] == FALLBACK_ANSWER
    assert [(item["role"], item["content"]) for item in list_recent_messages(user_id, conversation_id)] == [
        ("user", "Malformed please"), ("assistant", FALLBACK_ANSWER),
    ]
    assert ASSESSMENT_ASK_TASK_KEY not in context.user_data
    assert "active_turn_id" not in context.user_data[ASSESSMENT_CHAT_STATE_KEY]
    assert active_assessment_ask_worker_count(user_id) == 0


def test_four_worker_global_cap_rejects_extra_users_without_persisting_questions() -> None:
    users = list(range(1040, 1046))
    entered = []
    for user_id in users:
        assessment = create_assessment(f"Worker {user_id}", user_id=user_id)
        context, _ = _enter(assessment["id"], user_id)
        entered.append((user_id, context, context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]))
    release = threading.Event()
    started = set()
    started_lock = threading.Lock()

    def delayed_answer(**kwargs):
        with started_lock:
            started.add(kwargs["user_id"])
        release.wait(timeout=5)
        return {"answer": f"ANSWER {kwargs['user_id']}", "evidence_refs": {}, "provenance": {}}

    async def scenario():
        messages = []
        tasks = []
        with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", side_effect=delayed_answer):
            for user_id, context, _ in entered[:4]:
                update, message = _text(f"Question {user_id}", user_id)
                await scan_target_handler(update, context)
                messages.append(message)
                tasks.append(context.user_data[ASSESSMENT_ASK_TASK_KEY])
            for _ in range(200):
                with started_lock:
                    if len(started) == 4:
                        break
                await asyncio.sleep(0.01)
            assert active_assessment_ask_worker_count() == MAX_ACTIVE_ASSESSMENT_ASK_WORKERS
            for user_id, context, _ in entered[4:]:
                update, message = _text(f"Rejected {user_id}", user_id)
                await scan_target_handler(update, context)
                messages.append(message)
            release.set()
            await asyncio.gather(*tasks)
        return messages

    messages = asyncio.run(scenario())
    assert active_assessment_ask_worker_count() == 0
    for index, (user_id, _, conversation_id) in enumerate(entered[:4]):
        assert messages[index].reply_text.call_args_list[-1].args[0] == f"ANSWER {user_id}"
        assert [item["content"] for item in list_recent_messages(user_id, conversation_id)] == [
            f"Question {user_id}", f"ANSWER {user_id}",
        ]
    for index, (user_id, _, conversation_id) in enumerate(entered[4:], start=4):
        assert "no new question was started" in messages[index].reply_text.call_args.args[0]
        assert list_recent_messages(user_id, conversation_id) == []


def test_forged_unknown_tool_callback_cannot_create_scan_request() -> None:
    user_id = 1050
    assessment = create_assessment("Forged tool", user_id=user_id)
    add_assessment_target(assessment["id"], "example.test")
    update, query = _callback_update(assessment["id"], user_id, "run:unknown")

    asyncio.run(assessment_callback_handler(update, SimpleNamespace(user_data={})))

    assert query.edit_message_text.call_args.args[0] == "Unsupported assessment action."
    assert get_user_scan_requests(user_id) == []


def test_ai_failure_preserves_user_and_persists_safe_fallback() -> None:
    assessment = create_assessment("AI failure", user_id=1008)
    context, _ = _enter(assessment["id"], 1008)
    conversation_id = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    update, message = _text("Question survives", 1008)

    with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", side_effect=RuntimeError("boom")):
        _run_text_handler(update, context)

    messages = list_recent_messages(1008, conversation_id)
    assert [item["content"] for item in messages] == ["Question survives", FALLBACK_ANSWER]
    assert messages[1]["metadata"]["fallback_reason"] == "exception"
    assert message.reply_text.call_args_list[-1].args[0] == FALLBACK_ANSWER
    assert active_assessment_ask_worker_count(1008) == 0
    assert ASSESSMENT_ASK_TASK_KEY not in context.user_data

    retry_update, retry_message = _text("Retry after failure", 1008)
    retry_result = {"answer": "Recovered", "evidence_refs": {}, "provenance": {}}
    with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", return_value=retry_result):
        _run_text_handler(retry_update, context)
    assert retry_message.reply_text.call_args_list[-1].args[0] == "Recovered"


def test_user_persistence_failure_does_not_call_ai_or_claim_saved() -> None:
    assessment = create_assessment("Write failure", user_id=1009)
    context, _ = _enter(assessment["id"], 1009)
    update, message = _text("Do not lose me", 1009)

    with (
        patch("app.bot.handlers.assessment.append_message", side_effect=RuntimeError("disk full")),
        patch("app.bot.handlers.assessment.answer_assessment_conversation_question") as assessment_ai,
    ):
        _run_text_handler(update, context)

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
        _run_text_handler(update, context)

    assert "could not save it" in message.reply_text.call_args_list[-1].args[0]
    assert "Unsaved generated text" not in message.reply_text.call_args_list[-1].args[0]
    assert ASSESSMENT_ASK_TASK_KEY not in context.user_data
    assert "active_turn_id" not in context.user_data[ASSESSMENT_CHAT_STATE_KEY]
    assert active_assessment_ask_worker_count(1010) == 0


def test_telegram_send_failure_cleans_transient_turn_without_losing_persisted_answer() -> None:
    user_id = 1054
    assessment = create_assessment("Send failure", user_id=user_id)
    context, _ = _enter(assessment["id"], user_id)
    conversation_id = context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    update, message = _text("Persist before send", user_id)
    message.reply_text = AsyncMock(side_effect=[None, RuntimeError("telegram unavailable")])
    result = {"answer": "Persisted safe answer", "evidence_refs": {}, "provenance": {}}

    with patch("app.bot.handlers.assessment.answer_assessment_conversation_question", return_value=result):
        _run_text_handler(update, context)

    assert [item["content"] for item in list_recent_messages(user_id, conversation_id)] == [
        "Persist before send", "Persisted safe answer",
    ]
    assert ASSESSMENT_ASK_TASK_KEY not in context.user_data
    assert "active_turn_id" not in context.user_data[ASSESSMENT_CHAT_STATE_KEY]
    assert active_assessment_ask_worker_count(user_id) == 0


def test_assessment_ask_worker_avoids_default_executor_and_to_thread() -> None:
    from app.bot.handlers.assessment import _run_assessment_answer_off_loop

    source = inspect.getsource(_run_assessment_answer_off_loop)
    assert "to_thread" not in source
    assert "run_in_executor" not in source
    assert "daemon=True" in source


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
        _run_text_handler(update, context)

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
