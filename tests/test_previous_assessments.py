import asyncio
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.bot.handlers.assessment import (
    ASSESSMENT_CHAT_STATE_KEY,
    assessment_callback_handler,
    build_assessment_dashboard_keyboard,
    previous_assessments_handler,
)
from app.bot.keyboards.main_menu import MAIN_MENU_BUTTONS
from app.services.assessment_conversation_store import get_latest_assessment_conversation
from app.services.assessment_store import (
    add_assessment_target,
    create_assessment,
    list_assessment_scans,
    record_assessment_scan,
)
from app.services.findings_store import _get_connection, close_findings_database, configure_findings_database


@pytest.fixture(autouse=True)
def sqlite_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _message_update(user_id: int):
    message = SimpleNamespace(text="Previous Assessments", reply_text=AsyncMock())
    return SimpleNamespace(message=message, effective_user=SimpleNamespace(id=user_id)), message


def _callback_update(user_id: int, data: str):
    message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(data=data, answer=AsyncMock(), edit_message_text=AsyncMock(), message=message)
    return SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=user_id)), query


def _set_assessment_status(assessment_id: int, status: str) -> None:
    with _get_connection() as connection:
        connection.execute("UPDATE assessments SET status = ? WHERE id = ?", (status, assessment_id))


def _set_scan_time(scan_id: int, timestamp: str) -> None:
    with _get_connection() as connection:
        connection.execute(
            "UPDATE assessment_scans SET started_at = ?, completed_at = ?, created_at = ?, updated_at = ? WHERE id = ?",
            (timestamp, timestamp, timestamp, timestamp, scan_id),
        )


def _set_assessment_time(assessment_id: int, timestamp: str) -> None:
    with _get_connection() as connection:
        connection.execute(
            "UPDATE assessments SET created_at = ?, updated_at = ? WHERE id = ?",
            (timestamp, timestamp, assessment_id),
        )


def test_main_menu_keeps_generic_ask_separate_from_previous_assessments() -> None:
    assert "Previous Assessments" in MAIN_MENU_BUTTONS
    assert "Ask Mongrel" in MAIN_MENU_BUTTONS
    assert MAIN_MENU_BUTTONS.index("Previous Assessments") != MAIN_MENU_BUTTONS.index("Ask Mongrel")


def test_previous_assessments_lists_completed_and_partial_newest_first_with_metadata() -> None:
    user_id = 4201
    completed = create_assessment("Completed perimeter", user_id=user_id)
    add_assessment_target(completed["id"], "old.example")
    old_scans = [
        record_assessment_scan(completed["id"], "nmap", "completed"),
        record_assessment_scan(completed["id"], "httpx", "completed"),
        record_assessment_scan(completed["id"], "nmap", "completed"),
    ]
    _set_assessment_status(completed["id"], "completed")

    partial = create_assessment("Interrupted web review", user_id=user_id)
    add_assessment_target(partial["id"], "new.example")
    new_scan = record_assessment_scan(partial["id"], "nuclei", "failed")
    for old_scan in old_scans:
        _set_scan_time(old_scan["id"], "2026-01-02T10:15:00+00:00")
    _set_scan_time(new_scan["id"], "2026-09-07T18:45:00+00:00")
    _set_assessment_time(completed["id"], "2026-01-02T10:15:00+00:00")
    _set_assessment_time(partial["id"], "2026-09-07T18:45:00+00:00")

    update, message = _message_update(user_id)
    asyncio.run(previous_assessments_handler(update, SimpleNamespace(user_data={})))

    text = message.reply_text.call_args.args[0]
    keyboard = message.reply_text.call_args.kwargs["reply_markup"]
    labels = [button.text for row in keyboard.inline_keyboard for button in row]
    assert text.index("Interrupted web review") < text.index("Completed perimeter")
    assert "Target: new.example" in text
    assert re.search(r"Date: 2026-09-07 \d{2}:45", text)
    assert "Status: Active" in text
    assert "Status: Completed" in text
    assert "Completed tools: 2/12" in text
    assert any(label.startswith("Continue Assessment") for label in labels)
    assert any(label.startswith("Open Assessment") for label in labels)


def test_listing_is_owned_and_paginated() -> None:
    for index in range(6):
        create_assessment(f"Owned {index}", user_id=4202)
    create_assessment("Another user's private assessment", user_id=9999)

    update, message = _message_update(4202)
    asyncio.run(previous_assessments_handler(update, SimpleNamespace(user_data={})))

    text = message.reply_text.call_args.args[0]
    keyboard = message.reply_text.call_args.kwargs["reply_markup"]
    callbacks = [button.callback_data for row in keyboard.inline_keyboard for button in row]
    assert "Another user's private assessment" not in text
    assert text.count("Completed tools:") == 5
    assert "assessment:list:1" in callbacks


def test_opening_persisted_partial_dashboard_does_not_mutate_or_rerun_scans() -> None:
    user_id = 4203
    assessment = create_assessment("Recover after reboot", user_id=user_id)
    add_assessment_target(assessment["id"], "persist.example")
    record_assessment_scan(assessment["id"], "nmap", "completed", raw_reference="kept-evidence.xml")
    before = list_assessment_scans(assessment["id"])
    update, query = _callback_update(user_id, f"assessment:dashboard:{assessment['id']}")

    asyncio.run(assessment_callback_handler(update, SimpleNamespace(user_data={})))

    rendered = query.edit_message_text.call_args.args[0]
    assert "Assessment Dashboard" in rendered
    assert "Recover after reboot" in rendered
    assert "Nmap: Completed" in rendered
    assert list_assessment_scans(assessment["id"]) == before


def test_dashboard_has_scoped_ask_entry_and_restart_resumes_or_creates_conversation() -> None:
    user_id = 4204
    assessment = create_assessment("Persistent conversation", user_id=user_id)
    labels = [button.text for row in build_assessment_dashboard_keyboard(assessment["id"]).inline_keyboard for button in row]
    assert "Ask Mongrel about this assessment" in labels

    first_context = SimpleNamespace(user_data={})
    first_update, _ = _callback_update(user_id, f"assessment:ask:{assessment['id']}")
    asyncio.run(assessment_callback_handler(first_update, first_context))
    first_conversation_id = first_context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"]
    assert get_latest_assessment_conversation(user_id, assessment["id"])["id"] == first_conversation_id

    reconstructed_context = SimpleNamespace(user_data={})
    second_update, _ = _callback_update(user_id, f"assessment:ask:{assessment['id']}")
    asyncio.run(assessment_callback_handler(second_update, reconstructed_context))
    assert reconstructed_context.user_data[ASSESSMENT_CHAT_STATE_KEY]["conversation_id"] == first_conversation_id


@pytest.mark.parametrize("action", ["dashboard", "history", "ask", "run:nmap"])
def test_forged_assessment_callbacks_cannot_open_another_users_assessment(action: str) -> None:
    assessment = create_assessment("Private evidence", user_id=4205)
    add_assessment_target(assessment["id"], "secret.example")
    record_assessment_scan(assessment["id"], "nmap", "completed", raw_reference="private.xml")
    before = list_assessment_scans(assessment["id"])
    update, query = _callback_update(6666, f"assessment:{action}:{assessment['id']}")
    context = SimpleNamespace(user_data={})

    asyncio.run(assessment_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == "Assessment not found."
    assert "secret.example" not in query.edit_message_text.call_args.args[0]
    assert ASSESSMENT_CHAT_STATE_KEY not in context.user_data
    assert list_assessment_scans(assessment["id"]) == before


def test_ownerless_legacy_assessment_callback_remains_inaccessible() -> None:
    assessment = create_assessment("Unattributed legacy assessment")
    add_assessment_target(assessment["id"], "legacy-private.example")
    record_assessment_scan(assessment["id"], "nmap", "completed", raw_reference="legacy-private.xml")
    update, query = _callback_update(4206, f"assessment:dashboard:{assessment['id']}")

    asyncio.run(assessment_callback_handler(update, SimpleNamespace(user_data={})))

    assert query.edit_message_text.call_args.args[0] == "Assessment not found."
    assert "legacy-private.example" not in query.edit_message_text.call_args.args[0]
