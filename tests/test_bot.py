import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from telegram.error import TimedOut

from app.bot.auth import is_admin
from app.bot.handlers.ask import ask_handler, build_ask_text, cancel_handler
from app.bot.handlers.findings import (
    MAX_FINDINGS_MESSAGE_LENGTH,
    build_finding_analysis_context,
    build_finding_detail_keyboard,
    build_finding_detail_text,
    build_finding_ai_prompt,
    build_finding_followup_ai_prompt,
    build_findings_keyboard,
    build_findings_text,
    findings_callback_handler,
    findings_handler,
)
from app.bot.handlers.home import build_home_text, home_handler
from app.bot.handlers.reports import (
    build_investigation_timeline_text,
    build_investigations_text,
    build_reports_keyboard,
    build_reports_text,
    reports_callback_handler,
    reports_handler,
    split_report_text,
)
from app.bot.handlers.scan import (
    NUCLEI_STATUS_UPDATE_INTERVAL_SECONDS,
    PENDING_NMAP_REQUEST_KEY,
    _finalize_nuclei_status,
    _update_nuclei_status_card,
    append_change_summary,
    build_bbot_ai_assessment_keyboard,
    build_bbot_result_text,
    build_bbot_target_prompt,
    build_clean_nuclei_verdict_text,
    build_nuclei_status_card,
    build_nuclei_target_prompt,
    build_nmap_scan_result_text,
    build_nmap_target_prompt,
    build_scan_created_text,
    build_scan_text,
    scan_callback_handler,
    scan_handler,
    scan_target_handler,
    store_clean_nuclei_scan,
    store_bbot_scan_result,
    store_successful_nmap_finding,
)
from app.bot.handlers.settings import build_settings_text
from app.bot.handlers.start import build_start_text
from app.bot.handlers.upload import build_upload_text
from app.bot.handlers.upload import (
    UPLOAD_STATE_AWAITING_NMAP_XML,
    UPLOAD_EXPLAIN_CALLBACK,
    build_upload_ai_prompt,
    build_nmap_xml_import_success_text,
    build_nuclei_import_success_text,
    build_upload_success_keyboard,
    clear_latest_upload_scan_summary,
    clear_upload_state,
    get_latest_upload_scan_summary,
    get_upload_state,
    set_upload_state,
    store_nuclei_finding,
    store_latest_upload_scan_summary,
    upload_callback_handler,
    upload_document_handler,
)
from app.bot.keyboards import MAIN_MENU_BUTTONS, build_main_menu_keyboard, build_scan_type_keyboard
from app.core.config import Settings
from app.services.active_scan_state import clear_active_scan, get_active_scan, set_active_scan
from app.services.bbot_ai_assessment import FALLBACK_LINES
from app.services.findings_store import (
    add_finding,
    add_report_metadata,
    clear_user_findings,
    clear_user_reports,
    get_user_findings,
    get_user_reports,
)
from app.services.investigation_store import (
    add_investigation_event,
    clear_user_investigations,
    create_investigation,
    get_investigation_events,
    get_user_investigations,
)
from app.services.observation_store import add_observation, clear_user_observations, get_investigation_observations, get_user_observations
from app.services.chat_state import (
    clear_ai_waiting,
    clear_finding_analysis_context,
    get_finding_analysis_context,
    is_ai_waiting,
    set_ai_waiting,
    set_finding_analysis_context,
)
from app.services.scan_manager import clear_user_scan_requests, create_scan_request, mark_scan_request_awaiting_target
from app.services.verdict_engine import generate_mongrel_verdict


def test_main_menu_keyboard_contains_expected_buttons() -> None:
    keyboard = build_main_menu_keyboard()
    rendered_buttons = [
        button.text
        for row in keyboard.keyboard
        for button in row
    ]

    assert rendered_buttons == list(MAIN_MENU_BUTTONS)


def test_admin_helper_matches_configured_admin() -> None:
    settings = Settings(admin_user_id=12345)

    assert is_admin(12345, settings) is True
    assert is_admin(54321, settings) is False
    assert is_admin(None, settings) is False
    assert is_admin(12345, Settings(admin_user_id=None)) is False


def test_handler_text_builders_do_not_expose_secrets() -> None:
    settings = Settings(admin_user_id=12345, telegram_bot_token="secret-token")

    assert "Project Mongrel control panel" in build_home_text()
    assert "Welcome to Project Mongrel" in build_start_text("Ada")

    settings_text = build_settings_text(12345, settings)
    assert "Telegram ID: 12345" in settings_text
    assert "Admin: yes" in settings_text
    assert "secret-token" not in settings_text


def test_navigation_text_builders_are_importable() -> None:
    assert build_findings_text() == "No findings available yet."
    assert "Choose a scan workflow" in build_scan_text()
    assert "pending" in build_scan_created_text("nmap")
    assert "authorized target" in build_nmap_target_prompt()
    assert "Nmap XML" in build_upload_text()
    assert "- Nuclei JSON (supported)" in build_upload_text()
    assert "- Nuclei JSONL (supported)" in build_upload_text()
    assert "Send an Nmap XML or Nuclei results file to begin analysis." in build_upload_text()
    assert build_ask_text() == "Ask Mongrel anything. Cybersecurity is my specialty."
    assert "Reports" in build_reports_text([])


def test_reports_menu_renders() -> None:
    text = build_reports_text([])
    keyboard = build_reports_keyboard([])
    rendered_buttons = [button.text for row in keyboard.inline_keyboard for button in row]

    assert "Persisted scan runs available: 0" in text
    assert "Generate Latest Report" in rendered_buttons
    assert "Generate Report with AI Assessment" in rendered_buttons
    assert "Reports by Target" in rendered_buttons
    assert "Previous Reports / History" in rendered_buttons
    assert "Investigations" in rendered_buttons
    assert "Latest Investigation" in rendered_buttons
    assert "Back/Home" in rendered_buttons


def test_reports_handler_sends_menu() -> None:
    clear_user_findings(9101)
    clear_user_reports(9101)
    add_finding(user_id=9101, finding={"source": "nmap", "target": "127.0.0.1", "risk_level": "low"})
    message = SimpleNamespace(reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=9101))

    asyncio.run(reports_handler(update, SimpleNamespace()))

    assert "Persisted scan runs available: 1" in message.reply_text.call_args.args[0]
    assert message.reply_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data == "report:latest"


def test_latest_report_generation_from_telegram() -> None:
    clear_user_findings(9102)
    clear_user_reports(9102)
    clear_user_investigations(9102)
    add_finding(
        user_id=9102,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(data="report:latest", answer=AsyncMock(), edit_message_text=AsyncMock(), message=query_message)
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9102))

    asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    query.edit_message_text.assert_called_once_with("Generating report...")
    report_text = query_message.reply_text.call_args.args[0]
    assert "# Project Mongrel" in report_text
    assert "Security Assessment Report" in report_text
    assert "Report ID:\nPM-" in report_text
    assert "## Assessment Statistics" in report_text
    assert "22/tcp ssh" in report_text
    reports = get_user_reports(9102)
    assert reports[0]["report_type"] == "deterministic"
    assert reports[0]["report_id"].startswith("PM-")
    assert reports[0]["target"] == "127.0.0.1"
    assert reports[0]["overall_risk"] == "medium"
    investigation = get_user_investigations(9102)[0]
    events = get_investigation_events(investigation["id"], 9102)
    assert events[-1]["event_type"] == "report_generated"
    assert get_user_investigations(9102)[0]["status"] == "completed"
    assert get_user_investigations(9102)[0]["completed_at"] is not None
    assert get_user_investigations(9102)[0]["metadata"]["duration_seconds"] >= 0


def test_report_empty_history_handling() -> None:
    clear_user_findings(9103)
    clear_user_reports(9103)
    query = SimpleNamespace(
        data="report:latest",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9103))

    asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    assert query.edit_message_text.call_args.args[0] == "No scan history available yet. Run or upload scans before generating a report."


def test_ai_report_generation_from_telegram() -> None:
    clear_user_findings(9106)
    clear_user_reports(9106)
    clear_user_investigations(9106)
    add_finding(
        user_id=9106,
        finding={
            "source": "nuclei",
            "target": "example.com",
            "risk_level": "high",
            "finding_count": 1,
            "nuclei_findings": [{"template_id": "git-config-exposure", "severity": "high"}],
        },
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(data="report:latest_ai", answer=AsyncMock(), edit_message_text=AsyncMock(), message=query_message)
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9106))

    with patch("app.services.report_generator.ask_ai", return_value="AI assessment: high risk."):
        asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    edited_messages = [call.args[0] for call in query.edit_message_text.call_args_list]
    assert any(message.endswith("Generating AI report /") for message in edited_messages)
    assert any(
        message.endswith(("Collecting scan history -", "Building deterministic report \\", "Asking Mongrel AI |"))
        for message in edited_messages
    )
    assert edited_messages[-1] == "AI report ready."
    report_text = query_message.reply_text.call_args.args[0]
    assert "## Executive Assessment" in report_text
    assert "AI assessment: high risk." in report_text
    assert "git-config-exposure" in report_text
    reports = get_user_reports(9106)
    assert reports[0]["report_type"] == "ai_assessment"
    assert reports[0]["title"] == "Executive Assessment Report"
    assert reports[0]["overall_risk"] == "high"
    investigation = get_user_investigations(9106)[0]
    events = get_investigation_events(investigation["id"], 9106)
    assert events[-1]["event_type"] == "ai_report_generated"
    assert get_user_investigations(9106)[0]["status"] == "completed"


def test_ai_report_failure_updates_status_and_sends_fallback_report() -> None:
    clear_user_findings(9110)
    clear_user_reports(9110)
    add_finding(
        user_id=9110,
        finding={
            "source": "nuclei",
            "target": "example.com",
            "risk_level": "high",
            "finding_count": 1,
            "nuclei_findings": [{"template_id": "git-config-exposure", "severity": "high"}],
        },
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(data="report:latest_ai", answer=AsyncMock(), edit_message_text=AsyncMock(), message=query_message)
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9110))

    with patch("app.services.report_generator.ask_ai", side_effect=TimeoutError("timeout")):
        asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    edited_messages = [call.args[0] for call in query.edit_message_text.call_args_list]
    assert any(message.endswith("Generating AI report /") for message in edited_messages)
    assert edited_messages[-1] == "AI unavailable. Sending deterministic report with fallback note."
    report_text = query_message.reply_text.call_args.args[0]
    assert "## Executive Assessment" in report_text
    assert "AI assessment unavailable: timeout" in report_text
    assert "git-config-exposure" in report_text


def test_ai_report_progress_edit_failures_do_not_break_generation() -> None:
    clear_user_findings(9111)
    clear_user_reports(9111)
    add_finding(
        user_id=9111,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data="report:latest_ai",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(side_effect=TimedOut("telegram timeout")),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9111))

    with patch("app.services.report_generator.ask_ai", return_value="SSH should be hardened."):
        asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    assert query.edit_message_text.await_count >= 2
    report_text = query_message.reply_text.call_args.args[0]
    assert "## Executive Assessment" in report_text
    assert "SSH should be hardened." in report_text


def test_target_specific_report_generation_from_telegram() -> None:
    clear_user_findings(9104)
    clear_user_reports(9104)
    add_finding(
        user_id=9104,
        finding={
            "source": "nmap",
            "target": "alpha.example",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )
    add_finding(
        user_id=9104,
        finding={
            "source": "nuclei",
            "target": "beta.example",
            "risk_level": "high",
            "finding_count": 1,
            "nuclei_findings": [{"template_id": "git-config-exposure", "severity": "high"}],
        },
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(data="report:target:1", answer=AsyncMock(), edit_message_text=AsyncMock(), message=query_message)
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9104))

    asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    report_text = query_message.reply_text.call_args.args[0]
    assert "Target / Scope:\nbeta.example" in report_text
    assert "git-config-exposure" in report_text
    assert "alpha.example" not in report_text
    reports = get_user_reports(9104)
    assert reports[0]["target"] == "beta.example"
    assert reports[0]["scan_count"] == 1


def test_report_targets_list_from_telegram() -> None:
    clear_user_findings(9105)
    clear_user_reports(9105)
    add_finding(user_id=9105, finding={"source": "nmap", "target": "alpha.example", "risk_level": "low"})
    add_finding(user_id=9105, finding={"source": "nuclei", "target": "beta.example", "risk_level": "high"})
    query = SimpleNamespace(data="report:targets", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9105))

    asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    assert query.edit_message_text.call_args.args[0] == "Choose a target for the report."
    keyboard = query.edit_message_text.call_args.kwargs["reply_markup"]
    assert keyboard.inline_keyboard[0][0].text == "alpha.example"
    assert keyboard.inline_keyboard[0][0].callback_data == "report:target:0"
    assert keyboard.inline_keyboard[1][0].text == "beta.example"


def test_report_history_list_loads_from_sqlite() -> None:
    clear_user_findings(9107)
    clear_user_reports(9107)
    report = add_report_metadata(
        user_id=9107,
        metadata={
            "target": "hellosundaykids.com",
            "report_type": "ai_assessment",
            "title": "Executive Assessment Report",
            "report_id": "PM-20260625-0001",
            "summary": "Generated report.",
            "overall_risk": "medium",
            "source_count": 2,
            "scan_count": 3,
        },
    )
    query = SimpleNamespace(data="report:history", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9107))

    asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    history_text = query.edit_message_text.call_args.args[0]
    keyboard = query.edit_message_text.call_args.kwargs["reply_markup"]
    assert "Previous Reports / History" in history_text
    assert "UTC" in history_text
    assert "+00:00" not in history_text
    assert "hellosundaykids.com" in history_text
    assert "Report ID: PM-20260625-0001" in history_text
    assert "Target: hellosundaykids.com" in history_text
    assert "Type: Executive Assessment Report" in history_text
    assert "Risk: MEDIUM" in history_text
    assert keyboard.inline_keyboard[0][0].callback_data == f"report:history:{report['id']}"


def test_empty_report_history_handling() -> None:
    clear_user_findings(9108)
    clear_user_reports(9108)
    query = SimpleNamespace(data="report:history", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9108))

    asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    assert query.edit_message_text.call_args.args[0] == "No previous reports generated yet."


def test_selecting_previous_report_details() -> None:
    clear_user_findings(9109)
    clear_user_reports(9109)
    report = add_report_metadata(
        user_id=9109,
        metadata={
            "target": "example.com",
            "report_type": "deterministic",
            "title": "Deterministic Security Report",
            "report_id": "PM-20260625-0002",
            "investigation_name": "External review",
            "summary": "example.com report generated from 1 scan run.",
            "overall_risk": "low",
            "source_count": 1,
            "scan_count": 1,
        },
    )
    query = SimpleNamespace(data=f"report:history:{report['id']}", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9109))

    asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    detail_text = query.edit_message_text.call_args.args[0]
    assert "Report Details" in detail_text
    assert "Report ID: PM-20260625-0002" in detail_text
    assert "Generated:" in detail_text
    assert "UTC" in detail_text
    assert "Investigation: External review" in detail_text
    assert "Target: example.com" in detail_text
    assert "Type: Deterministic Report" in detail_text
    assert "Risk: LOW" in detail_text
    assert "example.com report generated from 1 scan run." in detail_text


def test_investigation_list_rendering() -> None:
    investigation = create_investigation(user_id=9112, target="127.0.0.1")
    investigation["overall_risk"] = "high"

    text = build_investigations_text([investigation])

    assert "Investigations" in text
    assert "Investigation - 127.0.0.1" in text
    assert "Target: 127.0.0.1" in text
    assert "Risk: HIGH" in text
    assert "Status: Open" in text


def test_timeline_rendering_with_date_and_time() -> None:
    investigation = create_investigation(user_id=9113, target="127.0.0.1")
    event = add_investigation_event(
        investigation_id=investigation["id"],
        user_id=9113,
        target="127.0.0.1",
        event_type="nmap_scan_started",
        tool="nmap",
        status="started",
        summary="Nmap scan started",
    )

    text = build_investigation_timeline_text(investigation, [event])

    assert "Investigation" in text
    assert "Investigation - 127.0.0.1" in text
    assert "Status:\nOpen" in text
    assert "Duration:\nIn progress" in text
    assert "Tools Used:\nNmap" in text
    assert "Investigation Timeline" in text
    assert "Target:\n127.0.0.1" in text
    assert event["created_at"].strftime("%d %b %Y") in text
    assert event["created_at"].strftime("%H:%M") in text
    assert "Nmap Scan Started" in text


def test_investigation_timeline_callback_renders_events() -> None:
    clear_user_investigations(9114)
    investigation = create_investigation(user_id=9114, target="example.com")
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=9114,
        target="example.com",
        event_type="report_generated",
        tool="report",
        status="completed",
        summary="Report generated",
    )
    query = SimpleNamespace(data=f"report:investigation:{investigation['id']}", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9114))

    asyncio.run(reports_callback_handler(update, SimpleNamespace()))

    text = query.edit_message_text.call_args.args[0]
    assert "Investigation Timeline" in text
    assert "Security Report Generated" in text


def test_long_report_splitting() -> None:
    report = "A" * 3900 + "\n\n" + "B" * 3900
    chunks = split_report_text(report, max_length=3800)

    assert len(chunks) > 1
    assert all(len(chunk) <= 3800 for chunk in chunks)


def test_ask_mongrel_sets_ai_waiting_state() -> None:
    clear_ai_waiting(7001)
    message = SimpleNamespace(reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7001))

    asyncio.run(ask_handler(update, SimpleNamespace()))

    assert is_ai_waiting(7001) is True
    assert message.reply_text.call_args.args[0] == "Ask Mongrel anything. Cybersecurity is my specialty."


def test_ai_question_triggers_ask_ai_and_keeps_state() -> None:
    clear_ai_waiting(7002)
    message = SimpleNamespace(text="How do I harden SSH?", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7002))
    asyncio.run(ask_handler(SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()), effective_user=SimpleNamespace(id=7002)), SimpleNamespace()))

    with patch("app.bot.handlers.scan.ask_ai", return_value="AI integration is not configured yet.") as ask_ai:
        asyncio.run(scan_target_handler(update, SimpleNamespace(user_data={})))

    ask_ai.assert_called_once_with("How do I harden SSH?")
    assert is_ai_waiting(7002) is True
    assert message.reply_text.call_args_list[0].args[0] == "Analyzing..."
    assert message.reply_text.call_args_list[1].args[0] == "AI integration is not configured yet."


def test_ai_question_failure_returns_safe_message() -> None:
    clear_ai_waiting(7005)
    message = SimpleNamespace(text="How do I harden SSH?", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7005))
    asyncio.run(ask_handler(SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()), effective_user=SimpleNamespace(id=7005)), SimpleNamespace()))

    with patch("app.bot.handlers.scan.ask_ai", side_effect=RuntimeError("boom")):
        asyncio.run(scan_target_handler(update, SimpleNamespace(user_data={})))

    assert is_ai_waiting(7005) is True
    assert message.reply_text.call_args_list[0].args[0] == "Analyzing..."
    assert message.reply_text.call_args_list[1].args[0] == "AI request failed. Check bot logs."


def test_multiple_consecutive_ai_questions_stay_in_session() -> None:
    clear_ai_waiting(7006)
    asyncio.run(
        ask_handler(
            SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()), effective_user=SimpleNamespace(id=7006)),
            SimpleNamespace(),
        )
    )

    with patch("app.bot.handlers.scan.ask_ai", side_effect=["Linux answer", "Nmap answer"]) as ask_ai:
        first_message = SimpleNamespace(text="What is Linux?", reply_text=AsyncMock())
        second_message = SimpleNamespace(text="What is Nmap?", reply_text=AsyncMock())
        asyncio.run(
            scan_target_handler(
                SimpleNamespace(message=first_message, effective_user=SimpleNamespace(id=7006)),
                SimpleNamespace(user_data={}),
            )
        )
        asyncio.run(
            scan_target_handler(
                SimpleNamespace(message=second_message, effective_user=SimpleNamespace(id=7006)),
                SimpleNamespace(user_data={}),
            )
        )

    assert ask_ai.call_args_list[0].args[0] == "What is Linux?"
    assert ask_ai.call_args_list[1].args[0] == "What is Nmap?"
    assert first_message.reply_text.call_args_list[1].args[0] == "Linux answer"
    assert second_message.reply_text.call_args_list[1].args[0] == "Nmap answer"
    assert is_ai_waiting(7006) is True


def test_home_exits_ai_session() -> None:
    clear_ai_waiting(7007)
    asyncio.run(
        ask_handler(
            SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()), effective_user=SimpleNamespace(id=7007)),
            SimpleNamespace(),
        )
    )
    message = SimpleNamespace(text="Home", reply_text=AsyncMock())

    asyncio.run(home_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7007)), SimpleNamespace()))

    assert is_ai_waiting(7007) is False
    assert "Project Mongrel control panel" in message.reply_text.call_args.args[0]


def test_cancel_exits_ai_session() -> None:
    clear_ai_waiting(7008)
    asyncio.run(
        ask_handler(
            SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()), effective_user=SimpleNamespace(id=7008)),
            SimpleNamespace(),
        )
    )
    message = SimpleNamespace(text="Cancel", reply_text=AsyncMock())

    asyncio.run(cancel_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7008)), SimpleNamespace()))

    assert is_ai_waiting(7008) is False
    assert message.reply_text.call_args.args[0] == "Ask Mongrel session closed."


def test_normal_messages_do_not_trigger_ai() -> None:
    clear_ai_waiting(7003)
    message = SimpleNamespace(text="hello", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7003))

    with patch("app.bot.handlers.scan.ask_ai") as ask_ai:
        asyncio.run(scan_target_handler(update, SimpleNamespace(user_data={})))

    ask_ai.assert_not_called()
    message.reply_text.assert_not_called()


def test_scan_workflow_still_runs_when_ai_state_is_not_waiting() -> None:
    clear_ai_waiting(7004)
    clear_user_findings(7004)
    clear_user_investigations(7004)
    clear_user_scan_requests(7004)
    scan_request = create_scan_request(user_id=7004, scan_type="nmap")
    mark_scan_request_awaiting_target(user_id=7004, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="127.0.0.1", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7004))

    with patch(
        "app.bot.handlers.scan.run_nmap_scan",
        return_value={
            "success": True,
            "target": "127.0.0.1",
            "output": "Nmap scan report for 127.0.0.1\nHost is up.\n22/tcp open ssh\n",
            "error": "",
        },
    ) as run_nmap_scan:
        asyncio.run(scan_target_handler(update, context))

    run_nmap_scan.assert_called_once_with("127.0.0.1")
    assert message.reply_text.call_args_list[0].args[0] == "Running NMAP scan for target: 127.0.0.1"
    assert "Target: 127.0.0.1" in message.reply_text.call_args_list[1].args[0]
    assert get_user_findings(7004)
    investigation = get_user_investigations(7004)[0]
    events = get_investigation_events(investigation["id"], 7004)
    assert [event["event_type"] for event in events] == ["nmap_scan_started", "nmap_scan_completed"]


def test_scan_menu_includes_nuclei_scan() -> None:
    keyboard = build_scan_type_keyboard()
    rendered_buttons = [button.text for row in keyboard.inline_keyboard for button in row]

    assert "Nmap Scan" in rendered_buttons
    assert "Nuclei Scan" in rendered_buttons
    assert "BBOT Recon" in rendered_buttons


def test_nuclei_scan_callback_prompts_for_target() -> None:
    clear_user_scan_requests(7101)
    query = SimpleNamespace(data="scan:nuclei", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7101))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_nuclei_target_prompt()
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_bbot_scan_callback_prompts_for_target() -> None:
    clear_user_scan_requests(7201)
    query = SimpleNamespace(data="scan:bbot", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7201))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_bbot_target_prompt()
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_successful_bbot_scan_creates_events_and_stores_result() -> None:
    clear_user_findings(7202)
    clear_user_investigations(7202)
    clear_user_observations(7202)
    clear_user_scan_requests(7202)
    scan_request = create_scan_request(user_id=7202, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7202, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7202))
    result = {
        "success": True,
        "target": "example.com",
        "output": "Found app.example.com and https://api.example.com/login",
        "error": "",
        "returncode": 0,
        "elapsed_seconds": 3.4,
        "output_dir": "data/bbot/example.com",
    }

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=True),
        patch("app.bot.handlers.scan.run_bbot_scan", return_value=result) as run_bbot_scan,
    ):
        asyncio.run(scan_target_handler(update, context))

    run_bbot_scan.assert_called_once_with("https://example.com")
    assert message.reply_text.call_args_list[0].args[0] == "BBOT recon started.\n\nTarget:\nexample.com"
    assert "BBOT Recon" in message.reply_text.call_args_list[1].args[0]
    assert "Recon Overview" in message.reply_text.call_args_list[1].args[0]
    assert "- Subdomains:" in message.reply_text.call_args_list[1].args[0]
    assert "- URLs: 1" in message.reply_text.call_args_list[1].args[0]
    assert "Recommended Next Actions" in message.reply_text.call_args_list[1].args[0]
    keyboard = message.reply_text.call_args_list[1].kwargs["reply_markup"]
    assert keyboard.inline_keyboard[0][0].text == "Generate AI Recon Assessment"
    assert keyboard.inline_keyboard[0][0].callback_data.startswith("bbot_ai:")
    findings = get_user_findings(7202)
    assert findings[0]["source"] == "bbot"
    assert findings[0]["target"] == "example.com"
    assert findings[0]["target_key"] == "example.com"
    assert findings[0]["status"] == "completed"
    assert findings[0]["risk_level"] == "info"
    assert findings[0]["finding_count"] >= 2
    assert "Observations:" in findings[0]["summary"]
    investigation = get_user_investigations(7202)[0]
    events = get_investigation_events(investigation["id"], 7202)
    assert [event["event_type"] for event in events] == ["bbot_scan_started", "bbot_scan_completed"]
    assert "Recon Summary Generated" in events[-1]["summary"]
    observations = get_investigation_observations(investigation["id"], 7202)
    assert observations
    assert get_user_observations(7202) == observations
    assert context.user_data == {}


def test_bbot_ai_assessment_keyboard_exists() -> None:
    keyboard = build_bbot_ai_assessment_keyboard("investigation-1")

    assert keyboard is not None
    assert keyboard.inline_keyboard[0][0].text == "Generate AI Recon Assessment"
    assert keyboard.inline_keyboard[0][0].callback_data == "bbot_ai:investigation-1"


def test_bbot_ai_assessment_callback_success_sends_assessment_and_timeline_event() -> None:
    clear_user_investigations(7210)
    clear_user_observations(7210)
    investigation = create_investigation(user_id=7210, target="example.com")
    add_observation(
        user_id=7210,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="admin.example.com",
        target="example.com",
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"bbot_ai:{investigation['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7210))

    with patch(
        "app.bot.handlers.scan.generate_bbot_ai_assessment",
        return_value=["AI Recon Assessment", "Confidence:", "MEDIUM"],
    ):
        asyncio.run(scan_callback_handler(update, SimpleNamespace(user_data={})))

    query.answer.assert_called_once()
    edited_messages = [call.args[0] for call in query.edit_message_text.call_args_list]
    assert "Generating AI Recon Assessment /" in edited_messages
    assert edited_messages[-1] == "AI Recon Assessment ready."
    query_message.reply_text.assert_called_once_with("AI Recon Assessment\nConfidence:\nMEDIUM")
    events = get_investigation_events(investigation["id"], 7210)
    assert events[-1]["event_type"] == "bbot_ai_assessment_generated"
    assert events[-1]["summary"] == "BBOT AI Recon Assessment Generated"


def test_bbot_ai_assessment_callback_failure_sends_fallback_and_timeline_event() -> None:
    clear_user_investigations(7211)
    clear_user_observations(7211)
    investigation = create_investigation(user_id=7211, target="example.com")
    add_observation(
        user_id=7211,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="app.example.com",
        target="example.com",
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"bbot_ai:{investigation['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7211))

    with patch("app.bot.handlers.scan.generate_bbot_ai_assessment", return_value=FALLBACK_LINES):
        asyncio.run(scan_callback_handler(update, SimpleNamespace(user_data={})))

    assert query.edit_message_text.call_args_list[-1].args[0] == "AI Recon Assessment unavailable."
    query_message.reply_text.assert_called_once_with("\n".join(FALLBACK_LINES))
    events = get_investigation_events(investigation["id"], 7211)
    assert events[-1]["event_type"] == "bbot_ai_assessment_fallback"
    assert events[-1]["summary"] == "BBOT AI Recon Assessment Fallback"


def test_bbot_ai_assessment_callback_chunks_response() -> None:
    clear_user_investigations(7212)
    investigation = create_investigation(user_id=7212, target="example.com")
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"bbot_ai:{investigation['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7212))

    with (
        patch("app.bot.handlers.scan.generate_bbot_ai_assessment", return_value=["AI Recon Assessment", "Confidence:", "LOW"]),
        patch("app.bot.handlers.scan.split_report_text", return_value=["chunk one", "chunk two"]) as splitter,
    ):
        asyncio.run(scan_callback_handler(update, SimpleNamespace(user_data={})))

    splitter.assert_called_once_with("AI Recon Assessment\nConfidence:\nLOW")
    assert [call.args[0] for call in query_message.reply_text.call_args_list] == ["chunk one", "chunk two"]


def test_bbot_scan_missing_binary_does_not_crash() -> None:
    clear_user_scan_requests(7203)
    scan_request = create_scan_request(user_id=7203, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7203, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7203))

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=False),
        patch("app.bot.handlers.scan.run_bbot_scan") as run_bbot_scan,
    ):
        asyncio.run(scan_target_handler(update, context))

    run_bbot_scan.assert_not_called()
    message.reply_text.assert_called_once_with("BBOT is not installed or not available on PATH.")
    assert context.user_data == {}


def test_bbot_scan_failure_creates_failed_event_and_stores_result() -> None:
    clear_user_findings(7204)
    clear_user_investigations(7204)
    clear_user_scan_requests(7204)
    scan_request = create_scan_request(user_id=7204, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7204, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7204))

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=True),
        patch(
            "app.bot.handlers.scan.run_bbot_scan",
            return_value={
                "success": False,
                "target": "example.com",
                "output": "",
                "error": "BBOT recon failed.",
                "returncode": 1,
                "elapsed_seconds": 2,
            },
        ),
    ):
        asyncio.run(scan_target_handler(update, context))

    assert "Status:\nFailed" in message.reply_text.call_args_list[1].args[0]
    finding = get_user_findings(7204)[0]
    assert finding["source"] == "bbot"
    assert finding["status"] == "failed"
    assert finding["summary"] == "BBOT recon failed."
    investigation = get_user_investigations(7204)[0]
    events = get_investigation_events(investigation["id"], 7204)
    assert [event["event_type"] for event in events] == ["bbot_scan_started", "bbot_scan_failed"]


def test_bbot_scan_zero_observations_handled_cleanly() -> None:
    clear_user_findings(7206)
    clear_user_investigations(7206)
    clear_user_observations(7206)
    clear_user_scan_requests(7206)
    scan_request = create_scan_request(user_id=7206, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7206, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7206))

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=True),
        patch(
            "app.bot.handlers.scan.run_bbot_scan",
            return_value={
                "success": True,
                "target": "example.com",
                "output": "scan complete",
                "error": "",
                "returncode": 0,
                "elapsed_seconds": 1,
            },
        ),
    ):
        asyncio.run(scan_target_handler(update, context))

    assert "Observations Collected: 0" in message.reply_text.call_args_list[1].args[0]
    assert "Continue reconnaissance using additional observation sources." in message.reply_text.call_args_list[1].args[0]
    finding = get_user_findings(7206)[0]
    assert finding["summary"] == "BBOT completed but no structured observations were extracted."
    assert get_user_observations(7206) == []


def test_bbot_scan_summary_chunks_are_sent() -> None:
    clear_user_findings(7207)
    clear_user_investigations(7207)
    clear_user_observations(7207)
    clear_user_scan_requests(7207)
    scan_request = create_scan_request(user_id=7207, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7207, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7207))

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=True),
        patch(
            "app.bot.handlers.scan.run_bbot_scan",
            return_value={
                "success": True,
                "target": "example.com",
                "output": "Found app.example.com",
                "error": "",
                "returncode": 0,
                "elapsed_seconds": 1,
            },
        ),
        patch("app.bot.handlers.scan.split_report_text", return_value=["chunk one", "chunk two"]) as splitter,
    ):
        asyncio.run(scan_target_handler(update, context))

    splitter.assert_called_once()
    assert [call.args[0] for call in message.reply_text.call_args_list] == [
        "BBOT recon started.\n\nTarget:\nexample.com",
        "chunk one",
        "chunk two",
    ]


def test_bbot_scan_result_formatter_uses_recon_summary() -> None:
    text = build_bbot_result_text(
        {
            "success": True,
            "target": "example.com",
            "output": "A" * 1000,
            "elapsed_seconds": 1,
        },
        recon_summary="BBOT Recon Summary\n\nTarget:\nexample.com",
    )

    assert text == "BBOT Recon Summary\n\nTarget:\nexample.com"


def test_bbot_scan_result_formatter_keeps_failure_output_concise() -> None:
    text = build_bbot_result_text(
        {
            "success": False,
            "target": "example.com",
            "error": "A" * 1000,
            "elapsed_seconds": 1,
        }
    )

    assert "Status:\nFailed" in text
    assert "...[truncated]" in text


def test_store_bbot_scan_result_persists_minimal_history() -> None:
    clear_user_findings(7205)
    finding = store_bbot_scan_result(
        user_id=7205,
        result={
            "success": True,
            "target": "example.com",
            "output": "bbot output",
            "error": "",
            "returncode": 0,
            "elapsed_seconds": 1.2,
            "output_dir": "data/bbot/example.com",
        },
    )

    assert finding["source"] == "bbot"
    assert finding["target"] == "example.com"
    assert finding["status"] == "completed"
    assert finding["summary"] == "BBOT completed but no structured observations were extracted."
    assert finding["risk_level"] == "info"
    assert finding["finding_count"] == 0
    assert finding["raw_output"] == "bbot output"


def test_successful_nuclei_scan_returns_verdict_and_stores_finding() -> None:
    clear_user_findings(7102)
    clear_user_investigations(7102)
    clear_user_scan_requests(7102)
    clear_active_scan(7102)
    scan_request = create_scan_request(user_id=7102, scan_type="nuclei")
    mark_scan_request_awaiting_target(user_id=7102, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7102))
    nuclei_output = (
        '{"template-id":"git-config-exposure","info":{"name":"Exposed Git Repository","severity":"high","tags":["git","exposure"]},'
        '"host":"https://example.com","matched-at":"https://example.com/.git/config"}'
    )

    async def run_flow() -> None:
        with patch(
            "app.bot.handlers.scan.run_nuclei_scan",
            return_value={
                "success": True,
                "target": "https://example.com",
                "output": nuclei_output,
                "error": "",
                "returncode": 0,
            },
        ) as run_nuclei_scan:
            await scan_target_handler(update, context)
            active_scan = get_active_scan(7102)
            assert active_scan is not None
            assert active_scan.task is not None
            await active_scan.task

        run_nuclei_scan.assert_called_once_with("https://example.com")

    asyncio.run(run_flow())
    assert "Nuclei Fast Scan" in message.reply_text.call_args_list[0].args[0]
    assert "Status:\nInitializing" in message.reply_text.call_args_list[0].args[0]
    assert "Status:\nComplete" in status_message.edit_text.call_args.args[0]
    assert "Nuclei Verdict" in message.reply_text.call_args_list[1].args[0]
    assert "Risk Level:\nHIGH" in message.reply_text.call_args_list[1].args[0]
    findings = get_user_findings(7102)
    assert findings[0]["source"] == "nuclei"
    assert findings[0]["target"] == "https://example.com"
    investigation = get_user_investigations(7102)[0]
    events = get_investigation_events(investigation["id"], 7102)
    assert [event["event_type"] for event in events] == ["nuclei_scan_started", "nuclei_scan_completed"]
    assert context.user_data == {}


def test_nuclei_scan_no_findings_output() -> None:
    clear_user_findings(7103)
    clear_user_scan_requests(7103)
    clear_active_scan(7103)
    scan_request = create_scan_request(user_id=7103, scan_type="nuclei")
    mark_scan_request_awaiting_target(user_id=7103, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7103))

    async def run_flow() -> None:
        with patch(
            "app.bot.handlers.scan.run_nuclei_scan",
            return_value={"success": True, "target": "https://example.com", "output": "", "error": "", "returncode": 0},
        ):
            await scan_target_handler(update, context)
            active_scan = get_active_scan(7103)
            assert active_scan is not None
            assert active_scan.task is not None
            await active_scan.task

    asyncio.run(run_flow())
    assert "Status:\nComplete" in status_message.edit_text.call_args.args[0]
    verdict_text = message.reply_text.call_args_list[1].args[0]
    assert "Nuclei Verdict" in verdict_text
    assert "Target:\nhttps://example.com" in verdict_text
    assert "Risk Level:\nINFO" in verdict_text
    assert "Findings:\n0" in verdict_text
    assert "No matching Nuclei findings were identified using the fast scan profile." in verdict_text
    assert "- The target was reachable." in verdict_text
    assert "- Nuclei executed successfully." in verdict_text
    assert "- Continue regular patching and monitoring." in verdict_text
    clean_record = get_user_findings(7103)[0]
    assert clean_record["source"] == "nuclei"
    assert clean_record["status"] == "clean"
    assert clean_record["risk_level"] == "info"
    assert clean_record["finding_count"] == 0
    assert clean_record["summary"] == "No matching Nuclei findings were identified using the fast scan profile."


def test_clean_nuclei_verdict_formatter_for_no_findings() -> None:
    verdict_text = build_clean_nuclei_verdict_text("hellosundaykids.com")

    assert "Nuclei Verdict" in verdict_text
    assert "Target:\nhellosundaykids.com" in verdict_text
    assert "Risk Level:\nINFO" in verdict_text
    assert "Findings:\n0" in verdict_text
    assert "What this means:" in verdict_text
    assert "Recommended Actions:" in verdict_text


def test_clean_nuclei_scan_record_appears_in_findings_view() -> None:
    finding = store_clean_nuclei_scan(user_id=7108, target="hellosundaykids.com")

    findings_text = build_findings_text([finding])

    assert "Nuclei Fast Scan" in findings_text
    assert "Target: hellosundaykids.com" in findings_text
    assert "Result: Clean" in findings_text
    assert "Findings: 0" in findings_text
    assert "Risk Level: INFO" in findings_text


def test_clean_nuclei_scan_detail_view() -> None:
    finding = store_clean_nuclei_scan(user_id=7109, target="hellosundaykids.com")

    detail_text = build_finding_detail_text(finding)

    assert "Nuclei Fast Scan" in detail_text
    assert "Result: Clean" in detail_text
    assert "Findings: 0" in detail_text
    assert "Risk Level: INFO" in detail_text
    assert "No matching Nuclei findings were identified using the fast scan profile." in detail_text


def test_nuclei_scan_runner_failure_message() -> None:
    clear_user_scan_requests(7104)
    clear_active_scan(7104)
    scan_request = create_scan_request(user_id=7104, scan_type="nuclei")
    mark_scan_request_awaiting_target(user_id=7104, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7104))

    async def run_flow() -> None:
        with patch(
            "app.bot.handlers.scan.run_nuclei_scan",
            return_value={
                "success": False,
                "target": "https://example.com",
                "output": "",
                "error": "Nuclei executable was not found.",
                "returncode": None,
            },
        ):
            await scan_target_handler(update, context)
            active_scan = get_active_scan(7104)
            assert active_scan is not None
            assert active_scan.task is not None
            await active_scan.task

    asyncio.run(run_flow())
    assert "Status:\nFailed" in status_message.edit_text.call_args.args[0]
    assert "Reason:\nNuclei executable was not found." in status_message.edit_text.call_args.args[0]
    assert message.reply_text.call_args_list[1].args[0] == "Nuclei scan failed: Nuclei executable was not found."


def test_nuclei_scan_state_created() -> None:
    clear_user_scan_requests(7105)
    clear_active_scan(7105)
    scan_request = create_scan_request(user_id=7105, scan_type="nuclei")
    mark_scan_request_awaiting_target(user_id=7105, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7105))

    async def run_flow() -> None:
        with patch(
            "app.bot.handlers.scan.run_nuclei_scan",
            side_effect=lambda target: (time.sleep(0.2) or {"success": True, "target": target, "output": "", "error": "", "returncode": 0}),
        ):
            await scan_target_handler(update, context)
            active_scan = get_active_scan(7105)
            assert active_scan is not None
            assert active_scan.scan_type == "nuclei"
            assert active_scan.target == "example.com"
            assert active_scan.task is not None
            assert active_scan.status_message is status_message
            active_scan.task.cancel()
            try:
                await active_scan.task
            except asyncio.CancelledError:
                pass

    asyncio.run(run_flow())


def test_cancel_cancels_active_nuclei_scan() -> None:
    clear_user_scan_requests(7106)
    clear_active_scan(7106)
    scan_request = create_scan_request(user_id=7106, scan_type="nuclei")
    mark_scan_request_awaiting_target(user_id=7106, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    scan_message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    cancel_message = SimpleNamespace(text="Cancel", reply_text=AsyncMock())

    async def run_flow() -> None:
        with patch(
            "app.bot.handlers.scan.run_nuclei_scan",
            side_effect=lambda target: (time.sleep(0.2) or {"success": True, "target": target, "output": "", "error": "", "returncode": 0}),
        ):
            await scan_target_handler(
                SimpleNamespace(message=scan_message, effective_user=SimpleNamespace(id=7106)),
                context,
            )
            active_scan = get_active_scan(7106)
            assert active_scan is not None
            assert active_scan.task is not None
            await cancel_handler(
                SimpleNamespace(message=cancel_message, effective_user=SimpleNamespace(id=7106)),
                SimpleNamespace(),
            )
            try:
                await active_scan.task
            except asyncio.CancelledError:
                pass

    asyncio.run(run_flow())
    assert cancel_message.reply_text.call_args.args[0] == "Nuclei scan cancelled."
    assert get_active_scan(7106) is None
    assert "Status:\nCancelled" in status_message.edit_text.call_args.args[0]
    assert len(scan_message.reply_text.call_args_list) == 1


def test_home_clears_active_nuclei_scan_state() -> None:
    clear_user_scan_requests(7107)
    clear_active_scan(7107)
    scan_request = create_scan_request(user_id=7107, scan_type="nuclei")
    mark_scan_request_awaiting_target(user_id=7107, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    scan_message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    home_message = SimpleNamespace(text="Home", reply_text=AsyncMock())

    async def run_flow() -> None:
        with patch(
            "app.bot.handlers.scan.run_nuclei_scan",
            side_effect=lambda target: (time.sleep(0.2) or {"success": True, "target": target, "output": "", "error": "", "returncode": 0}),
        ):
            await scan_target_handler(
                SimpleNamespace(message=scan_message, effective_user=SimpleNamespace(id=7107)),
                context,
            )
            active_scan = get_active_scan(7107)
            assert active_scan is not None
            assert active_scan.task is not None
            await home_handler(
                SimpleNamespace(message=home_message, effective_user=SimpleNamespace(id=7107)),
                SimpleNamespace(),
            )
            try:
                await active_scan.task
            except asyncio.CancelledError:
                pass

    asyncio.run(run_flow())
    assert get_active_scan(7107) is None
    assert "Project Mongrel control panel" in home_message.reply_text.call_args.args[0]
    assert "Status:\nCancelled" in status_message.edit_text.call_args.args[0]
    assert len(scan_message.reply_text.call_args_list) == 1


def test_status_edit_timeout_does_not_crash_updater(caplog) -> None:
    clear_active_scan(7110)
    set_active_scan(user_id=7110, scan_type="nuclei", target="example.com")
    status_message = SimpleNamespace(edit_text=AsyncMock(side_effect=TimedOut("status timeout")))

    async def fake_sleep(seconds: int) -> None:
        assert seconds == NUCLEI_STATUS_UPDATE_INTERVAL_SECONDS
        if status_message.edit_text.await_count:
            raise asyncio.CancelledError

    async def run_flow() -> None:
        with patch("app.bot.handlers.scan.asyncio.sleep", side_effect=fake_sleep):
            await _update_nuclei_status_card(7110, status_message, "example.com", asyncio.get_running_loop().time())

    asyncio.run(run_flow())
    clear_active_scan(7110)

    assert status_message.edit_text.await_count == 1
    assert "Nuclei status card edit timed out" in caplog.text


def test_final_status_edit_timeout_does_not_prevent_verdict_send() -> None:
    clear_user_findings(7111)
    clear_user_scan_requests(7111)
    clear_active_scan(7111)
    scan_request = create_scan_request(user_id=7111, scan_type="nuclei")
    mark_scan_request_awaiting_target(user_id=7111, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock(side_effect=TimedOut("status timeout")))
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7111))

    async def run_flow() -> None:
        with patch(
            "app.bot.handlers.scan.run_nuclei_scan",
            return_value={"success": True, "target": "https://example.com", "output": "", "error": "", "returncode": 0},
        ):
            await scan_target_handler(update, context)
            active_scan = get_active_scan(7111)
            assert active_scan is not None
            assert active_scan.task is not None
            await active_scan.task

    asyncio.run(run_flow())

    assert "Nuclei Verdict" in message.reply_text.call_args_list[1].args[0]
    assert "Risk Level:\nINFO" in message.reply_text.call_args_list[1].args[0]


def test_failed_status_edit_is_logged(caplog) -> None:
    status_message = SimpleNamespace(edit_text=AsyncMock(side_effect=TimedOut("final timeout")))

    async def run_flow() -> None:
        await _finalize_nuclei_status(status_message, "example.com", "Complete", asyncio.get_running_loop().time())

    asyncio.run(run_flow())

    assert "Nuclei status card edit timed out" in caplog.text


def test_nuclei_status_update_interval_is_15_seconds() -> None:
    assert NUCLEI_STATUS_UPDATE_INTERVAL_SECONDS == 15


def test_cancel_clears_state_when_status_edit_fails() -> None:
    clear_user_scan_requests(7112)
    clear_active_scan(7112)
    scan_request = create_scan_request(user_id=7112, scan_type="nuclei")
    mark_scan_request_awaiting_target(user_id=7112, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock(side_effect=TimedOut("cancel timeout")))
    scan_message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    cancel_message = SimpleNamespace(text="Cancel", reply_text=AsyncMock())

    async def run_flow() -> None:
        with patch(
            "app.bot.handlers.scan.run_nuclei_scan",
            side_effect=lambda target: (time.sleep(0.2) or {"success": True, "target": target, "output": "", "error": "", "returncode": 0}),
        ):
            await scan_target_handler(
                SimpleNamespace(message=scan_message, effective_user=SimpleNamespace(id=7112)),
                context,
            )
            active_scan = get_active_scan(7112)
            assert active_scan is not None
            assert active_scan.task is not None
            await cancel_handler(
                SimpleNamespace(message=cancel_message, effective_user=SimpleNamespace(id=7112)),
                SimpleNamespace(),
            )
            try:
                await active_scan.task
            except asyncio.CancelledError:
                pass

    asyncio.run(run_flow())

    assert get_active_scan(7112) is None
    assert cancel_message.reply_text.call_args.args[0] == "Nuclei scan cancelled."


def test_nmap_result_text_uses_clean_parser_output() -> None:
    result_text = build_nmap_scan_result_text(
        {
            "success": True,
            "target": "127.0.0.1",
            "returncode": 0,
            "output": (
                "Starting Nmap 7.95 ( https://nmap.org )\n"
                "Nmap scan report for 127.0.0.1\n"
                "Host is up (0.00012s latency).\n"
                "PORT     STATE SERVICE\n"
                "22/tcp   open  ssh\n"
                "Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds\n"
            ),
            "error": "",
        }
    )

    assert "Target: 127.0.0.1" in result_text
    assert "Host Status: Up" in result_text
    assert "22/tcp ssh" in result_text
    assert "Duration: 0.32s" in result_text
    assert "Risk: medium" in result_text
    assert "Notes: SSH exposed" in result_text
    assert "https://nmap.org" not in result_text


def test_findings_text_summarizes_latest_findings() -> None:
    finding = {
        "id": "abc123",
        "source": "nmap",
        "target": "127.0.0.1",
        "host_status": "Up",
        "open_ports": [
            {"port": "22", "protocol": "tcp", "service": "ssh"},
            {"port": "445", "protocol": "tcp", "service": "microsoft-ds"},
        ],
        "created_at": "2026-06-18T12:00:00Z",
        "risk_level": "high",
        "risk_notes": ["SMB exposed"],
    }
    findings_text = build_findings_text(
        [finding]
    )
    keyboard = build_findings_keyboard([finding])

    assert "Latest Findings" in findings_text
    assert "#1 HIGH - nmap" in findings_text
    assert "Target: 127.0.0.1" in findings_text
    assert "Host: Up" in findings_text
    assert "Open Ports: 2" in findings_text
    assert "Notes: SMB exposed" in findings_text
    assert keyboard is not None
    assert keyboard.inline_keyboard[0][0].text == "View Details #1"
    assert keyboard.inline_keyboard[0][0].callback_data == "finding:view:abc123"
    assert keyboard.inline_keyboard[1][0].text == "Clear Findings"
    assert keyboard.inline_keyboard[1][0].callback_data == "finding:clear"


def test_successful_nmap_result_creates_finding() -> None:
    clear_user_findings(3001)

    finding = store_successful_nmap_finding(
        user_id=3001,
        result={
            "success": True,
            "target": "127.0.0.1",
            "output": (
                "Nmap scan report for 127.0.0.1\n"
                "Host is up.\n"
                "22/tcp open ssh\n"
                "Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds\n"
            ),
            "error": "",
        },
    )

    assert finding is not None
    assert get_user_findings(3001) == [finding]
    assert finding["source"] == "nmap"
    assert finding["target"] == "127.0.0.1"
    assert finding["target_key"] == "127.0.0.1"
    assert finding["host_status"] == "Up"
    assert finding["open_ports"][0]["port"] == "22"
    assert finding["open_ports"][0]["protocol"] == "tcp"
    assert finding["open_ports"][0]["service"] == "ssh"
    assert finding["duration"] == "0.32s"
    assert finding["risk_level"] == "medium"
    assert finding["risk_notes"] == ["SSH exposed"]
    assert finding["comparison"]["has_previous"] is False
    assert finding["comparison"]["summary"] == "No previous scan found for this target."
    assert finding["impact"]["impact_level"] == "low"
    assert finding["impact"]["summary"] == "No material exposure changes detected."
    assert finding["open_ports"][0]["intelligence"]["name"] == "SSH"
    assert finding["open_ports"][0]["intelligence"]["recommendation"]


def test_findings_include_service_intelligence() -> None:
    findings_text = build_finding_detail_text(
        {
            "source": "nmap",
            "target": "127.0.0.1",
            "host_status": "Up",
            "open_ports": [
                {
                    "port": "445",
                    "protocol": "tcp",
                    "service": "microsoft-ds",
                    "intelligence": {
                        "name": "SMB",
                        "description": "Windows file sharing and remote administration service.",
                        "common_risk": "File exposure and lateral movement.",
                        "recommendation": "Block internet exposure.",
                    },
                }
            ],
            "duration": "0.32s",
            "created_at": "2026-06-18T12:00:00Z",
            "risk_level": "high",
            "risk_notes": ["SMB exposed"],
            "comparison": {
                "has_previous": True,
                "new_ports": [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}],
                "removed_ports": [],
                "unchanged_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
                "risk_changed": True,
                "previous_risk": "medium",
                "current_risk": "high",
                "summary": "1 new port(s), risk changed from medium to high",
            },
            "impact": {
                "impact_level": "high",
                "summary": "High-impact exposure change detected.",
                "impacts": ["SMB file sharing became exposed."],
                "recommendations": ["Restrict or disable SMB if not required."],
            },
        },
        display_number=1,
    )

    assert "Finding #1" in findings_text
    assert "Mongrel Verdict" in findings_text
    assert "HIGH RISK" in findings_text
    assert "Summary:" in findings_text
    assert "Key Findings:" in findings_text
    assert "- Windows SMB file sharing service exposed." in findings_text
    assert "Recommended Actions:" in findings_text
    assert "- Restrict or disable SMB if not required." in findings_text
    assert "Comparison" in findings_text
    assert "New Ports: 445/tcp microsoft-ds" in findings_text
    assert "Removed Ports: none" in findings_text
    assert "Risk Change: MEDIUM -> HIGH" in findings_text
    assert "Unchanged Ports: 1" in findings_text
    assert "Impact Assessment" in findings_text
    assert "Change Impact: HIGH" in findings_text
    assert "Summary:" in findings_text
    assert "Reason:" in findings_text
    assert "A new high-risk service became exposed." in findings_text
    assert "SMB file sharing became exposed." in findings_text
    assert "Restrict or disable SMB if not required." in findings_text
    assert "Technical Details" in findings_text
    assert "Risk: HIGH" in findings_text
    assert "445/tcp microsoft-ds" in findings_text
    assert "Windows file sharing and remote administration service." in findings_text
    assert "Risk: File exposure and lateral movement." in findings_text
    assert "Recommendation: Block internet exposure." in findings_text


def test_unknown_finding_id_handled_safely() -> None:
    assert build_finding_detail_text(None) == "Finding not found."


def test_back_button_routes_to_findings_list() -> None:
    keyboard = build_finding_detail_keyboard()

    assert keyboard.inline_keyboard[0][0].text == "Back to Findings"
    assert keyboard.inline_keyboard[0][0].callback_data == "finding:list"


def test_nmap_detail_includes_explain_with_mongrel_ai_button() -> None:
    keyboard = build_finding_detail_keyboard("nmap-id")

    assert keyboard.inline_keyboard[0][0].text == "Explain with Mongrel AI"
    assert keyboard.inline_keyboard[0][0].callback_data == "explain:finding:nmap-id"
    assert keyboard.inline_keyboard[1][0].callback_data == "finding:list"


def test_nuclei_positive_detail_includes_explain_with_mongrel_ai_button() -> None:
    keyboard = build_finding_detail_keyboard("nuclei-id")

    assert keyboard.inline_keyboard[0][0].text == "Explain with Mongrel AI"
    assert keyboard.inline_keyboard[0][0].callback_data == "explain:finding:nuclei-id"


def test_clean_nuclei_detail_includes_explain_with_mongrel_ai_button() -> None:
    keyboard = build_finding_detail_keyboard("clean-id")

    assert keyboard.inline_keyboard[0][0].text == "Explain with Mongrel AI"
    assert keyboard.inline_keyboard[0][0].callback_data == "explain:finding:clean-id"


def test_nmap_finding_ai_prompt_includes_ports_services_and_guardrails() -> None:
    prompt = build_finding_ai_prompt(
        {
            "source": "nmap",
            "target": "127.0.0.1",
            "host_status": "Up",
            "risk_level": "high",
            "risk_notes": ["SSH exposed"],
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        }
    )

    assert prompt is not None
    assert "22/tcp ssh" in prompt
    assert "Target: 127.0.0.1" in prompt
    assert "What this means" in prompt
    assert "Highest priority risks" in prompt
    assert "- Do not invent ports." in prompt
    assert "- Do not invent services." in prompt
    assert "- Do not reassign services to ports." in prompt
    assert "- Accuracy is more important than completeness." in prompt


def test_nuclei_finding_ai_prompt_includes_severity_findings_and_guardrails() -> None:
    prompt = build_finding_ai_prompt(
        {
            "source": "nuclei",
            "target": "https://example.com",
            "risk_level": "high",
            "finding_count": 1,
            "severity_summary": {"high": 1},
            "nuclei_findings": [
                {
                    "template_id": "git-config-exposure",
                    "severity": "high",
                    "name": "Exposed Git Repository",
                    "host": "https://example.com",
                }
            ],
        }
    )

    assert prompt is not None
    assert "Exposed Git Repository" in prompt
    assert "high: 1" in prompt
    assert "What to verify first" in prompt
    assert "Suggested remediation" in prompt
    assert "- Do not invent CVEs." in prompt
    assert "- Do not invent vulnerabilities." in prompt


def test_clean_nuclei_ai_prompt_includes_clean_scan_context() -> None:
    prompt = build_finding_ai_prompt(
        {
            "source": "nuclei",
            "target": "hellosundaykids.com",
            "status": "clean",
            "risk_level": "info",
            "finding_count": 0,
            "summary": "No matching Nuclei findings were identified using the fast scan profile.",
        }
    )

    assert prompt is not None
    assert "clean Nuclei fast scan" in prompt
    assert "Status: clean" in prompt
    assert "Finding count: 0" in prompt
    assert "What it does not prove" in prompt
    assert "What to do next" in prompt


def test_findings_explain_callback_returns_ai_response() -> None:
    clear_user_findings(4010)
    clear_finding_analysis_context(4010)
    finding = add_finding(
        user_id=4010,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "host_status": "Up",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
            "risk_level": "medium",
            "risk_notes": ["SSH exposed"],
        },
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"explain:finding:{finding['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=4010))

    with patch("app.bot.handlers.findings.ask_ai", return_value="Plain English finding explanation.") as ask_ai:
        asyncio.run(findings_callback_handler(update, SimpleNamespace()))

    prompt = ask_ai.call_args.args[0]
    assert "Target: 127.0.0.1" in prompt
    assert "22/tcp ssh" in prompt
    assert query_message.reply_text.call_args_list[0].args[0] == "Mongrel is analyzing this finding..."
    assert query_message.reply_text.call_args_list[1].args[0] == "Plain English finding explanation."
    assert "Finding Analysis Mode" in query_message.reply_text.call_args_list[2].args[0]
    assert get_finding_analysis_context(4010)["finding_id"] == finding["id"]


def test_findings_explain_callback_handles_missing_finding() -> None:
    clear_user_findings(4011)
    query = SimpleNamespace(
        data="explain:finding:missing",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=4011))

    asyncio.run(findings_callback_handler(update, SimpleNamespace()))

    query.edit_message_text.assert_called_once_with("Finding not found.")


def test_findings_explain_callback_handles_ai_failure() -> None:
    clear_user_findings(4012)
    finding = add_finding(
        user_id=4012,
        finding={
            "source": "nuclei",
            "target": "https://example.com",
            "risk_level": "high",
            "finding_count": 1,
            "severity_summary": {"high": 1},
            "nuclei_findings": [{"template_id": "git-config-exposure", "severity": "high"}],
        },
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"explain:finding:{finding['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=4012))

    with patch("app.bot.handlers.findings.ask_ai", side_effect=RuntimeError("boom")):
        asyncio.run(findings_callback_handler(update, SimpleNamespace()))

    assert query_message.reply_text.call_args_list[0].args[0] == "Mongrel is analyzing this finding..."
    assert query_message.reply_text.call_args_list[1].args[0] == "AI explanation failed. Check bot logs."


def test_findings_explain_callback_handles_unsupported_source() -> None:
    clear_user_findings(4013)
    finding = add_finding(
        user_id=4013,
        finding={
            "source": "bbot",
            "target": "https://example.com",
        },
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"explain:finding:{finding['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=4013))

    asyncio.run(findings_callback_handler(update, SimpleNamespace()))

    query_message.reply_text.assert_called_once_with("Unsupported finding source.")


def test_finding_analysis_context_builder_stores_structured_data() -> None:
    finding = {
        "id": "finding-1",
        "source": "nmap",
        "target": "127.0.0.1",
        "risk_level": "medium",
        "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
    }

    context = build_finding_analysis_context(finding)

    assert context["finding_id"] == "finding-1"
    assert context["source"] == "nmap"
    assert context["target"] == "127.0.0.1"
    assert "1 open port" in context["summary"]
    assert context["finding"]["open_ports"][0]["service"] == "ssh"


def test_finding_followup_prompt_contains_stored_finding_question_and_guardrails() -> None:
    context = build_finding_analysis_context(
        {
            "id": "finding-2",
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "high",
            "risk_notes": ["SSH exposed"],
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        }
    )

    prompt = build_finding_followup_ai_prompt(context, "Why is SSH important?")

    assert "Finding ID: finding-2" in prompt
    assert "Finding source: nmap" in prompt
    assert "Tools already used: Nmap" in prompt
    assert "Target: 127.0.0.1" in prompt
    assert "22/tcp ssh" in prompt
    assert "Latest user question:\nWhy is SSH important?" in prompt
    assert "- Never invent scan results." in prompt
    assert "- Never invent ports." in prompt
    assert "- Never invent services." in prompt
    assert "- Never invent CVEs." in prompt
    assert "- Never invent vulnerabilities." in prompt
    assert "- Base answers only on stored finding plus user question." in prompt
    assert "- If information is unknown, explicitly say so." in prompt
    assert (
        "- Do not recommend the same tool as the primary next step if it was already used, unless suggesting a specific re-scan or different scan mode."
    ) in prompt


def test_nmap_followup_prompt_suggests_alternative_next_tools() -> None:
    context = build_finding_analysis_context(
        {
            "id": "finding-nmap-tools",
            "source": "nmap",
            "target": "example.com",
            "open_ports": [{"port": "443", "protocol": "tcp", "service": "https"}],
        }
    )

    prompt = build_finding_followup_ai_prompt(context, "What other tools should I use?")

    assert "Finding source: nmap" in prompt
    assert "Tools already used: Nmap" in prompt
    assert "Useful next tools for Nmap findings:" in prompt
    assert "- Nuclei" in prompt
    assert "- OWASP ZAP baseline scan" in prompt
    assert "- Burp Suite manual testing" in prompt
    assert "- SSL Labs / testssl.sh for TLS" in prompt
    assert "- securityheaders.com or header checks" in prompt
    assert "- technology fingerprinting" in prompt
    assert "- manual config review" in prompt


def test_nuclei_followup_prompt_includes_source_and_validation_guidance() -> None:
    context = build_finding_analysis_context(
        {
            "id": "finding-nuclei-tools",
            "source": "nuclei",
            "target": "https://example.com",
            "risk_level": "high",
            "finding_count": 1,
            "severity_summary": {"high": 1},
            "nuclei_findings": [{"template_id": "git-config-exposure", "severity": "high"}],
        }
    )

    prompt = build_finding_followup_ai_prompt(context, "What should I do next?")

    assert "Finding source: nuclei" in prompt
    assert "Tools already used: Nuclei" in prompt
    assert "Useful next actions/tools for Nuclei findings:" in prompt
    assert "- manual validation" in prompt
    assert "- browser verification" in prompt
    assert "- Burp Suite/ZAP" in prompt
    assert "- patch/config review" in prompt
    assert "- re-scan after remediation" in prompt
    assert (
        "- Do not recommend the same tool as the primary next step if it was already used, unless suggesting a specific re-scan or different scan mode."
    ) in prompt


def test_finding_analysis_followup_question_routed_to_ai() -> None:
    clear_finding_analysis_context(4014)
    clear_ai_waiting(4014)
    finding = {
        "id": "finding-3",
        "source": "nuclei",
        "target": "https://example.com",
        "risk_level": "high",
        "finding_count": 1,
        "severity_summary": {"high": 1},
        "nuclei_findings": [{"template_id": "git-config-exposure", "severity": "high", "name": "Git exposed"}],
    }
    set_finding_analysis_context(4014, build_finding_analysis_context(finding))
    message = SimpleNamespace(text="What should I verify first?", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=4014))

    with patch("app.bot.handlers.scan.ask_ai", return_value="Verify the exposed Git path.") as ask_ai:
        asyncio.run(scan_target_handler(update, SimpleNamespace(user_data={})))

    prompt = ask_ai.call_args.args[0]
    assert "Git exposed" in prompt
    assert "What should I verify first?" in prompt
    assert message.reply_text.call_args_list[0].args[0] == "Analyzing..."
    assert message.reply_text.call_args_list[1].args[0] == "Verify the exposed Git path."
    assert get_finding_analysis_context(4014) is not None


def test_finding_analysis_has_priority_over_ask_mongrel() -> None:
    clear_finding_analysis_context(4015)
    clear_ai_waiting(4015)
    set_finding_analysis_context(
        4015,
        build_finding_analysis_context(
            {
                "id": "finding-4",
                "source": "nmap",
                "target": "127.0.0.1",
                "open_ports": [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}],
            }
        ),
    )
    set_ai_waiting(4015)
    message = SimpleNamespace(text="Explain this risk.", reply_text=AsyncMock())

    with patch("app.bot.handlers.scan.ask_ai", return_value="SMB explanation.") as ask_ai:
        asyncio.run(
            scan_target_handler(
                SimpleNamespace(message=message, effective_user=SimpleNamespace(id=4015)),
                SimpleNamespace(user_data={}),
            )
        )

    assert "Stored finding context:" in ask_ai.call_args.args[0]
    assert "445/tcp microsoft-ds" in ask_ai.call_args.args[0]


def test_scan_exits_finding_analysis_and_target_goes_to_scan_flow() -> None:
    clear_finding_analysis_context(4020)
    clear_user_findings(4020)
    clear_user_scan_requests(4020)
    set_finding_analysis_context(
        4020,
        build_finding_analysis_context(
            {
                "id": "finding-scan-exit",
                "source": "nmap",
                "target": "127.0.0.1",
                "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
            }
        ),
    )
    context = SimpleNamespace(user_data={})
    scan_message = SimpleNamespace(text="Scan", reply_text=AsyncMock())

    asyncio.run(scan_handler(SimpleNamespace(message=scan_message, effective_user=SimpleNamespace(id=4020)), context))

    assert get_finding_analysis_context(4020) is None

    query = SimpleNamespace(data="scan:nmap", answer=AsyncMock(), edit_message_text=AsyncMock())
    asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=4020)), context))

    target_message = SimpleNamespace(text="127.0.0.1", reply_text=AsyncMock())
    with patch("app.bot.handlers.scan.ask_ai") as ask_ai, patch(
        "app.bot.handlers.scan.run_nmap_scan",
        return_value={
            "success": True,
            "target": "127.0.0.1",
            "output": "Nmap scan report for 127.0.0.1\nHost is up.\n22/tcp open ssh\n",
            "error": "",
        },
    ) as run_nmap_scan:
        asyncio.run(
            scan_target_handler(
                SimpleNamespace(message=target_message, effective_user=SimpleNamespace(id=4020)),
                context,
            )
        )

    ask_ai.assert_not_called()
    run_nmap_scan.assert_called_once_with("127.0.0.1")
    assert target_message.reply_text.call_args_list[0].args[0] == "Running NMAP scan for target: 127.0.0.1"


def test_finding_analysis_home_exits_mode() -> None:
    clear_finding_analysis_context(4016)
    set_finding_analysis_context(4016, {"finding_id": "finding-5", "target": "127.0.0.1"})
    message = SimpleNamespace(text="Home", reply_text=AsyncMock())

    asyncio.run(home_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=4016)), SimpleNamespace()))

    assert get_finding_analysis_context(4016) is None
    assert message.reply_text.call_args_list[0].args[0] == "Exited Finding Analysis Mode."
    assert "Project Mongrel control panel" in message.reply_text.call_args_list[1].args[0]


def test_finding_analysis_cancel_exits_mode() -> None:
    clear_finding_analysis_context(4017)
    set_finding_analysis_context(4017, {"finding_id": "finding-6", "target": "127.0.0.1"})
    message = SimpleNamespace(text="Cancel", reply_text=AsyncMock())

    asyncio.run(cancel_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=4017)), SimpleNamespace()))

    assert get_finding_analysis_context(4017) is None
    assert message.reply_text.call_args.args[0] == "Exited Finding Analysis Mode."


def test_ask_mongrel_still_works_after_finding_analysis_exit() -> None:
    clear_finding_analysis_context(4018)
    clear_ai_waiting(4018)
    set_finding_analysis_context(4018, {"finding_id": "finding-7", "target": "127.0.0.1"})
    asyncio.run(cancel_handler(SimpleNamespace(message=SimpleNamespace(text="Cancel", reply_text=AsyncMock()), effective_user=SimpleNamespace(id=4018)), SimpleNamespace()))
    ask_message = SimpleNamespace(reply_text=AsyncMock())

    asyncio.run(ask_handler(SimpleNamespace(message=ask_message, effective_user=SimpleNamespace(id=4018)), SimpleNamespace()))

    assert get_finding_analysis_context(4018) is None
    assert is_ai_waiting(4018) is True
    assert ask_message.reply_text.call_args.args[0] == "Ask Mongrel anything. Cybersecurity is my specialty."


def test_finding_analysis_ai_failure_keeps_mode_active() -> None:
    clear_finding_analysis_context(4019)
    set_finding_analysis_context(
        4019,
        build_finding_analysis_context(
            {
                "id": "finding-8",
                "source": "nmap",
                "target": "127.0.0.1",
                "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
            }
        ),
    )
    message = SimpleNamespace(text="How serious is this?", reply_text=AsyncMock())

    with patch("app.bot.handlers.scan.ask_ai", side_effect=RuntimeError("boom")):
        asyncio.run(
            scan_target_handler(
                SimpleNamespace(message=message, effective_user=SimpleNamespace(id=4019)),
                SimpleNamespace(user_data={}),
            )
        )

    assert message.reply_text.call_args_list[0].args[0] == "Analyzing..."
    assert message.reply_text.call_args_list[1].args[0] == "AI request failed. Check bot logs."
    assert get_finding_analysis_context(4019) is not None


def test_max_5_findings_shown() -> None:
    findings = [
        {
            "id": f"id-{index}",
            "source": "nmap",
            "target": f"192.168.0.{index}",
            "host_status": "Up",
            "open_ports": [],
            "risk_level": "low",
            "risk_notes": [],
        }
        for index in range(1, 7)
    ]

    findings_text = build_findings_text(findings)
    keyboard = build_findings_keyboard(findings)

    assert "192.168.0.1" not in findings_text
    assert "192.168.0.2" in findings_text
    assert "192.168.0.6" in findings_text
    assert findings_text.count("LOW - nmap") == 5
    assert keyboard is not None
    assert len(keyboard.inline_keyboard) == 6


def test_risk_labels_are_uppercase() -> None:
    findings_text = build_findings_text(
        [
            {
                "id": "risk-id",
                "source": "nmap",
                "target": "127.0.0.1",
                "host_status": "Up",
                "open_ports": [],
                "risk_level": "medium",
                "risk_notes": [],
            }
        ]
    )

    assert "#1 MEDIUM - nmap" in findings_text


def test_pressing_findings_returns_list_view_not_detail_view() -> None:
    clear_user_findings(4001)
    finding = add_finding(
        user_id=4001,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "host_status": "Up",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
            "risk_level": "medium",
            "risk_notes": ["SSH exposed"],
        },
    )
    message = SimpleNamespace(reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=4001))

    asyncio.run(findings_handler(update, SimpleNamespace()))

    reply_text = message.reply_text.call_args.args[0]
    reply_markup = message.reply_text.call_args.kwargs["reply_markup"]
    assert "Latest Findings" in reply_text
    assert "Finding #1" not in reply_text
    assert reply_markup.inline_keyboard[0][0].callback_data == f"finding:view:{finding['id']}"


def test_detail_view_only_opens_from_finding_view_callback() -> None:
    clear_user_findings(4002)
    finding = add_finding(
        user_id=4002,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "host_status": "Up",
            "open_ports": [],
            "risk_level": "low",
            "risk_notes": [],
        },
    )
    query = SimpleNamespace(
        data=f"finding:view:{finding['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=4002))

    asyncio.run(findings_callback_handler(update, SimpleNamespace()))

    detail_text = query.edit_message_text.call_args.args[0]
    assert "Finding #1" in detail_text
    assert "Mongrel Verdict" in detail_text
    assert "Latest Findings" not in detail_text


def test_back_to_findings_callback_returns_list_view() -> None:
    clear_user_findings(4003)
    finding = add_finding(
        user_id=4003,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "host_status": "Up",
            "open_ports": [],
            "risk_level": "low",
            "risk_notes": [],
        },
    )
    query = SimpleNamespace(
        data="finding:list",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=4003))

    asyncio.run(findings_callback_handler(update, SimpleNamespace()))

    list_text = query.edit_message_text.call_args.args[0]
    reply_markup = query.edit_message_text.call_args.kwargs["reply_markup"]
    assert "Latest Findings" in list_text
    assert "Finding #1" not in list_text
    assert reply_markup.inline_keyboard[0][0].callback_data == f"finding:view:{finding['id']}"


def test_clear_findings_callback_works() -> None:
    clear_user_findings(4004)
    add_finding(
        user_id=4004,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "host_status": "Up",
            "open_ports": [],
            "risk_level": "low",
            "risk_notes": [],
        },
    )
    query = SimpleNamespace(
        data="finding:clear",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=4004))

    asyncio.run(findings_callback_handler(update, SimpleNamespace()))

    assert query.edit_message_text.call_args.args[0] == "No findings available yet."
    assert get_user_findings(4004) == []


def test_long_detail_output_safely_truncates() -> None:
    finding = {
        "source": "nmap",
        "target": "127.0.0.1",
        "host_status": "Up",
        "open_ports": [
            {
                "port": str(1000 + index),
                "protocol": "tcp",
                "service": "test",
                "intelligence": {
                    "description": "x" * 200,
                    "common_risk": "y" * 200,
                    "recommendation": "z" * 200,
                },
            }
            for index in range(30)
        ],
        "duration": "0.25s",
        "risk_level": "high",
        "risk_notes": ["Many open ports"],
    }

    detail_text = build_finding_detail_text(finding, display_number=1)

    assert len(detail_text) <= MAX_FINDINGS_MESSAGE_LENGTH + len("\n\n[output truncated]")
    assert "[output truncated]" in detail_text


def test_wrong_file_type_handling() -> None:
    set_upload_state(5001, UPLOAD_STATE_AWAITING_NMAP_XML)
    document = SimpleNamespace(file_name="scan.txt", file_size=100)
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=5001))

    asyncio.run(upload_document_handler(update, SimpleNamespace()))

    assert message.reply_text.call_args.args[0] == "Please upload an Nmap XML or Nuclei JSON/JSONL file."


def test_malformed_xml_upload_handling() -> None:
    set_upload_state(5009, UPLOAD_STATE_AWAITING_NMAP_XML)
    telegram_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray("<nmaprun>", "utf-8")))
    document = SimpleNamespace(file_name="scan.xml", file_size=9, get_file=AsyncMock(return_value=telegram_file))
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=5009))

    asyncio.run(upload_document_handler(update, SimpleNamespace()))

    assert message.reply_text.call_args.args[0] == "Unable to parse Nmap XML file."


def test_json_upload_routes_to_nuclei_parser() -> None:
    clear_user_findings(5020)
    set_upload_state(5020, UPLOAD_STATE_AWAITING_NMAP_XML)
    json_content = '{"template-id":"one","info":{"severity":"low"},"host":"https://example.com"}'
    telegram_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(json_content, "utf-8")))
    document = SimpleNamespace(file_name="nuclei_test.json", file_size=len(json_content), get_file=AsyncMock(return_value=telegram_file))
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=5020))

    with patch(
        "app.bot.handlers.upload.parse_nuclei_results",
        return_value=[{"template_id": "one", "severity": "low", "name": "One", "host": "https://example.com"}],
    ) as parse_nuclei_results:
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    parse_nuclei_results.assert_called_once_with(json_content)
    assert "Nuclei Verdict" in message.reply_text.call_args.args[0]


def test_jsonl_upload_routes_to_nuclei_parser() -> None:
    clear_user_findings(5021)
    set_upload_state(5021, UPLOAD_STATE_AWAITING_NMAP_XML)
    jsonl_content = '{"template-id":"one","info":{"severity":"low"},"host":"https://example.com"}'
    telegram_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(jsonl_content, "utf-8")))
    document = SimpleNamespace(file_name="nuclei_test.jsonl", file_size=len(jsonl_content), get_file=AsyncMock(return_value=telegram_file))
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=5021))

    with patch(
        "app.bot.handlers.upload.parse_nuclei_results",
        return_value=[{"template_id": "one", "severity": "low", "name": "One", "host": "https://example.com"}],
    ) as parse_nuclei_results:
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    parse_nuclei_results.assert_called_once_with(jsonl_content)
    assert "Nuclei Verdict" in message.reply_text.call_args.args[0]


def test_xml_upload_routes_to_nmap_parser() -> None:
    clear_user_findings(5022)
    set_upload_state(5022, UPLOAD_STATE_AWAITING_NMAP_XML)
    xml_content = "<nmaprun><host><status state=\"up\" /><address addr=\"127.0.0.1\" /></host></nmaprun>"
    telegram_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(xml_content, "utf-8")))
    document = SimpleNamespace(file_name="scan.xml", file_size=len(xml_content), get_file=AsyncMock(return_value=telegram_file))
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=5022))

    with patch(
        "app.bot.handlers.upload.parse_nmap_xml",
        return_value={"target": "127.0.0.1", "host_status": "Up", "open_ports": []},
    ) as parse_nmap_xml:
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    parse_nmap_xml.assert_called_once_with(xml_content)
    assert "Mongrel Verdict" in message.reply_text.call_args.args[0]


def test_valid_nuclei_jsonl_upload_creates_finding_and_report() -> None:
    clear_user_findings(5015)
    set_upload_state(5015, UPLOAD_STATE_AWAITING_NMAP_XML)
    jsonl_content = "\n".join(
        [
            '{"template-id":"missing-security-headers","info":{"name":"Missing Security Headers","severity":"low","tags":"http,headers","remediation":"Add recommended headers."},"host":"https://example.com","matched-at":"https://example.com/login"}',
            '{"template-id":"git-config-exposure","info":{"name":"Exposed Git Repository","severity":"high","tags":["exposure","git"]},"host":"https://example.com","matched-at":"https://example.com/.git/config"}',
        ]
    )
    telegram_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(jsonl_content, "utf-8")))
    document = SimpleNamespace(file_name="nuclei.jsonl", file_size=len(jsonl_content), get_file=AsyncMock(return_value=telegram_file))
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=5015))

    asyncio.run(upload_document_handler(update, SimpleNamespace()))

    findings = get_user_findings(5015)
    assert findings[0]["source"] == "nuclei"
    assert findings[0]["target"] == "https://example.com"
    assert findings[0]["risk_level"] == "high"
    assert findings[0]["finding_count"] == 2
    report = message.reply_text.call_args.args[0]
    assert "Nuclei Verdict" in report
    assert "Target:\nhttps://example.com" in report
    assert "Risk Level:\nHIGH" in report
    assert "Findings:\n2" in report
    assert "High: 1" in report
    assert "Low: 1" in report
    assert "- Exposed Git Repository (high)" in report
    assert "- Missing Security Headers (low)" in report
    assert "1. Exposed Git Repository" in report
    assert "Template: git-config-exposure" in report
    assert "Tags: exposure, git" in report
    assert get_upload_state(5015) is None


def test_valid_nuclei_json_upload_routes_to_nuclei_parser() -> None:
    clear_user_findings(5016)
    set_upload_state(5016, UPLOAD_STATE_AWAITING_NMAP_XML)
    json_content = (
        '[{"template-id":"open-redirect","info":{"name":"Open Redirect","severity":"medium"},'
        '"host":"https://example.com","matched-at":"https://example.com/redirect"}]'
    )
    telegram_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(json_content, "utf-8")))
    document = SimpleNamespace(file_name="nuclei.json", file_size=len(json_content), get_file=AsyncMock(return_value=telegram_file))
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=5016))

    asyncio.run(upload_document_handler(update, SimpleNamespace()))

    latest = get_user_findings(5016)[0]
    assert latest["source"] == "nuclei"
    assert latest["risk_level"] == "medium"
    assert "Nuclei Verdict" in message.reply_text.call_args.args[0]
    assert "Medium: 1" in message.reply_text.call_args.args[0]


def test_nuclei_report_severity_aggregation_risk_scoring_and_ordering() -> None:
    finding = store_nuclei_finding(
        5017,
        [
            {"template_id": "low-one", "severity": "low", "name": "Low Finding", "host": "https://example.com", "tags": []},
            {"template_id": "medium-one", "severity": "medium", "name": "Medium Finding", "host": "https://example.com", "tags": []},
            {"template_id": "critical-one", "severity": "critical", "name": "Critical Finding", "host": "https://example.com", "tags": []},
            {"template_id": "high-one", "severity": "high", "name": "High Finding", "host": "https://example.com", "tags": []},
        ],
    )

    report = build_nuclei_import_success_text(finding)

    assert "Risk Level:\nHIGH" in report
    assert "Critical: 1" in report
    assert "High: 1" in report
    assert "Medium: 1" in report
    assert "Low: 1" in report
    assert report.index("- Critical Finding (critical)") < report.index("- High Finding (high)")
    assert report.index("- High Finding (high)") < report.index("- Medium Finding (medium)")
    assert report.index("- Medium Finding (medium)") < report.index("- Low Finding (low)")


def test_nuclei_medium_only_scores_medium() -> None:
    finding = store_nuclei_finding(
        5018,
        [{"template_id": "medium-one", "severity": "medium", "name": "Medium Finding", "host": "https://example.com"}],
    )

    assert finding["risk_level"] == "medium"
    assert "Risk Level:\nMEDIUM" in build_nuclei_import_success_text(finding)


def test_malformed_nuclei_upload_handling() -> None:
    set_upload_state(5019, UPLOAD_STATE_AWAITING_NMAP_XML)
    telegram_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray("{bad-json", "utf-8")))
    document = SimpleNamespace(file_name="nuclei.json", file_size=9, get_file=AsyncMock(return_value=telegram_file))
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=5019))

    asyncio.run(upload_document_handler(update, SimpleNamespace()))

    assert message.reply_text.call_args.args[0] == "Unable to parse Nuclei results file."


def test_uploaded_scan_creates_finding() -> None:
    clear_user_findings(5002)
    clear_latest_upload_scan_summary(5002)
    set_upload_state(5002, UPLOAD_STATE_AWAITING_NMAP_XML)
    xml_content = (
        "<nmaprun>"
        "<host>"
        "<status state=\"up\" />"
        "<address addr=\"192.168.0.24\" />"
        "<ports>"
        "<port protocol=\"tcp\" portid=\"22\"><state state=\"open\" /><service name=\"ssh\" /></port>"
        "</ports>"
        "</host>"
        "<runstats><finished elapsed=\"0.25\" /></runstats>"
        "</nmaprun>"
    )
    telegram_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(xml_content, "utf-8")))
    document = SimpleNamespace(file_name="scan.xml", file_size=len(xml_content), get_file=AsyncMock(return_value=telegram_file))
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=5002))

    asyncio.run(upload_document_handler(update, SimpleNamespace()))

    findings = get_user_findings(5002)
    assert len(findings) == 1
    assert findings[0]["source"] == "nmap_xml"
    assert findings[0]["target"] == "192.168.0.24"
    assert findings[0]["risk_level"] == "medium"
    assert findings[0]["risk_notes"] == ["SSH exposed"]
    assert findings[0]["comparison"]["has_previous"] is False
    assert findings[0]["impact"]["impact_level"] == "low"
    assert get_upload_state(5002) is None
    success_text = message.reply_text.call_args.args[0]
    reply_markup = message.reply_text.call_args.kwargs["reply_markup"]
    assert "Mongrel Verdict" in success_text
    assert "Target:\n192.168.0.24" in success_text
    assert "Open Services:\n- 22/tcp ssh" in success_text
    assert "Risk Level:\nMEDIUM" in success_text
    assert "Summary:\n192.168.0.24 has 1 open port(s) and is currently assessed as medium risk." in success_text
    assert "Key Findings:\n- SSH remote administration service exposed." in success_text
    assert "Recommended Actions:" in success_text
    assert "- Restrict SSH access to trusted networks." in success_text
    assert "Comparison:" in success_text
    assert "No previous scan found for this target." in success_text
    assert "This scan has been stored as the baseline for future comparisons." in success_text
    assert "Impact Assessment:" in success_text
    assert "Change Impact: N/A" in success_text
    assert "No historical comparison available." in success_text
    assert "Technical Details:" in success_text
    assert "1. 22/tcp ssh" in success_text
    assert "Purpose: Secure Shell remote administration service." in success_text
    assert reply_markup.inline_keyboard[0][0].text == "Open Findings"
    assert reply_markup.inline_keyboard[0][0].callback_data == "finding:list"
    assert reply_markup.inline_keyboard[1][0].text == "Explain with Mongrel AI"
    assert reply_markup.inline_keyboard[1][0].callback_data == UPLOAD_EXPLAIN_CALLBACK
    assert get_latest_upload_scan_summary(5002)["target"] == "192.168.0.24"


def test_verdict_generated_from_uploaded_scan() -> None:
    finding = {
        "source": "nmap_xml",
        "target": "192.168.0.24",
        "risk_level": "medium",
        "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
    }

    verdict = generate_mongrel_verdict(finding)

    assert "SSH remote administration service exposed." in verdict["key_findings"]
    assert "Restrict SSH access to trusted networks." in verdict["recommended_actions"]


def test_upload_success_includes_risk_level() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "192.168.0.24",
            "risk_level": "high",
            "open_ports": [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}],
        }
    )

    assert "Risk Level:\nHIGH" in success_text


def test_upload_success_includes_key_findings() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "192.168.0.24",
            "risk_level": "high",
            "open_ports": [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}],
        }
    )

    assert "Key Findings:" in success_text
    assert "- Windows SMB file sharing service exposed." in success_text


def test_upload_success_includes_ports_services_and_recommendations() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "scanme.nmap.org",
            "risk_level": "medium",
            "open_ports": [
                {
                    "port": "22",
                    "protocol": "tcp",
                    "service": "ssh",
                    "intelligence": {"name": "SSH", "recommendation": "Confirm SSH is restricted to authorized users."},
                },
                {
                    "port": "80",
                    "protocol": "tcp",
                    "service": "http",
                    "intelligence": {"name": "HTTP", "recommendation": "Review HTTP service for outdated software or exposed admin paths."},
                },
            ],
        }
    )

    assert "Target:\nscanme.nmap.org" in success_text
    assert "- 22/tcp ssh" in success_text
    assert "- 80/tcp http" in success_text
    assert "Risk Level:\nMEDIUM" in success_text
    assert "- SSH remote administration service exposed." in success_text
    assert "- HTTP service is reachable." in success_text
    assert "- Confirm SSH is restricted to authorized users." in success_text
    assert "- Review HTTP service for outdated software or exposed admin paths." in success_text


def test_upload_success_collapses_repeated_http_findings_and_actions() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "192.168.0.24",
            "risk_level": "low",
            "open_ports": [
                {
                    "port": "80",
                    "protocol": "tcp",
                    "service": "http",
                    "intelligence": {
                        "name": "HTTP",
                        "description": "Web service.",
                        "common_risk": "Exposed web surface.",
                        "recommendation": "Review HTTP service for outdated software or exposed admin paths.",
                    },
                },
                {
                    "port": "5357",
                    "protocol": "tcp",
                    "service": "http",
                    "intelligence": {
                        "name": "HTTP",
                        "description": "Web service.",
                        "common_risk": "Exposed web surface.",
                        "recommendation": "Review HTTP service for outdated software or exposed admin paths.",
                    },
                },
            ],
        }
    )

    key_findings = success_text.split("Key Findings:\n", 1)[1].split("\n\nRecommended Actions:", 1)[0]
    actions = success_text.split("Recommended Actions:\n", 1)[1].split("\n\nComparison:", 1)[0]
    assert key_findings.count("- HTTP services are reachable on multiple ports.") == 1
    assert "- HTTP service is reachable." not in key_findings
    assert actions.count("- Review exposed HTTP services and redirect to HTTPS where appropriate.") == 1
    assert "1. 80/tcp http" in success_text
    assert "2. 5357/tcp http" in success_text


def test_upload_success_prefers_stronger_smb_finding() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "192.168.0.24",
            "risk_level": "high",
            "open_ports": [
                {
                    "port": "445",
                    "protocol": "tcp",
                    "service": "microsoft-ds",
                    "intelligence": {"name": "SMB"},
                }
            ],
        }
    )

    key_findings = success_text.split("Key Findings:\n", 1)[1].split("\n\nRecommended Actions:", 1)[0]
    assert "- Windows SMB file sharing service exposed." in key_findings
    assert "- Microsoft-DS / SMB service is reachable." not in key_findings


def test_upload_success_deduplicates_exact_recommended_actions() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "192.168.0.24",
            "risk_level": "low",
            "open_ports": [
                {
                    "port": "1234",
                    "protocol": "tcp",
                    "service": "alpha",
                    "intelligence": {"name": "ALPHA", "recommendation": "Review shared exposure."},
                },
                {
                    "port": "1235",
                    "protocol": "tcp",
                    "service": "beta",
                    "intelligence": {"name": "BETA", "recommendation": "Review shared exposure."},
                },
            ],
        }
    )

    actions = success_text.split("Recommended Actions:\n", 1)[1].split("\n\nComparison:", 1)[0]
    assert actions.count("- Review shared exposure.") == 1
    assert "1. 1234/tcp alpha" in success_text
    assert "2. 1235/tcp beta" in success_text


def test_upload_success_limits_open_services_to_first_10() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "192.168.0.24",
            "risk_level": "medium",
            "open_ports": [
                {"port": str(1000 + index), "protocol": "tcp", "service": f"service-{index}"}
                for index in range(11)
            ],
        }
    )

    assert "- 1000/tcp service-0" in success_text
    assert "- 1009/tcp service-9" in success_text
    assert "- 1010/tcp service-10" not in success_text
    assert "...and 1 more services." in success_text


def test_upload_success_includes_service_version_when_available() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "scanme.nmap.org",
            "risk_level": "low",
            "open_ports": [
                {
                    "port": "80",
                    "protocol": "tcp",
                    "service": "http",
                    "version": "Apache httpd 2.4.58",
                    "intelligence": {"name": "HTTP"},
                },
            ],
        }
    )

    assert "- 80/tcp http (Apache httpd 2.4.58)" in success_text


def test_upload_success_technical_details_use_manual_review_fallbacks() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "192.168.0.24",
            "risk_level": "low",
            "open_ports": [
                {
                    "port": "135",
                    "protocol": "tcp",
                    "service": "msrpc",
                    "intelligence": {
                        "description": "Description unavailable.",
                        "common_risk": "Description unavailable.",
                        "recommendation": "Manual review recommended.",
                    },
                },
            ],
        }
    )

    assert "Technical Details:" in success_text
    assert "1. 135/tcp msrpc" in success_text
    assert "Purpose: Manual review required." in success_text
    assert "Risk: Manual review required." in success_text
    assert "Recommendation: Manual review recommended." in success_text
    assert "Description unavailable" not in success_text


def test_upload_success_includes_open_findings_button() -> None:
    keyboard = build_upload_success_keyboard()

    assert keyboard.inline_keyboard[0][0].text == "Open Findings"
    assert keyboard.inline_keyboard[0][0].callback_data == "finding:list"


def test_upload_success_includes_explain_with_mongrel_ai_button() -> None:
    keyboard = build_upload_success_keyboard()

    assert keyboard.inline_keyboard[1][0].text == "Explain with Mongrel AI"
    assert keyboard.inline_keyboard[1][0].callback_data == UPLOAD_EXPLAIN_CALLBACK


def test_upload_ai_prompt_contains_scan_summary_and_guardrails() -> None:
    summary = store_latest_upload_scan_summary(
        5010,
        {
            "target": "192.168.0.24",
            "risk_level": "high",
            "open_ports": [
                {
                    "port": "445",
                    "protocol": "tcp",
                    "service": "microsoft-ds",
                    "intelligence": {"name": "SMB", "recommendation": "Restrict or disable SMB if not required."},
                },
                {
                    "port": "5357",
                    "protocol": "tcp",
                    "service": "wsdapi",
                    "intelligence": {"name": "WSDAPI", "recommendation": "Review service exposure."},
                },
            ],
            "comparison": {"has_previous": False, "summary": "No previous scan found for this target."},
            "impact": {"impact_level": "low", "summary": "No material exposure changes detected."},
        },
    )

    prompt = build_upload_ai_prompt(summary)

    assert "Target: 192.168.0.24" in prompt
    assert "Risk level: HIGH" in prompt
    assert "Open Services:\n445/tcp microsoft-ds\n5357/tcp wsdapi" in prompt
    assert "- Windows SMB file sharing service exposed." in prompt
    assert "- WSDAPI service is reachable." in prompt
    assert "- Restrict or disable SMB if not required." in prompt
    assert "No previous scan found for this target." in prompt
    assert "Accuracy is more important than completeness." in prompt
    assert "- Use only the supplied findings." in prompt
    assert "- Do not invent services." in prompt
    assert "- Do not invent ports." in prompt
    assert "- Do not invent CVEs." in prompt
    assert "- Do not merge services together." in prompt
    assert "- Do not reassign services to different ports." in prompt
    assert "- Assume the user has already read the deterministic report." in prompt
    assert "- Do not repeat Scan Summary." in prompt
    assert "- The exact port list has already been shown to the user. Do not repeat it." in prompt
    assert "- Do not repeat Open Services." in prompt
    assert "- Do not repeat Risk Level." in prompt
    assert "- Do not restate the Open Services list." in prompt
    assert "- Do not produce service-on-port mapping lines." in prompt
    assert "- Refer to exact ports only when quoting directly from the supplied Open Services list." in prompt
    assert "- If uncertain, state uncertainty rather than guessing." in prompt
    assert (
        "- Use only these four section titles: What this means, Highest priority risks, What to check first, Suggested next steps."
    ) in prompt
    assert "- Do not create sections titled Scan Summary, Open Services, or Risk Level." in prompt
    assert "- Use a maximum of 8 bullet points total." in prompt
    assert "What this means:\n- Explain the overall exposure in plain English without restating every port." in prompt
    assert (
        "Highest priority risks:\n"
        "- Focus on SSH, SMB, remote administration, file sharing, and exposed web/management surfaces if present in supplied findings."
    ) in prompt


def test_upload_explain_button_uses_latest_parsed_scan_summary() -> None:
    clear_latest_upload_scan_summary(5011)
    store_latest_upload_scan_summary(
        5011,
        {
            "target": "scanme.nmap.org",
            "risk_level": "medium",
            "open_ports": [
                {
                    "port": "80",
                    "protocol": "tcp",
                    "service": "http",
                    "intelligence": {"name": "HTTP", "recommendation": "Review exposed HTTP service."},
                }
            ],
        },
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=UPLOAD_EXPLAIN_CALLBACK,
        answer=AsyncMock(),
        message=query_message,
        edit_message_text=AsyncMock(),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5011))

    with patch("app.bot.handlers.upload.ask_ai", return_value="Plain English explanation.") as ask_ai:
        asyncio.run(upload_callback_handler(update, SimpleNamespace()))

    prompt = ask_ai.call_args.args[0]
    assert "Target: scanme.nmap.org" in prompt
    assert "Open Services:\n80/tcp http" in prompt
    assert "Review exposed HTTP service." in prompt
    assert query_message.reply_text.call_args_list[0].args[0] == "Mongrel is analyzing the findings..."
    assert query_message.reply_text.call_args_list[1].args[0] == "Plain English explanation."


def test_upload_explain_button_handles_no_latest_scan() -> None:
    clear_latest_upload_scan_summary(5012)
    query = SimpleNamespace(
        data=UPLOAD_EXPLAIN_CALLBACK,
        answer=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
        edit_message_text=AsyncMock(),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5012))

    asyncio.run(upload_callback_handler(update, SimpleNamespace()))

    query.edit_message_text.assert_called_once_with("Upload an Nmap XML file first.")


def test_upload_explain_button_returns_ai_disabled_fallback() -> None:
    clear_latest_upload_scan_summary(5013)
    store_latest_upload_scan_summary(5013, {"target": "127.0.0.1", "risk_level": "low", "open_ports": []})
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=UPLOAD_EXPLAIN_CALLBACK,
        answer=AsyncMock(),
        message=query_message,
        edit_message_text=AsyncMock(),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5013))

    with patch("app.bot.handlers.upload.ask_ai", return_value="AI integration is not configured yet."):
        asyncio.run(upload_callback_handler(update, SimpleNamespace()))

    assert query_message.reply_text.call_args_list[1].args[0] == "AI integration is not configured yet."


def test_upload_explain_button_handles_ai_failure() -> None:
    clear_latest_upload_scan_summary(5014)
    store_latest_upload_scan_summary(5014, {"target": "127.0.0.1", "risk_level": "low", "open_ports": []})
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=UPLOAD_EXPLAIN_CALLBACK,
        answer=AsyncMock(),
        message=query_message,
        edit_message_text=AsyncMock(),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5014))

    with patch("app.bot.handlers.upload.ask_ai", side_effect=RuntimeError("boom")):
        asyncio.run(upload_callback_handler(update, SimpleNamespace()))

    assert query_message.reply_text.call_args_list[0].args[0] == "Mongrel is analyzing the findings..."
    assert query_message.reply_text.call_args_list[1].args[0] == "AI explanation failed. Check bot logs."


def test_upload_success_no_findings_fallback_message() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "192.168.0.24",
            "risk_level": "low",
            "open_ports": [],
        }
    )

    assert "- No significant findings identified." in success_text
    assert "- No immediate action required." in success_text


def test_live_scan_finding_stores_comparison() -> None:
    clear_user_findings(6001)
    first = store_successful_nmap_finding(
        user_id=6001,
        result={
            "success": True,
            "target": "127.0.0.1",
            "output": "Nmap scan report for 127.0.0.1\nHost is up.\n22/tcp open ssh\n",
            "error": "",
        },
    )
    second = store_successful_nmap_finding(
        user_id=6001,
        result={
            "success": True,
            "target": "127.0.0.1",
            "output": "Nmap scan report for 127.0.0.1\nHost is up.\n22/tcp open ssh\n3389/tcp open rdp\n",
            "error": "",
        },
    )

    assert first is not None
    assert second is not None
    assert second["comparison"]["has_previous"] is True
    assert second["comparison"]["new_ports"] == [{"port": "3389", "protocol": "tcp", "service": "rdp", "intelligence": second["open_ports"][1]["intelligence"]}]
    assert second["impact"]["impact_level"] == "high"
    assert "Remote Desktop became exposed." in second["impact"]["impacts"]


def test_live_scan_comparison_matches_normalized_target_key() -> None:
    clear_user_findings(6003)
    first = store_successful_nmap_finding(
        user_id=6003,
        result={
            "success": True,
            "target": "127.0.0.1",
            "output": "Nmap scan report for localhost (127.0.0.1)\nHost is up.\n22/tcp open ssh\n",
            "error": "",
        },
    )
    second = store_successful_nmap_finding(
        user_id=6003,
        result={
            "success": True,
            "target": "127.0.0.1",
            "output": "Nmap scan report for 127.0.0.1\nHost is up.\n22/tcp open ssh\n",
            "error": "",
        },
    )

    assert first is not None
    assert second is not None
    assert second["comparison"]["has_previous"] is True


def test_nmap_comparison_ignores_intervening_clean_nuclei_scan() -> None:
    clear_user_findings(6004)
    first = store_successful_nmap_finding(
        user_id=6004,
        result={
            "success": True,
            "target": "127.0.0.1",
            "output": "Nmap scan report for 127.0.0.1\nHost is up.\n22/tcp open ssh\n445/tcp open microsoft-ds\n",
            "error": "",
        },
    )
    add_finding(
        user_id=6004,
        finding={
            "source": "nuclei",
            "target": "localhost (127.0.0.1)",
            "risk_level": "info",
            "finding_count": 0,
            "status": "clean",
        },
    )
    second = store_successful_nmap_finding(
        user_id=6004,
        result={
            "success": True,
            "target": "localhost (127.0.0.1)",
            "output": "Nmap scan report for localhost (127.0.0.1)\nHost is up.\n22/tcp open ssh\n445/tcp open microsoft-ds\n",
            "error": "",
        },
    )

    assert first is not None
    assert second is not None
    assert second["comparison"]["has_previous"] is True
    assert second["comparison"]["risk_changed"] is False
    assert second["comparison"]["previous_risk"] == "high"
    assert second["comparison"]["current_risk"] == "high"
    assert second["comparison"]["new_ports"] == []
    assert len(second["comparison"]["unchanged_ports"]) == 2


def test_xml_upload_finding_stores_comparison() -> None:
    clear_user_findings(6002)
    add_finding(
        user_id=6002,
        finding={
            "source": "nmap",
            "target": "192.168.0.24",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )
    set_upload_state(6002, UPLOAD_STATE_AWAITING_NMAP_XML)
    xml_content = (
        "<nmaprun><host><status state=\"up\" /><address addr=\"192.168.0.24\" />"
        "<ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\" /><service name=\"ssh\" /></port>"
        "<port protocol=\"tcp\" portid=\"445\"><state state=\"open\" /><service name=\"microsoft-ds\" /></port>"
        "</ports></host></nmaprun>"
    )
    telegram_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(xml_content, "utf-8")))
    document = SimpleNamespace(file_name="scan.xml", file_size=len(xml_content), get_file=AsyncMock(return_value=telegram_file))
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=6002))

    asyncio.run(upload_document_handler(update, SimpleNamespace()))

    latest = get_user_findings(6002)[-1]
    assert latest["source"] == "nmap_xml"
    assert latest["comparison"]["has_previous"] is True
    assert latest["comparison"]["new_ports"][0]["port"] == "445"
    assert "Comparison" in message.reply_text.call_args.args[0]


def test_comparison_unchanged_ports_render_as_count() -> None:
    detail_text = build_finding_detail_text(
        {
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [],
            "comparison": {
                "has_previous": True,
                "new_ports": [],
                "removed_ports": [],
                "unchanged_ports": [
                    {"port": "22", "protocol": "tcp", "service": "ssh"},
                    {"port": "445", "protocol": "tcp", "service": "microsoft-ds"},
                ],
                "risk_changed": False,
                "previous_risk": "medium",
                "current_risk": "medium",
                "summary": "No material changes detected.",
            },
        }
    )

    assert "Unchanged Ports: 2" in detail_text
    assert "Unchanged Ports: 22/tcp ssh" not in detail_text


def test_comparison_new_ports_still_list_details() -> None:
    detail_text = build_finding_detail_text(
        {
            "target": "127.0.0.1",
            "risk_level": "high",
            "open_ports": [],
            "comparison": {
                "has_previous": True,
                "new_ports": [{"port": "3389", "protocol": "tcp", "service": "rdp"}],
                "removed_ports": [],
                "unchanged_ports": [],
                "risk_changed": True,
                "previous_risk": "medium",
                "current_risk": "high",
                "summary": "1 new port(s), risk changed from medium to high",
            },
        }
    )

    assert "New Ports: 3389/tcp rdp" in detail_text


def test_comparison_removed_ports_still_list_details() -> None:
    detail_text = build_finding_detail_text(
        {
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [],
            "comparison": {
                "has_previous": True,
                "new_ports": [],
                "removed_ports": [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}],
                "unchanged_ports": [],
                "risk_changed": True,
                "previous_risk": "high",
                "current_risk": "medium",
                "summary": "1 removed port(s), risk changed from high to medium",
            },
        }
    )

    assert "Removed Ports: 445/tcp microsoft-ds" in detail_text


def test_comparison_risk_change_still_renders() -> None:
    detail_text = build_finding_detail_text(
        {
            "target": "127.0.0.1",
            "risk_level": "high",
            "open_ports": [],
            "comparison": {
                "has_previous": True,
                "new_ports": [],
                "removed_ports": [],
                "unchanged_ports": [],
                "risk_changed": True,
                "previous_risk": "medium",
                "current_risk": "high",
                "summary": "risk changed from medium to high",
            },
        }
    )

    assert "Risk Change: MEDIUM -> HIGH" in detail_text


def test_no_material_changes_section_is_clean() -> None:
    detail_text = build_finding_detail_text(
        {
            "target": "127.0.0.1",
            "risk_level": "low",
            "open_ports": [],
            "comparison": {
                "has_previous": True,
                "new_ports": [],
                "removed_ports": [],
                "unchanged_ports": [],
                "risk_changed": False,
                "previous_risk": "low",
                "current_risk": "low",
                "summary": "No material changes detected.",
            },
        }
    )

    assert "No material changes detected." in detail_text
    assert "New Ports: none" in detail_text
    assert "Removed Ports: none" in detail_text
    assert "Risk Change: none" in detail_text
    assert "Unchanged Ports: 0" in detail_text


def test_no_change_impact_section_has_reason_without_empty_lists() -> None:
    detail_text = build_finding_detail_text(
        {
            "target": "127.0.0.1",
            "risk_level": "low",
            "open_ports": [],
            "impact": {
                "impact_level": "low",
                "summary": "No material exposure changes detected.",
                "impacts": [],
                "recommendations": [],
            },
        }
    )

    assert "Change Impact: LOW" in detail_text
    assert "Reason:" in detail_text
    assert "No new services appeared and no risky services were removed since the previous scan." in detail_text
    assert "Impacts:\n- None" not in detail_text
    assert "Recommendations:\n- None" not in detail_text


def test_first_scan_comparison_rendering_uses_baseline_message() -> None:
    detail_text = build_finding_detail_text(
        {
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
            "comparison": {
                "has_previous": False,
                "new_ports": [],
                "removed_ports": [],
                "unchanged_ports": [],
                "risk_changed": False,
                "previous_risk": None,
                "current_risk": "medium",
                "summary": "No previous scan found for this target.",
            },
            "impact": {
                "impact_level": "low",
                "summary": "No material exposure changes detected.",
                "impacts": [],
                "recommendations": [],
            },
        }
    )

    assert "Comparison" in detail_text
    assert "No previous scan found for this target." in detail_text
    assert "This scan has been stored as the baseline for future comparisons." in detail_text


def test_first_scan_impact_rendering_is_not_applicable() -> None:
    detail_text = build_finding_detail_text(
        {
            "target": "127.0.0.1",
            "risk_level": "low",
            "open_ports": [],
            "comparison": {
                "has_previous": False,
                "new_ports": [],
                "removed_ports": [],
                "unchanged_ports": [],
                "risk_changed": False,
                "previous_risk": None,
                "current_risk": "low",
                "summary": "No previous scan found for this target.",
            },
            "impact": {
                "impact_level": "low",
                "summary": "No material exposure changes detected.",
                "impacts": [],
                "recommendations": [],
            },
        }
    )

    assert "Impact Assessment" in detail_text
    assert "Change Impact: N/A" in detail_text
    assert "Summary:\nNo historical comparison available." in detail_text
    assert "Reason:\nThis is the first recorded scan for this target." in detail_text
    assert "Impacts:" not in detail_text
    assert "Recommendations:" not in detail_text


def test_first_scan_response_does_not_show_port_delta_counts() -> None:
    response_text = append_change_summary(
        "Target: 127.0.0.1",
        {
            "has_previous": False,
            "new_ports": [],
            "removed_ports": [],
            "unchanged_ports": [],
            "risk_changed": False,
            "previous_risk": None,
            "current_risk": "medium",
            "summary": "No previous scan found for this target.",
        },
        {
            "impact_level": "low",
            "summary": "No material exposure changes detected.",
            "impacts": [],
            "recommendations": [],
        },
    )

    assert "This scan has been stored as the baseline for future comparisons." in response_text
    assert "New Ports:" not in response_text
    assert "Removed Ports:" not in response_text
    assert "Risk Change:" not in response_text
    assert "Unchanged Ports:" not in response_text


def test_existing_comparison_response_behavior_is_unchanged() -> None:
    response_text = append_change_summary(
        "Target: 127.0.0.1",
        {
            "has_previous": True,
            "new_ports": [{"port": "3389", "protocol": "tcp", "service": "rdp"}],
            "removed_ports": [],
            "unchanged_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
            "risk_changed": True,
            "previous_risk": "medium",
            "current_risk": "high",
            "summary": "1 new port(s), risk changed from medium to high",
        },
        {
            "impact_level": "high",
            "summary": "High-impact exposure change detected.",
            "impacts": ["Remote Desktop became exposed."],
            "recommendations": ["Restrict RDP and require strong authentication."],
        },
    )

    assert "New Ports: 3389/tcp rdp" in response_text
    assert "Removed Ports: none" in response_text
    assert "Risk Change: MEDIUM -> HIGH" in response_text
    assert "Unchanged Ports: 1" in response_text
    assert "Impact\nHigh-impact exposure change detected." in response_text
