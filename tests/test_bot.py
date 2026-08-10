import asyncio
import json
import re
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from telegram.error import BadRequest
from telegram.error import TimedOut

from app.bot.auth import is_admin
from app.bot.bot import SCAN_CALLBACK_PATTERN
from app.bot.handlers.ask import ask_handler, build_ask_text, cancel_handler
from app.bot.handlers.assessment import (
    ASSESSMENT_CHAT_STATE_KEY,
    ASSESSMENT_FLOW_STATE_KEY,
    ASSESSMENT_SCAN_CONTEXT_KEY,
    ACTIVE_ASSESSMENT_ID_KEY,
    assessment_callback_handler,
    build_assessment_chat_intro,
    build_assessment_dashboard_keyboard,
    build_assessment_dashboard_text,
    build_assessment_history_text,
    build_new_assessment_name_prompt,
    new_assessment_handler,
)
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
    _metasploit_pending_context,
    _send_metasploit_ai_assessment,
    _update_nuclei_status_card,
    append_change_summary,
    build_bbot_ai_assessment_keyboard,
    build_bbot_result_text,
    build_bbot_target_prompt,
    build_ffuf_result_text,
    build_ffuf_target_prompt,
    build_gitleaks_target_prompt,
    build_httpx_result_text,
    build_httpx_target_prompt,
    build_katana_result_text,
    build_katana_target_prompt,
    build_metasploit_mode_text,
    build_metasploit_request_prompt,
    build_metasploit_readiness_failure_text,
    build_metasploit_result_text,
    build_playwright_result_text,
    build_playwright_target_prompt,
    build_prowler_provider_prompt,
    build_prowler_result_text,
    build_testssl_target_prompt,
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
    store_ffuf_scan_result,
    store_httpx_scan_result,
    store_katana_scan_result,
    store_playwright_scan_result,
    store_successful_nmap_finding,
)
from app.bot.handlers.settings import build_settings_text
from app.bot.handlers.start import build_start_text
from app.bot.handlers.upload import build_upload_text
from app.bot.handlers.upload import (
    UPLOAD_STATE_AWAITING_NMAP_XML,
    UPLOAD_EXPLAIN_CALLBACK,
    UPLOAD_STATE_AWAITING_TSHARK_PCAP,
    build_tshark_mode_text,
    build_tshark_result_text,
    build_tshark_upload_prompt,
    build_upload_ai_prompt,
    build_nmap_xml_import_success_text,
    build_nuclei_import_success_text,
    build_upload_success_keyboard,
    clear_latest_upload_scan_summary,
    clear_upload_state,
    get_latest_upload_scan_summary,
    get_tshark_assessment_upload_context,
    get_upload_state,
    set_upload_state,
    store_nuclei_finding,
    store_latest_upload_scan_summary,
    tshark_callback_handler,
    upload_callback_handler,
    upload_document_handler,
)
from app.bot.keyboards import MAIN_MENU_BUTTONS, build_main_menu_keyboard, build_scan_type_keyboard
from app.bot.progress import build_spinner_frames, run_progress_frames, safe_edit_text
from app.core.config import Settings
from app.services.active_scan_state import clear_active_scan, get_active_scan, set_active_scan
from app.services.assessment_context import build_assessment_context
from app.services.assessment_guard import build_assessment_guard
from app.services.assessment_store import (
    add_assessment_target,
    create_assessment,
    record_assessment_scan,
    list_assessment_scans,
    list_assessment_artifacts,
    list_assessment_targets,
    list_assessments,
)
from app.services.bbot_ai_assessment import FALLBACK_LINES
from app.services.nmap_ai_assessment import FALLBACK_LINES as NMAP_AI_FALLBACK_LINES
from app.services.nuclei_ai_assessment import FALLBACK_LINES as NUCLEI_AI_FALLBACK_LINES
from app.tools.bbot_runner import BBOT_RUNTIME_INCOMPATIBLE_ERROR
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
from app.services.metasploit_approval import (
    approve_metasploit_proposal,
    clear_metasploit_proposals,
    get_metasploit_proposal,
    mark_metasploit_proposal_status,
    propose_metasploit_action,
    record_metasploit_result_reference,
)
from app.services.metasploit_policy import build_metasploit_action_request
from app.services.observation_store import add_observation, clear_user_observations, get_investigation_observations, get_user_observations
from app.services.tshark_approval import clear_tshark_capture_proposals, get_tshark_capture_proposal
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
from app.ui.ai_summary import render_ai_summary_card
from app.ui.icons import icon


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
    assert "JavaScript endpoint discovery" in build_katana_target_prompt()
    assert "No clicks, form submissions, credential entry" in build_playwright_target_prompt()
    assert "ffuf discovery request created" in build_ffuf_target_prompt()
    assert "https://example.com/search?q=FUZZ" in build_ffuf_target_prompt()
    assert "Nmap XML" in build_upload_text()
    assert "- Nuclei JSON (supported)" in build_upload_text()
    assert "- Nuclei JSONL (supported)" in build_upload_text()
    assert "Send an Nmap XML or Nuclei results file to begin analysis." in build_upload_text()
    assert build_ask_text() == "Ask Mongrel anything. Cybersecurity is my specialty."
    assert "Reports" in build_reports_text([])
    assert "Send an assessment name." in build_new_assessment_name_prompt()


def test_assessment_dashboard_renders_scan_statuses_and_actions() -> None:
    assessment = create_assessment("Acme External Assessment")
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", elapsed_seconds=9, risk="medium")
    dashboard = build_assessment_dashboard_text(
        assessment,
        [{"address": "example.com"}],
        list_assessment_scans(assessment["id"]),
    )
    keyboard = build_assessment_dashboard_keyboard(assessment["id"])
    rendered_buttons = [button.text for row in keyboard.inline_keyboard for button in row]

    assert "Assessment Dashboard" in dashboard
    assert "Acme External Assessment" in dashboard
    assert "example.com" in dashboard
    assert "Status\nActive" in dashboard
    assert "Last Updated" in dashboard
    assert "Nmap: Completed" in dashboard
    assert "BBOT: Not run" in dashboard
    assert "Nuclei: Not run" in dashboard
    assert "httpx: Not run" in dashboard
    assert "Katana: Not run" in dashboard
    assert "Playwright: Not run" in dashboard
    assert "ffuf: Not run" in dashboard
    assert "testssl.sh: Not run" in dashboard
    assert "Gitleaks: Not run" in dashboard
    assert "Prowler: Not run" in dashboard
    assert "Metasploit: Not run" in dashboard
    assert "TShark: Not run" in dashboard
    assert rendered_buttons == [
        "Run Nmap",
        "Run BBOT",
        "Run Nuclei",
        "Run httpx",
        "Run Katana",
        "Run Playwright",
        "Run ffuf",
        "Run testssl.sh",
        "Run Gitleaks",
        "Run Prowler",
        "Run Metasploit",
        "Run TShark",
        "Ask Mongrel",
        "Generate AI Report",
        "Markdown Report",
        "History",
        "Home",
    ]


def test_assessment_history_renders_empty_and_recorded_scans() -> None:
    empty_assessment = create_assessment("Empty History Assessment")
    assert "No assessment scans recorded yet." in build_assessment_history_text(empty_assessment, [])

    assessment = create_assessment("History Assessment")
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", elapsed_seconds=9, risk="medium")
    record_assessment_scan(assessment["id"], tool="nuclei", status="failed")
    history = build_assessment_history_text(assessment, list_assessment_scans(assessment["id"]))

    assert "Assessment History" in history
    assert "History Assessment" in history
    assert "NMAP - Completed" in history
    assert "Risk: MEDIUM" in history
    assert "Elapsed: 9s" in history
    assert "NUCLEI - Failed" in history


def test_new_assessment_flow_creates_assessment_target_and_dashboard() -> None:
    context = SimpleNamespace(user_data={})
    start_message = SimpleNamespace(text="New Assessment", reply_text=AsyncMock())
    asyncio.run(new_assessment_handler(SimpleNamespace(message=start_message, effective_user=SimpleNamespace(id=8101)), context))

    assert context.user_data[ASSESSMENT_FLOW_STATE_KEY]["stage"] == "awaiting_name"
    assert "Send an assessment name." in start_message.reply_text.call_args.args[0]

    name_message = SimpleNamespace(text="Mission 10.11 Assessment", reply_text=AsyncMock())
    asyncio.run(scan_target_handler(SimpleNamespace(message=name_message, effective_user=SimpleNamespace(id=8101)), context))

    assert context.user_data[ASSESSMENT_FLOW_STATE_KEY]["stage"] == "awaiting_target"
    assert context.user_data[ASSESSMENT_FLOW_STATE_KEY]["name"] == "Mission 10.11 Assessment"
    assert "Primary Target" in name_message.reply_text.call_args.args[0]

    target_message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    asyncio.run(scan_target_handler(SimpleNamespace(message=target_message, effective_user=SimpleNamespace(id=8101)), context))

    assert ASSESSMENT_FLOW_STATE_KEY not in context.user_data
    dashboard = target_message.reply_text.call_args.args[0]
    keyboard = target_message.reply_text.call_args.kwargs["reply_markup"]
    assert "Assessment Dashboard" in dashboard
    assert "Mission 10.11 Assessment" in dashboard
    assert "example.com" in dashboard
    assert "Nmap: Not run" in dashboard
    assert keyboard.inline_keyboard[0][0].text == "Run Nmap"

    assessment = list_assessments()[-1]
    assert assessment["name"] == "Mission 10.11 Assessment"
    assert list_assessment_targets(assessment["id"])[0]["address"] == "example.com"


def test_assessment_nmap_button_records_assessment_scan() -> None:
    clear_user_findings(8120)
    clear_user_investigations(8120)
    assessment = create_assessment("Assessment Nmap")
    target = add_assessment_target(assessment["id"], address="127.0.0.1")
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:run:nmap:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )

    with (
        patch(
            "app.bot.handlers.scan.run_nmap_scan",
            return_value={
                "success": True,
                "target": "127.0.0.1",
                "output": "Nmap scan report for 127.0.0.1\nHost is up.\n22/tcp open ssh\n",
                "error": "",
            },
        ),
        patch("app.bot.handlers.scan.generate_nmap_ai_assessment", return_value=NMAP_AI_FALLBACK_LINES),
    ):
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8120)),
                SimpleNamespace(user_data={}),
            )
        )

    query.answer.assert_called_once()
    scans = list_assessment_scans(assessment["id"])
    assert len(scans) == 1
    assert scans[0]["tool"] == "nmap"
    assert scans[0]["status"] == "completed"
    assert scans[0]["target_id"] == target["id"]
    assert scans[0]["finding_id"]
    assert "Nmap: Completed" in query_message.reply_text.call_args_list[-1].args[0]


def test_assessment_bbot_button_records_assessment_scan() -> None:
    clear_user_findings(8121)
    clear_user_investigations(8121)
    clear_user_observations(8121)
    assessment = create_assessment("Assessment BBOT")
    target = add_assessment_target(assessment["id"], address="example.com")
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:run:bbot:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )

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
                "elapsed_seconds": 4.2,
            },
        ),
    ):
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8121)),
                SimpleNamespace(user_data={}),
            )
        )

    scans = list_assessment_scans(assessment["id"])
    assert len(scans) == 1
    assert scans[0]["tool"] == "bbot"
    assert scans[0]["status"] == "completed"
    assert scans[0]["target_id"] == target["id"]
    assert scans[0]["elapsed_seconds"] == 4
    assert "BBOT: Completed" in query_message.reply_text.call_args_list[-1].args[0]


def test_assessment_nuclei_button_records_assessment_scan() -> None:
    clear_user_findings(8122)
    clear_user_investigations(8122)
    clear_active_scan(8122)
    assessment = create_assessment("Assessment Nuclei")
    target = add_assessment_target(assessment["id"], address="https://example.com")
    status_message = SimpleNamespace(edit_text=AsyncMock())
    query_message = SimpleNamespace(reply_text=AsyncMock(return_value=status_message))
    query = SimpleNamespace(
        data=f"assessment:run:nuclei:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )

    async def run_flow() -> None:
        with (
            patch(
                "app.bot.handlers.scan.run_nuclei_scan",
                return_value={"success": True, "target": "https://example.com", "output": "", "error": "", "returncode": 0},
            ),
            patch("app.bot.handlers.scan.generate_nuclei_ai_assessment", return_value=NUCLEI_AI_FALLBACK_LINES),
        ):
            await assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8122)),
                SimpleNamespace(user_data={}),
            )
            active_scan = get_active_scan(8122)
            assert active_scan is not None
            assert active_scan.task is not None
            await active_scan.task

    asyncio.run(run_flow())
    scans = list_assessment_scans(assessment["id"])
    assert len(scans) == 1
    assert scans[0]["tool"] == "nuclei"
    assert scans[0]["status"] == "completed"
    assert scans[0]["target_id"] == target["id"]
    assert scans[0]["finding_id"]
    assert "Nuclei: Completed" in query_message.reply_text.call_args_list[-1].args[0]


def test_assessment_failed_scan_records_failed_status() -> None:
    clear_user_findings(8123)
    clear_user_investigations(8123)
    assessment = create_assessment("Assessment Failed Nmap")
    add_assessment_target(assessment["id"], address="127.0.0.1")
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:run:nmap:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )

    with patch(
        "app.bot.handlers.scan.run_nmap_scan",
        return_value={"success": False, "target": "127.0.0.1", "output": "", "error": "nmap failed"},
    ):
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8123)),
                SimpleNamespace(user_data={}),
            )
        )

    scans = list_assessment_scans(assessment["id"])
    assert len(scans) == 1
    assert scans[0]["tool"] == "nmap"
    assert scans[0]["status"] == "failed"
    assert "Nmap: Failed" in query_message.reply_text.call_args_list[-1].args[0]


def test_domain_assessment_skips_incompatible_gitleaks_and_prowler_without_findings() -> None:
    assessment = create_assessment("Domain Tool Compatibility")
    add_assessment_target(assessment["id"], address="example.com")

    for tool in ("gitleaks", "prowler"):
        query = SimpleNamespace(
            data=f"assessment:run:{tool}:{assessment['id']}",
            answer=AsyncMock(),
            edit_message_text=AsyncMock(),
            message=SimpleNamespace(reply_text=AsyncMock()),
        )
        with (
            patch("app.bot.handlers.scan.run_gitleaks_scan") as gitleaks_runner,
            patch("app.bot.handlers.scan.run_prowler_scan") as prowler_runner,
        ):
            asyncio.run(
                assessment_callback_handler(
                    SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8124)),
                    SimpleNamespace(user_data={}),
                )
            )

        query.edit_message_text.assert_not_called()
        assert "not applicable" in query.message.reply_text.call_args.args[0]
        assert "Assessment Dashboard" in query.message.reply_text.call_args.args[0]
        keyboard = query.message.reply_text.call_args.kwargs["reply_markup"]
        buttons = [button.text for row in keyboard.inline_keyboard for button in row]
        assert "Run Gitleaks" in buttons
        assert "Run Prowler" in buttons
        assert "Run Metasploit" in buttons
        gitleaks_runner.assert_not_called()
        prowler_runner.assert_not_called()

    assert list_assessment_scans(assessment["id"]) == []


def test_assessment_dashboard_gitleaks_and_prowler_buttons_route_to_assessment_handler() -> None:
    assessment = create_assessment("Dashboard Callback Routing")
    keyboard = build_assessment_dashboard_keyboard(assessment["id"])
    callbacks = {button.text: button.callback_data for row in keyboard.inline_keyboard for button in row}

    assert callbacks["Run Gitleaks"] == f"assessment:run:gitleaks:{assessment['id']}"
    assert callbacks["Run Prowler"] == f"assessment:run:prowler:{assessment['id']}"
    assert re.fullmatch(r"^assessment:.+", callbacks["Run Gitleaks"])
    assert re.fullmatch(r"^assessment:.+", callbacks["Run Prowler"])
    assert not re.fullmatch(SCAN_CALLBACK_PATTERN, callbacks["Run Gitleaks"])
    assert not re.fullmatch(SCAN_CALLBACK_PATTERN, callbacks["Run Prowler"])


def test_repeated_assessment_dashboard_render_handles_message_not_modified() -> None:
    assessment = create_assessment("Repeated Dashboard")
    add_assessment_target(assessment["id"], address="example.com")
    query = SimpleNamespace(
        data=f"assessment:dashboard:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(side_effect=BadRequest("Message is not modified")),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )

    asyncio.run(
        assessment_callback_handler(
            SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8126)),
            SimpleNamespace(user_data={}),
        )
    )

    assert query.answer.call_args_list[-1].args[0] == "Assessment dashboard is already shown."


def test_assessment_dashboard_changed_render_still_edits_message() -> None:
    assessment = create_assessment("Changed Dashboard")
    add_assessment_target(assessment["id"], address="example.com")
    query = SimpleNamespace(
        data=f"assessment:dashboard:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )

    asyncio.run(
        assessment_callback_handler(
            SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8127)),
            SimpleNamespace(user_data={}),
        )
    )

    query.edit_message_text.assert_called_once()
    assert "Assessment Dashboard" in query.edit_message_text.call_args.args[0]
    assert query.edit_message_text.call_args.kwargs["reply_markup"] is not None


def test_assessment_gitleaks_skip_dashboard_handles_message_not_modified() -> None:
    assessment = create_assessment("Gitleaks Skip Repeated")
    add_assessment_target(assessment["id"], address="example.com")
    query = SimpleNamespace(
        data=f"assessment:run:gitleaks:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(side_effect=BadRequest("Message is not modified")),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )

    with patch("app.bot.handlers.scan.run_gitleaks_scan") as gitleaks_runner:
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8128)),
                SimpleNamespace(user_data={}),
            )
        )

    assert query.edit_message_text.assert_not_called() is None
    assert query.answer.await_count == 1
    query.message.reply_text.assert_called_once()
    assert "Gitleaks is not applicable" in query.message.reply_text.call_args.args[0]
    assert query.message.reply_text.call_args.kwargs["reply_markup"] is not None
    gitleaks_runner.assert_not_called()


def test_assessment_prowler_skip_dashboard_handles_message_not_modified() -> None:
    assessment = create_assessment("Prowler Skip Repeated")
    add_assessment_target(assessment["id"], address="example.com")
    query = SimpleNamespace(
        data=f"assessment:run:prowler:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(side_effect=BadRequest("Message is not modified")),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )

    with patch("app.bot.handlers.scan.run_prowler_scan") as prowler_runner:
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8129)),
                SimpleNamespace(user_data={}),
            )
        )

    assert query.edit_message_text.assert_not_called() is None
    assert query.answer.await_count == 1
    query.message.reply_text.assert_called_once()
    assert "Prowler is not applicable" in query.message.reply_text.call_args.args[0]
    assert query.message.reply_text.call_args.kwargs["reply_markup"] is not None
    prowler_runner.assert_not_called()


def test_valid_local_directory_gitleaks_assessment_still_runs(tmp_path) -> None:
    clear_user_scan_requests(8130)
    assessment = create_assessment("Local Gitleaks")
    target = add_assessment_target(assessment["id"], address=str(tmp_path))
    message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:run:gitleaks:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=message,
    )
    context = SimpleNamespace(user_data={})

    with patch("app.bot.handlers.scan.scan_target_handler", new_callable=AsyncMock) as scan_target_mock:
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8130)),
                context,
            )
        )

    query.edit_message_text.assert_called_once()
    assert "Launching GITLEAKS" in query.edit_message_text.call_args.args[0]
    assert context.user_data[ASSESSMENT_SCAN_CONTEXT_KEY]["tool"] == "gitleaks"
    assert context.user_data[ASSESSMENT_SCAN_CONTEXT_KEY]["target_id"] == target["id"]
    scan_target_mock.assert_awaited_once()


def test_valid_provider_prowler_assessment_still_runs() -> None:
    clear_user_scan_requests(8131)
    assessment = create_assessment("AWS Prowler")
    target = add_assessment_target(assessment["id"], address="aws")
    message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:run:prowler:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=message,
    )
    context = SimpleNamespace(user_data={})

    with patch("app.bot.handlers.scan.scan_target_handler", new_callable=AsyncMock) as scan_target_mock:
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8131)),
                context,
            )
        )

    query.edit_message_text.assert_called_once()
    assert "Launching PROWLER" in query.edit_message_text.call_args.args[0]
    assert context.user_data[ASSESSMENT_SCAN_CONTEXT_KEY]["tool"] == "prowler"
    assert context.user_data[ASSESSMENT_SCAN_CONTEXT_KEY]["target_id"] == target["id"]
    scan_target_mock.assert_awaited_once()


def test_assessment_metasploit_launch_routes_only_to_metasploit_prompt() -> None:
    clear_user_scan_requests(8125)
    assessment = create_assessment("Metasploit Routing")
    add_assessment_target(assessment["id"], address="example.com")
    message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:run:metasploit:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=message,
    )
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: "stale-prowler"})

    with (
        patch("app.tools.metasploit_runner.check_metasploit_readiness", return_value={"ready": True}),
        patch("app.bot.handlers.scan.run_prowler_scan") as prowler_runner,
    ):
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8125)),
                context,
            )
        )

    assert "Launching METASPLOIT" in query.edit_message_text.call_args.args[0]
    assert message.reply_text.call_args.args[0] == build_metasploit_mode_text()
    assert message.reply_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].text == "Guided Validation"
    assert context.user_data[ASSESSMENT_SCAN_CONTEXT_KEY]["tool"] == "metasploit"
    prowler_runner.assert_not_called()


def test_assessment_tshark_button_shows_separate_upload_live_choice_and_clears_stale_state() -> None:
    assessment = create_assessment("TShark Assessment")
    add_assessment_target(assessment["id"], address="example.com")
    query = SimpleNamespace(
        data=f"assessment:run:tshark:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: "stale", ASSESSMENT_SCAN_CONTEXT_KEY: {"tool": "prowler"}})

    asyncio.run(
        assessment_callback_handler(
            SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8132)),
            context,
        )
    )

    assert PENDING_NMAP_REQUEST_KEY not in context.user_data
    assert ASSESSMENT_SCAN_CONTEXT_KEY not in context.user_data
    assert get_upload_state(8132) is None
    assert get_tshark_assessment_upload_context(8132) is None
    query.edit_message_text.assert_not_called()
    query.message.reply_text.assert_called_once()
    assert query.message.reply_text.call_args.args[0] == build_tshark_mode_text()
    keyboard = query.message.reply_text.call_args.kwargs["reply_markup"]
    callbacks = {button.text: button.callback_data for row in keyboard.inline_keyboard for button in row}
    assert callbacks["Capture During Validation"] == f"tshark:capture:{assessment['id']}"
    assert callbacks["Analyze PCAP"] == f"tshark:upload:{assessment['id']}"
    assert callbacks["Standalone Live Capture"] == f"tshark:live:{assessment['id']}"


def test_assessment_dashboard_shows_tshark_button_and_status() -> None:
    assessment = create_assessment("TShark Dashboard")
    record_assessment_scan(assessment["id"], tool="tshark", status="completed", elapsed_seconds=2)
    dashboard = build_assessment_dashboard_text(assessment, [{"address": "example.com"}], list_assessment_scans(assessment["id"]))
    keyboard = build_assessment_dashboard_keyboard(assessment["id"])
    buttons = [button.text for row in keyboard.inline_keyboard for button in row]

    assert "TShark: Completed" in dashboard
    assert "Run TShark" in buttons


def test_assessment_history_callback_lists_recorded_scans() -> None:
    assessment = create_assessment("History Callback Assessment")
    record_assessment_scan(assessment["id"], tool="bbot", status="completed", elapsed_seconds=19, risk="info")
    query = SimpleNamespace(
        data=f"assessment:history:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
    )

    asyncio.run(assessment_callback_handler(SimpleNamespace(callback_query=query), SimpleNamespace(user_data={})))

    query.answer.assert_called_once()
    assert "Assessment History" in query.edit_message_text.call_args.args[0]
    assert "BBOT - Completed" in query.edit_message_text.call_args.args[0]
    keyboard = query.edit_message_text.call_args.kwargs["reply_markup"]
    assert keyboard.inline_keyboard[0][0].text == "Back to Assessment"


def test_assessment_ask_mongrel_starts_assessment_conversation() -> None:
    assessment = create_assessment("Assessment Chat")
    target = add_assessment_target(assessment["id"], address="scanme.nmap.org")
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:ask:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    context = SimpleNamespace(user_data={})

    asyncio.run(assessment_callback_handler(SimpleNamespace(callback_query=query), context))

    query.answer.assert_called_once()
    query.edit_message_text.assert_not_called()
    query_message.reply_text.assert_called_once_with(build_assessment_chat_intro(assessment, [target]))
    assert "Ask Mongrel anything. Cybersecurity is my specialty." not in query_message.reply_text.call_args.args[0]
    assert "Assessment AI" in query_message.reply_text.call_args.args[0]
    assert context.user_data[ASSESSMENT_CHAT_STATE_KEY]["assessment_id"] == assessment["id"]
    assert context.user_data[ASSESSMENT_CHAT_STATE_KEY][ACTIVE_ASSESSMENT_ID_KEY] == assessment["id"]
    assert context.user_data[ASSESSMENT_CHAT_STATE_KEY]["assessment_chat"] is True


def test_assessment_ask_mongrel_answers_with_assessment_evidence() -> None:
    clear_user_findings(8130)
    assessment = create_assessment("Assessment Chat Evidence")
    target = add_assessment_target(assessment["id"], address="scanme.nmap.org")
    finding = add_finding(
        user_id=8130,
        finding={
            "source": "nmap",
            "target": "scanme.nmap.org",
            "risk_level": "medium",
            "summary": "SSH observed.",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", target_id=target["id"], finding_id=finding["id"])
    context = SimpleNamespace(user_data={ASSESSMENT_CHAT_STATE_KEY: {"assessment_id": assessment["id"]}})
    message = SimpleNamespace(text="What ports are open?", reply_text=AsyncMock())

    with patch("app.services.assessment_ai.ask_ai", return_value="Observed evidence shows 22/tcp ssh."):
        asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=8130)), context))

    assert message.reply_text.call_args_list[0].args[0] == "Reviewing assessment evidence..."
    assert message.reply_text.call_args_list[1].args[0] == "Observed evidence shows 22/tcp ssh."
    assert ASSESSMENT_CHAT_STATE_KEY in context.user_data


def test_assessment_chat_followup_does_not_call_generic_ask_mongrel() -> None:
    clear_user_findings(8136)
    assessment = create_assessment("Assessment Chat Followup")
    target = add_assessment_target(assessment["id"], address="scanme.nmap.org")
    finding = add_finding(
        user_id=8136,
        finding={
            "source": "nmap",
            "target": "scanme.nmap.org",
            "summary": "SSH observed.",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", target_id=target["id"], finding_id=finding["id"])
    set_ai_waiting(8136)
    context = SimpleNamespace(user_data={ASSESSMENT_CHAT_STATE_KEY: {"assessment_id": assessment["id"]}})
    message = SimpleNamespace(text="What evidence supports that?", reply_text=AsyncMock())

    with (
        patch("app.services.assessment_ai.ask_ai", return_value="Assessment evidence shows 22/tcp ssh.") as assessment_ask_ai,
        patch("app.bot.handlers.scan.ask_ai", side_effect=AssertionError("generic Ask Mongrel should not be called")) as generic_ask_ai,
    ):
        asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=8136)), context))

    assessment_ask_ai.assert_called_once()
    generic_ask_ai.assert_not_called()
    assert message.reply_text.call_args_list[0].args[0] == "Reviewing assessment evidence..."
    assert message.reply_text.call_args_list[1].args[0] == "Assessment evidence shows 22/tcp ssh."
    assert ASSESSMENT_CHAT_STATE_KEY in context.user_data


def test_assessment_ask_mongrel_exit_returns_to_normal_flow() -> None:
    assessment = create_assessment("Assessment Chat Exit")
    context = SimpleNamespace(user_data={ASSESSMENT_CHAT_STATE_KEY: {"assessment_id": assessment["id"]}})
    message = SimpleNamespace(text="Cancel", reply_text=AsyncMock())

    asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=8131)), context))

    assert ASSESSMENT_CHAT_STATE_KEY not in context.user_data
    assert message.reply_text.call_args.args[0] == "Exited assessment Ask Mongrel mode."


def test_assessment_chat_exit_words_clear_state() -> None:
    for word in ("Back", "Cancel"):
        assessment = create_assessment(f"Assessment Chat Exit {word}")
        context = SimpleNamespace(user_data={ASSESSMENT_CHAT_STATE_KEY: {"assessment_id": assessment["id"], ACTIVE_ASSESSMENT_ID_KEY: assessment["id"]}})
        message = SimpleNamespace(text=word, reply_text=AsyncMock())

        asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=8137)), context))

        assert ASSESSMENT_CHAT_STATE_KEY not in context.user_data
        assert message.reply_text.call_args.args[0] == "Exited assessment Ask Mongrel mode."


def test_assessment_dashboard_callback_exits_assessment_chat() -> None:
    assessment = create_assessment("Assessment Dashboard Exit")
    query = SimpleNamespace(
        data=f"assessment:dashboard:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
    )
    context = SimpleNamespace(user_data={ASSESSMENT_CHAT_STATE_KEY: {"assessment_id": assessment["id"], ACTIVE_ASSESSMENT_ID_KEY: assessment["id"]}})

    asyncio.run(assessment_callback_handler(SimpleNamespace(callback_query=query), context))

    assert ASSESSMENT_CHAT_STATE_KEY not in context.user_data
    assert "Assessment Dashboard" in query.edit_message_text.call_args.args[0]


def test_ask_handler_preserves_assessment_chat_mode() -> None:
    clear_ai_waiting(8138)
    assessment = create_assessment("Assessment Ask Handler")
    target = add_assessment_target(assessment["id"], address="example.com")
    context = SimpleNamespace(
        user_data={
            ASSESSMENT_CHAT_STATE_KEY: {
                "assessment_chat": True,
                "assessment_id": assessment["id"],
                ACTIVE_ASSESSMENT_ID_KEY: assessment["id"],
            }
        }
    )
    message = SimpleNamespace(text="Ask Mongrel", reply_text=AsyncMock())

    asyncio.run(ask_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=8138)), context))

    assert is_ai_waiting(8138) is False
    assert message.reply_text.call_args.args[0] == build_assessment_chat_intro(assessment, [target])
    assert ASSESSMENT_CHAT_STATE_KEY in context.user_data


def test_home_exits_assessment_chat_mode() -> None:
    assessment = create_assessment("Assessment Home Exit")
    context = SimpleNamespace(
        user_data={
            ASSESSMENT_CHAT_STATE_KEY: {
                "assessment_chat": True,
                "assessment_id": assessment["id"],
                ACTIVE_ASSESSMENT_ID_KEY: assessment["id"],
            }
        }
    )
    message = SimpleNamespace(text="Home", reply_text=AsyncMock())

    asyncio.run(home_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=8139)), context))

    assert ASSESSMENT_CHAT_STATE_KEY not in context.user_data
    assert message.reply_text.call_args.args[0] == build_home_text()


def test_assessment_markdown_report_callback_sends_report() -> None:
    clear_user_findings(8134)
    assessment = create_assessment("Markdown Assessment")
    add_assessment_target(assessment["id"], address="example.com")
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:markdown:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )

    asyncio.run(
        assessment_callback_handler(
            SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8134)),
            SimpleNamespace(user_data={}),
        )
    )

    query.answer.assert_called_once()
    query.edit_message_text.assert_not_called()
    report = query_message.reply_text.call_args.args[0]
    assert report.startswith("# Assessment Report")
    assert "Markdown Assessment" in report
    assert "## Evidence Limitations" in report


def test_assessment_ai_report_callback_sends_assessment_report() -> None:
    clear_user_findings(8132)
    assessment = create_assessment("Assessment AI Report")
    target = add_assessment_target(assessment["id"], address="scanme.nmap.org")
    finding = add_finding(
        user_id=8132,
        finding={
            "source": "nmap",
            "target": "scanme.nmap.org",
            "risk_level": "medium",
            "summary": "SSH observed.",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )
    record_assessment_scan(
        assessment["id"],
        tool="nmap",
        status="completed",
        target_id=target["id"],
        finding_id=finding["id"],
        risk="medium",
    )
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:ai_report:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )

    response = "✦ Assessment AI Report\n\nExecutive Summary\nSSH observed."
    with patch("app.services.assessment_ai.ask_ai", return_value=response):
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8132)),
                SimpleNamespace(user_data={}),
            )
        )

    query.answer.assert_called_once()
    query.edit_message_text.assert_not_called()
    query_message.reply_text.assert_called_once_with(response)


def test_assessment_ai_report_callback_returns_fallback_when_ai_unavailable() -> None:
    assessment = create_assessment("Assessment AI Report Fallback")
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:ai_report:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )

    with patch("app.services.assessment_ai.ask_ai", return_value="AI request timed out."):
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8133)),
                SimpleNamespace(user_data={}),
            )
        )

    query.answer.assert_called_once()
    query.edit_message_text.assert_not_called()
    assert "Assessment AI report unavailable." in query_message.reply_text.call_args.args[0]


def test_assessment_ai_report_callback_splits_long_reports() -> None:
    assessment = create_assessment("Assessment AI Long Report")
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:ai_report:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    report = "\u2726 Assessment AI Report\n\n" + ("Evidence reviewed.\n" * 500)

    with (
        patch("app.services.assessment_ai.ask_ai", return_value=report),
        patch("app.bot.handlers.reports.split_report_text", return_value=["chunk one", "chunk two"]) as splitter,
    ):
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8135)),
                SimpleNamespace(user_data={}),
            )
        )

    assert splitter.call_count == 1
    assert splitter.call_args.args[0].startswith("\u2726 Assessment AI Report")
    assert "Evidence reviewed." in splitter.call_args.args[0]
    assert [call.args[0] for call in query_message.reply_text.call_args_list] == ["chunk one", "chunk two"]


def test_assessment_markdown_report_callback_edits_when_message_missing() -> None:
    assessment = create_assessment("Placeholder Fallback Assessment")
    query = SimpleNamespace(
        data=f"assessment:markdown:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=None,
    )

    asyncio.run(assessment_callback_handler(SimpleNamespace(callback_query=query), SimpleNamespace(user_data={})))

    query.answer.assert_called_once()
    query.edit_message_text.assert_called_once()
    assert query.edit_message_text.call_args.args[0].startswith("# Assessment Report")


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


def test_progress_spinner_cycles_through_multiple_frames() -> None:
    stop_event = asyncio.Event()
    frames = build_spinner_frames("Generating AI Recon Assessment")
    edited_messages: list[str] = []

    async def record_edit(text: str) -> None:
        edited_messages.append(text)
        if len(edited_messages) == len(frames):
            stop_event.set()

    status_message = SimpleNamespace(edit_text=AsyncMock(side_effect=record_edit))

    async def run_flow() -> None:
        await run_progress_frames(
            status_message,
            frames,
            stop_event,
            interval_seconds=0,
            context="Test progress",
        )

    asyncio.run(run_flow())

    assert edited_messages == [
        "Generating AI Recon Assessment /",
        "Generating AI Recon Assessment -",
        "Generating AI Recon Assessment \\",
        "Generating AI Recon Assessment |",
    ]


def test_progress_edit_errors_are_swallowed_and_logged(caplog) -> None:
    status_message = SimpleNamespace(edit_text=AsyncMock(side_effect=TimedOut("status timeout")))

    asyncio.run(safe_edit_text(status_message, "Generating AI Recon Assessment /", context="Test progress"))

    assert status_message.edit_text.await_count == 1
    assert "Test progress edit timed out" in caplog.text


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
    assert message.reply_text.call_args_list[0].args[0] == (
        f" Nmap Scan\n\n{icon('target')} Target\n127.0.0.1\n\n"
        f"{icon('running')} Status\nLaunching scan...\n\n{icon('elapsed')} Elapsed\n0s"
    )
    assert f"{icon('target')} Target\n127.0.0.1" in message.reply_text.call_args_list[1].args[0]
    keyboard = message.reply_text.call_args_list[1].kwargs["reply_markup"]
    assert keyboard.inline_keyboard[0][0].text == "AI Summary"
    assert keyboard.inline_keyboard[0][0].callback_data.startswith("ai_summary:nmap:")
    assert get_user_findings(7004)
    investigation = get_user_investigations(7004)[0]
    events = get_investigation_events(investigation["id"], 7004)
    assert [event["event_type"] for event in events] == ["nmap_scan_started", "nmap_scan_completed"]


def test_nmap_scan_sends_result_card_before_ai_assessment() -> None:
    clear_user_findings(7009)
    clear_user_investigations(7009)
    clear_user_scan_requests(7009)
    scan_request = create_scan_request(user_id=7009, scan_type="nmap")
    mark_scan_request_awaiting_target(user_id=7009, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="127.0.0.1", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7009))
    assessment_lines = [
        "Executive Summary",
        "- SSH service was observed.",
        "",
        "Observed Facts",
        "- 22/tcp ssh",
        "",
        "Confidence",
        "Medium",
    ]

    with (
        patch(
            "app.bot.handlers.scan.run_nmap_scan",
            return_value={
                "success": True,
                "target": "127.0.0.1",
                "output": "Nmap scan report for 127.0.0.1\nHost is up.\n22/tcp open ssh\n",
                "error": "",
            },
        ),
        patch("app.bot.handlers.scan.generate_nmap_ai_assessment", return_value=assessment_lines),
    ):
        asyncio.run(scan_target_handler(update, context))

    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert "Nmap Scan Complete" in sent_messages[1]
    assert "AI Summary" in message.reply_text.call_args_list[1].kwargs["reply_markup"].inline_keyboard[0][0].text
    assert sent_messages[2] == "Generating Nmap AI assessment..."
    assert "Nmap AI Assessment" in sent_messages[3]
    assert "Observed Facts\n- 22/tcp ssh" in sent_messages[3]


def test_nmap_ai_assessment_failure_does_not_fail_scan() -> None:
    clear_user_findings(7010)
    clear_user_investigations(7010)
    clear_user_scan_requests(7010)
    scan_request = create_scan_request(user_id=7010, scan_type="nmap")
    mark_scan_request_awaiting_target(user_id=7010, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="127.0.0.1", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7010))

    with (
        patch(
            "app.bot.handlers.scan.run_nmap_scan",
            return_value={
                "success": True,
                "target": "127.0.0.1",
                "output": "Nmap scan report for 127.0.0.1\nHost is up.\n",
                "error": "",
            },
        ),
        patch("app.bot.handlers.scan.generate_nmap_ai_assessment", return_value=NMAP_AI_FALLBACK_LINES),
    ):
        asyncio.run(scan_target_handler(update, context))

    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert "Nmap Scan Complete" in sent_messages[1]
    assert "Nmap AI assessment unavailable." in sent_messages[-1]
    assert get_user_findings(7010)


def test_scan_menu_includes_nuclei_scan() -> None:
    keyboard = build_scan_type_keyboard()
    rendered_buttons = [button.text for row in keyboard.inline_keyboard for button in row]
    rendered_layout = [[button.text for button in row] for row in keyboard.inline_keyboard]
    callbacks = {button.text: button.callback_data for row in keyboard.inline_keyboard for button in row}

    assert "Nmap Scan" in rendered_buttons
    assert "Nuclei Scan" in rendered_buttons
    assert "BBOT Recon" in rendered_buttons
    assert "httpx Fingerprint" in rendered_buttons
    assert "Katana Crawl" in rendered_buttons
    assert "Playwright Observe" in rendered_buttons
    assert "ffuf Discovery" in rendered_buttons
    assert "testssl.sh TLS" in rendered_buttons
    assert "Gitleaks Secrets" in rendered_buttons
    assert "Prowler Cloud" in rendered_buttons
    assert "Metasploit Validation" in rendered_buttons
    assert rendered_layout == [
        ["Nmap Scan", "Nuclei Scan", "BBOT Recon"],
        ["httpx Fingerprint", "Katana Crawl", "Playwright Observe"],
        ["ffuf Discovery", "testssl.sh TLS", "Gitleaks Secrets"],
        ["Prowler Cloud", "Metasploit Validation", "TShark PCAP"],
        ["Back"],
    ]
    assert callbacks == {
        "Nmap Scan": "scan:nmap",
        "Nuclei Scan": "scan:nuclei",
        "BBOT Recon": "scan:bbot",
        "httpx Fingerprint": "scan:httpx",
        "Katana Crawl": "scan:katana",
        "Playwright Observe": "scan:playwright",
        "ffuf Discovery": "scan:ffuf",
        "testssl.sh TLS": "scan:testssl",
        "Gitleaks Secrets": "scan:gitleaks",
        "Prowler Cloud": "scan:prowler",
        "Metasploit Validation": "scan:metasploit",
        "TShark PCAP": "scan:tshark",
        "Back": "nav:home",
    }


def test_nuclei_scan_callback_prompts_for_target() -> None:
    clear_user_scan_requests(7101)
    query = SimpleNamespace(data="scan:nuclei", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7101))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_nuclei_target_prompt()
    assert "configured bounded Nuclei profile" in query.edit_message_text.call_args.args[0]
    assert "Zero matches means no selected templates matched" in query.edit_message_text.call_args.args[0]
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_bbot_scan_callback_prompts_for_target() -> None:
    clear_user_scan_requests(7201)
    query = SimpleNamespace(data="scan:bbot", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7201))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_bbot_target_prompt()
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_httpx_scan_callback_prompts_for_target() -> None:
    clear_user_scan_requests(7203)
    query = SimpleNamespace(data="scan:httpx", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7203))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_httpx_target_prompt()
    assert "configured ports/schemes" in query.edit_message_text.call_args.args[0]
    assert "No response bodies, cookies, auth headers, credentials, or secrets" in query.edit_message_text.call_args.args[0]
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_katana_scan_callback_prompts_for_target() -> None:
    clear_user_scan_requests(7205)
    query = SimpleNamespace(data="scan:katana", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7205))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_katana_target_prompt()
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_playwright_scan_callback_prompts_for_target() -> None:
    clear_user_scan_requests(7207)
    query = SimpleNamespace(data="scan:playwright", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7207))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_playwright_target_prompt()
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_ffuf_scan_callback_prompts_for_target() -> None:
    clear_user_scan_requests(7209)
    query = SimpleNamespace(data="scan:ffuf", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7209))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_ffuf_target_prompt()
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_testssl_scan_callback_prompts_for_target() -> None:
    clear_user_scan_requests(7211)
    query = SimpleNamespace(data="scan:testssl", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7211))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_testssl_target_prompt()
    assert "configured testssl.sh profile" in query.edit_message_text.call_args.args[0]
    assert "Absence of findings is not a secure verdict" in query.edit_message_text.call_args.args[0]
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_gitleaks_scan_callback_prompts_for_target() -> None:
    clear_user_scan_requests(7213)
    query = SimpleNamespace(data="scan:gitleaks", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7213))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_gitleaks_target_prompt()
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_prowler_scan_callback_prompts_for_provider_only() -> None:
    clear_user_scan_requests(7215)
    query = SimpleNamespace(data="scan:prowler", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7215))
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(update, context))

    prompt = query.edit_message_text.call_args.args[0]
    assert prompt == build_prowler_provider_prompt()
    assert "aws" in prompt
    assert "azure" in prompt
    assert "gcp" in prompt
    assert "access key" not in prompt.lower()
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_gitleaks_target_prompt_uses_vps_local_scope_guidance() -> None:
    prompt = build_gitleaks_target_prompt()

    assert "Send an authorized local directory path on the Mongrel VPS." in prompt
    assert "- Secrets are redacted in Telegram, AI, and reports." in prompt
    assert "- Raw secrets are stored only in the encrypted Evidence Vault when configured." in prompt
    assert "- No credential validation or use is performed." in prompt
    assert "/home/mongrel/Project-Mongrel/data/gitleaks_smoke_fixture" in prompt
    assert "/home/mongrel/Project-Mongrel/data/artifacts/<assessment-id>" in prompt
    assert "generated fake test data only" in prompt
    assert "C:\\dev" not in prompt
    assert ".\\data" not in prompt


def test_scan_callback_pattern_routes_testssl_button() -> None:
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "scan:testssl")


def test_scan_callback_pattern_routes_gitleaks_button() -> None:
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "scan:gitleaks")


def test_scan_callback_pattern_routes_prowler_button() -> None:
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "scan:prowler")


def test_scan_callback_pattern_routes_metasploit_button_and_actions() -> None:
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "scan:metasploit")
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "msf:approve:proposal-id")
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "msf:reject:proposal-id")
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "msf:details:proposal-id")


def test_scan_callback_pattern_routes_tshark_button() -> None:
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "scan:tshark")


def test_scan_callback_pattern_routes_evidence_vault_actions() -> None:
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "glev:shorttoken")
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "glrv:shorttoken")
    assert re.fullmatch(SCAN_CALLBACK_PATTERN, "glcx:shorttoken")


def test_testssl_scan_starts_timer_stores_evidence_and_sends_ai_assessment() -> None:
    clear_user_findings(7212)
    clear_user_investigations(7212)
    clear_user_scan_requests(7212)
    scan_request = create_scan_request(user_id=7212, scan_type="testssl")
    mark_scan_request_awaiting_target(user_id=7212, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7212))
    json_output = """
    {
      "scanResult": [
        {
          "serverDefaults": [
            {"id":"cert_commonName","severity":"INFO","finding":"example.com"},
            {"id":"cert_issuer","severity":"INFO","finding":"Example CA"}
          ],
          "scanResult": [
            {"id":"TLS 1.2","severity":"OK","finding":"offered"},
            {"id":"TLS 1.3","severity":"OK","finding":"offered"}
          ]
        }
      ]
    }
    """
    assessment_lines = ["Executive Summary", "- TLS evidence reviewed.", "Confidence", "Medium"]

    with (
        patch(
            "app.bot.handlers.scan.run_testssl_scan",
            return_value={
                "success": True,
                "target": "example.com:443",
                "output": "noisy stdout",
                "json_output": json_output,
                "error": "",
                "returncode": 0,
                "elapsed_seconds": 6,
            },
        ),
        patch("app.bot.handlers.scan.generate_testssl_ai_assessment", return_value=assessment_lines),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock) as start_auto_refresh,
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock) as stop_auto_refresh,
    ):
        asyncio.run(scan_target_handler(update, context))

    start_auto_refresh.assert_awaited_once_with("Running scan...", interval_seconds=5)
    assert stop_auto_refresh.await_count >= 1
    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert any("testssl.sh Scan Complete" in text for text in sent_messages)
    assert any("Generating testssl.sh AI assessment..." in text for text in sent_messages)
    assert any("testssl.sh AI Assessment" in text for text in sent_messages)
    finding = get_user_findings(7212)[0]
    assert finding["source"] == "testssl"
    assert finding["testssl_evidence"]["certificate"]["issuer"] == "Example CA"
    assert finding["testssl_summary"]["supported_protocols"] == ["TLS 1.2", "TLS 1.3"]


def test_testssl_scan_failure_uses_sanitized_runner_error() -> None:
    clear_user_findings(7214)
    clear_user_investigations(7214)
    clear_user_scan_requests(7214)
    scan_request = create_scan_request(user_id=7214, scan_type="testssl")
    mark_scan_request_awaiting_target(user_id=7214, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7214))
    diagnostic = '/opt/testssl.sh/testssl.sh: unrecognized option "--connect-timeout"'

    with (
        patch(
            "app.bot.handlers.scan.run_testssl_scan",
            return_value={
                "success": False,
                "target": "example.com:443",
                "output": "",
                "json_output": "",
                "error": diagnostic,
                "returncode": 1,
                "elapsed_seconds": 0.08,
            },
        ),
        patch("app.bot.handlers.scan.generate_testssl_ai_assessment") as generate_testssl_ai_assessment,
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock),
    ):
        asyncio.run(scan_target_handler(update, context))

    generate_testssl_ai_assessment.assert_not_called()
    progress_text = status_message.edit_text.call_args_list[-1].args[0]
    result_text = message.reply_text.call_args_list[1].args[0]
    assert diagnostic in progress_text
    assert diagnostic in result_text
    assert "Unknown error" not in progress_text
    assert "Unknown error" not in result_text


def _prowler_fixture(records: list[dict]) -> str:
    return json.dumps(records)


def _prowler_record(status: str = "FAIL", severity: str = "medium", service: str = "iam", check_id: str = "iam_check") -> dict:
    return {
        "metadata": {"event_code": check_id, "product": {"feature": {"name": service}}},
        "cloud": {"provider": "aws", "region": "global"},
        "finding_info": {"uid": f"{check_id}-finding", "title": f"{check_id} title", "desc": "Synthetic Prowler check."},
        "status_code": status,
        "severity": severity,
        "resources": [{"uid": f"{check_id}-resource", "name": "synthetic-resource", "region": "global", "group": {"name": service}}],
        "risk_details": "Scanner-reported posture risk.",
        "remediation": {"desc": "Review configuration.", "references": ["https://docs.example.invalid/prowler"]},
    }


def test_prowler_scan_provider_success_stores_normalized_evidence(tmp_path) -> None:
    clear_user_findings(7216)
    clear_user_investigations(7216)
    clear_user_scan_requests(7216)
    output_file = tmp_path / "mongrel-prowler-aws.ocsf.json"
    output_file.write_text(_prowler_fixture([_prowler_record("FAIL", "Medium", "iam"), _prowler_record("PASS", "informational", "s3", "s3_check")]), encoding="utf-8")
    scan_request = create_scan_request(user_id=7216, scan_type="prowler")
    mark_scan_request_awaiting_target(user_id=7216, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="aws", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7216))
    result = {
        "success": True,
        "provider": "aws",
        "elapsed_seconds": 4,
        "returncode": 0,
        "command": ["prowler", "aws"],
        "output_files": [str(output_file)],
        "output_dir": str(tmp_path),
    }

    with (
        patch("app.bot.handlers.scan.run_prowler_scan", return_value=result) as run_mock,
        patch("app.bot.handlers.scan.generate_prowler_ai_assessment", return_value=["Executive Summary", "- Prowler evidence reviewed."]) as ai_mock,
        patch("app.bot.handlers.scan.ScanProgressCard.start", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.complete", new_callable=AsyncMock),
    ):
        asyncio.run(scan_target_handler(update, context))

    run_args = run_mock.call_args.args
    assert run_args[0] == "aws"
    assert str(run_args[1]).replace("\\", "/").startswith("data/prowler/aws-")
    assert run_args[2] == "mongrel-prowler-aws"
    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert any("Prowler Cloud Posture Scan Complete" in text for text in sent_messages)
    assert any("Provider: AWS" in text and "Context: standalone-aws" in text for text in sent_messages)
    assert any("Prowler AI Assessment" in text for text in sent_messages)
    assert not any("Synthetic Prowler check." * 20 in text for text in sent_messages)
    finding = get_user_findings(7216)[0]
    assert finding["source"] == "prowler"
    assert finding["provider"] == "aws"
    assert finding["cloud_context"] == "standalone-aws"
    assert finding["target"] == "standalone-aws"
    assert finding["prowler_evidence"]["findings"][0]["status"] == "FAIL"
    assert finding["prowler_evidence"]["findings"][0]["status_interpretation"] == "scanner_reported_failed_check"
    assert finding["prowler_evidence"]["findings"][1]["status"] == "PASS"
    assert finding["prowler_evidence"]["findings"][0]["severity"] == "Medium"
    ai_mock.assert_called_once()


def test_prowler_provider_input_rejects_unsupported_and_flag_injection() -> None:
    clear_user_scan_requests(7217)
    scan_request = create_scan_request(user_id=7217, scan_type="prowler")
    mark_scan_request_awaiting_target(user_id=7217, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="aws --fix", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7217))

    with patch("app.bot.handlers.scan.run_prowler_scan") as run_mock:
        asyncio.run(scan_target_handler(update, context))

    run_mock.assert_not_called()
    assert "Invalid Prowler provider" in message.reply_text.call_args.args[0]


def test_prowler_assessment_mode_rejects_host_target_with_explicit_limitation() -> None:
    clear_user_scan_requests(7223)
    scan_request = create_scan_request(user_id=7223, scan_type="prowler")
    mark_scan_request_awaiting_target(user_id=7223, scan_request_id=scan_request.id)
    context = SimpleNamespace(
        user_data={
            PENDING_NMAP_REQUEST_KEY: scan_request.id,
            ASSESSMENT_SCAN_CONTEXT_KEY: {"assessment_id": 1, "target_id": 1, "tool": "prowler"},
        }
    )
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7223))

    with (
        patch("app.bot.handlers.scan.run_prowler_scan") as run_mock,
        patch("app.bot.handlers.scan._record_assessment_scan") as record_mock,
    ):
        asyncio.run(scan_target_handler(update, context))

    run_mock.assert_not_called()
    record_mock.assert_called_once()
    text = message.reply_text.call_args.args[0]
    assert "Assessment-mode Prowler currently accepts only aws, azure, or gcp" in text
    assert "richer cloud environment labels need a later UX pass" in text


def test_prowler_success_with_no_parsed_checks_does_not_invent_ai_findings(tmp_path) -> None:
    clear_user_findings(7222)
    clear_user_investigations(7222)
    clear_user_scan_requests(7222)
    output_file = tmp_path / "mongrel-prowler-aws.ocsf.json"
    output_file.write_text("[]", encoding="utf-8")
    scan_request = create_scan_request(user_id=7222, scan_type="prowler")
    mark_scan_request_awaiting_target(user_id=7222, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="aws", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7222))
    result = {
        "success": True,
        "provider": "aws",
        "elapsed_seconds": 1,
        "output_files": [str(output_file)],
        "returncode": 0,
    }

    with (
        patch("app.bot.handlers.scan.run_prowler_scan", return_value=result),
        patch("app.bot.handlers.scan.generate_prowler_ai_assessment") as ai_mock,
        patch("app.bot.handlers.scan.ScanProgressCard.start", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.complete", new_callable=AsyncMock),
    ):
        asyncio.run(scan_target_handler(update, context))

    ai_mock.assert_not_called()
    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert any("No parsed Prowler checks were available from this run." in text for text in sent_messages)
    assert not any("confirmed exploitable" in text.lower() for text in sent_messages)


def test_prowler_runner_failure_is_safe_message() -> None:
    clear_user_findings(7218)
    clear_user_scan_requests(7218)
    scan_request = create_scan_request(user_id=7218, scan_type="prowler")
    mark_scan_request_awaiting_target(user_id=7218, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="aws", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7218))
    result = {"success": False, "provider": "aws", "elapsed_seconds": 1, "error": "Prowler failed with <REDACTED>", "error_type": "execution_failed"}

    with (
        patch("app.bot.handlers.scan.run_prowler_scan", return_value=result),
        patch("app.bot.handlers.scan.ScanProgressCard.start", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.fail", new_callable=AsyncMock),
    ):
        asyncio.run(scan_target_handler(update, context))

    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert any("Prowler Cloud Posture" in text and "Failed" in text for text in sent_messages)
    assert "fake-token" not in str(sent_messages)
    assert get_user_findings(7218)[0]["status"] == "failed"


def test_prowler_no_credentials_stderr_is_sanitized_in_telegram() -> None:
    clear_user_findings(7224)
    clear_user_scan_requests(7224)
    scan_request = create_scan_request(user_id=7224, scan_type="prowler")
    mark_scan_request_awaiting_target(user_id=7224, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="aws", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7224))
    result = {
        "success": False,
        "provider": "aws",
        "cloud_context": "standalone-aws",
        "elapsed_seconds": 2,
        "output": "[1;92m                         _\n\x1b[1;92m  ____  Prowler banner\n| |_) | | | (_) \\ V  V /| |  __/ |",
        "error": "[File: aws_provider.py:1347]\n[Module: aws_provider]\nCRITICAL: NoCredentialsError: Unable to locate credentials\nauthorization: Bearer fake-token-for-test",
        "error_type": "execution_failed",
    }

    with (
        patch("app.bot.handlers.scan.run_prowler_scan", return_value=result),
        patch("app.bot.handlers.scan.ScanProgressCard.start", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.fail", new_callable=AsyncMock),
    ):
        asyncio.run(scan_target_handler(update, context))

    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    combined = "\n".join(sent_messages)
    assert "Cloud credentials were not available for AWS on the Mongrel VPS." in combined
    assert "Provider: AWS" in combined
    assert "Context: standalone-aws" in combined
    assert "Total checks/findings parsed: 0" in combined
    assert "Failed" in combined
    assert "[1;92m" not in combined
    assert "____" not in combined
    assert "| |_) | | | (_) \\ V  V /| |  __/ |" not in combined
    assert "[File:" not in combined
    assert "[Module:" not in combined
    assert "fake-token-for-test" not in combined
    result_card = next(text for text in sent_messages if "Prowler Cloud Posture Scan Complete" in text)
    findings_text = result_card.split("Findings", 1)[1].split("Observed Assets", 1)[0]
    assert "Cloud credentials were not available" not in findings_text
    assert "Highest scanner-reported severity" not in findings_text
    assert "Top failed services" not in findings_text
    assert findings_text.count("- ") == 5
    stored = get_user_findings(7224)[0]
    assert stored["finding_count"] == 0
    assert "[1;92m" not in str(stored)
    assert "____" not in str(stored)
    assert "| |_) | | | (_) \\ V  V /| |  __/ |" not in str(stored)


def test_prowler_missing_output_file_is_handled_safely(tmp_path) -> None:
    clear_user_findings(7219)
    clear_user_scan_requests(7219)
    scan_request = create_scan_request(user_id=7219, scan_type="prowler")
    mark_scan_request_awaiting_target(user_id=7219, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="aws", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7219))
    result = {"success": True, "provider": "aws", "elapsed_seconds": 1, "output_files": [str(tmp_path / "missing.json")], "returncode": 0}

    with (
        patch("app.bot.handlers.scan.run_prowler_scan", return_value=result),
        patch("app.bot.handlers.scan.ScanProgressCard.start", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.fail", new_callable=AsyncMock),
    ):
        asyncio.run(scan_target_handler(update, context))

    assert get_user_findings(7219)[0]["status"] == "failed"
    assert "output artifact was not found" in get_user_findings(7219)[0]["summary"]


def test_prowler_malformed_output_is_handled_safely(tmp_path) -> None:
    clear_user_findings(7221)
    clear_user_scan_requests(7221)
    output_file = tmp_path / "prowler.json"
    output_file.write_text("{not json", encoding="utf-8")
    scan_request = create_scan_request(user_id=7221, scan_type="prowler")
    mark_scan_request_awaiting_target(user_id=7221, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="aws", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7221))
    result = {"success": True, "provider": "aws", "elapsed_seconds": 1, "output_files": [str(output_file)], "returncode": 0}

    with (
        patch("app.bot.handlers.scan.run_prowler_scan", return_value=result),
        patch("app.bot.handlers.scan.ScanProgressCard.start", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.fail", new_callable=AsyncMock),
    ):
        asyncio.run(scan_target_handler(update, context))

    assert get_user_findings(7221)[0]["status"] == "failed"
    assert "Unable to parse Prowler JSON output" in get_user_findings(7221)[0]["summary"]


def test_prowler_result_card_does_not_dump_huge_raw_output() -> None:
    evidence = {
        "provider": "aws",
        "finding_count": 100,
        "findings": [_prowler_record("FAIL", "high", "iam", f"check_{index}") for index in range(20)],
    }
    result = {"success": True, "provider": "aws", "elapsed_seconds": 2, "output": "RAW" * 1000}

    card = build_prowler_result_text(result, evidence)

    assert "Prowler Cloud Posture Scan Complete" in card
    assert "RAWRAWRAW" not in card
    assert card.count("check_") <= 3


def _metasploit_request_text() -> str:
    return "\n".join(
        [
            "module=auxiliary/scanner/http/http_version",
            "action=auxiliary_validation",
            "target=example.com",
            "port=80",
            "option.TARGETURI=/",
        ]
    )


def test_metasploit_scan_callback_prompts_for_guided_or_advanced_mode() -> None:
    clear_user_scan_requests(7300)
    query = SimpleNamespace(data="scan:metasploit", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7300))
    context = SimpleNamespace(user_data={})

    with patch("app.bot.handlers.scan.check_metasploit_readiness", return_value={"ready": True, "resolved_binary": "msfconsole"}):
        asyncio.run(scan_callback_handler(update, context))

    assert query.edit_message_text.call_args.args[0] == build_metasploit_mode_text()
    keyboard = query.edit_message_text.call_args.kwargs["reply_markup"]
    buttons = [button.text for row in keyboard.inline_keyboard for button in row]
    assert buttons == ["Guided Validation", "Advanced Manual Mode", "Back"]
    assert PENDING_NMAP_REQUEST_KEY not in context.user_data


def test_metasploit_advanced_manual_mode_still_prompts_for_structured_request() -> None:
    clear_user_scan_requests(7330)
    query = SimpleNamespace(data="scan:metasploit", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7330))
    context = SimpleNamespace(user_data={})

    with patch("app.bot.handlers.scan.check_metasploit_readiness", return_value={"ready": True, "resolved_binary": "msfconsole"}):
        asyncio.run(scan_callback_handler(update, context))
    mode_keyboard = query.edit_message_text.call_args.kwargs["reply_markup"]
    manual_callback = mode_keyboard.inline_keyboard[1][0].callback_data
    manual_query = SimpleNamespace(data=manual_callback, answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))

    asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=manual_query, effective_user=SimpleNamespace(id=7330)), context))

    assert manual_query.edit_message_text.call_args.args[0] == build_metasploit_request_prompt()
    assert isinstance(context.user_data[PENDING_NMAP_REQUEST_KEY], str)


def test_metasploit_guided_target_entry_normalizes_url_and_prompts_for_service() -> None:
    clear_user_scan_requests(7331)
    context = _start_metasploit_guided_mode(7331)
    message = SimpleNamespace(text="https://Example.com/app", reply_text=AsyncMock())

    asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7331)), context))

    text = message.reply_text.call_args.args[0]
    keyboard = message.reply_text.call_args.kwargs["reply_markup"]
    assert "Target: example.com" in text
    assert keyboard.inline_keyboard[0][0].text == "HTTP - 80"
    assert keyboard.inline_keyboard[0][1].text == "HTTPS - 443"
    assert len(keyboard.inline_keyboard[0][0].callback_data) <= 64


def test_metasploit_guided_invalid_target_rejected_without_proposal() -> None:
    clear_user_scan_requests(7332)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    context = _start_metasploit_guided_mode(7332)
    message = SimpleNamespace(text="example.com;id", reply_text=AsyncMock())

    asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7332)), context))

    assert "Invalid Metasploit target" in message.reply_text.call_args.args[0]
    assert _metasploit_pending_context == {}


def test_metasploit_guided_service_selection_shows_only_allowlisted_compatible_validation() -> None:
    clear_user_scan_requests(7333)
    context, service_keyboard = _metasploit_guided_service_keyboard_for_target(7333, "https://example.com")
    service_query = SimpleNamespace(
        data=service_keyboard.inline_keyboard[0][1].callback_data,
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )

    asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=service_query, effective_user=SimpleNamespace(id=7333)), context))

    text = service_query.edit_message_text.call_args.args[0]
    keyboard = service_query.edit_message_text.call_args.kwargs["reply_markup"]
    assert "Service: HTTPS - 443" in text
    assert "HTTP service fingerprint check" in text
    assert "struts" not in text.lower()
    assert keyboard.inline_keyboard[0][0].text == "HTTP service fingerprint check"
    assert len(keyboard.inline_keyboard[0][0].callback_data) <= 64


def test_metasploit_guided_custom_port_entry_is_validated() -> None:
    clear_user_scan_requests(7337)
    context, service_keyboard = _metasploit_guided_service_keyboard_for_target(7337, "https://example.com")
    custom_query = SimpleNamespace(
        data=service_keyboard.inline_keyboard[1][0].callback_data,
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )
    asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=custom_query, effective_user=SimpleNamespace(id=7337)), context))
    assert "Send the authorized service port" in custom_query.edit_message_text.call_args.args[0]
    port_message = SimpleNamespace(text="8080", reply_text=AsyncMock())

    asyncio.run(scan_target_handler(SimpleNamespace(message=port_message, effective_user=SimpleNamespace(id=7337)), context))

    assert "Service: Custom service - 8080" in port_message.reply_text.call_args.args[0]
    assert port_message.reply_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].text == "HTTP service fingerprint check"


def test_metasploit_guided_review_card_and_approve_executes_exact_request() -> None:
    clear_user_findings(7334)
    clear_user_scan_requests(7334)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    context, service_keyboard = _metasploit_guided_service_keyboard_for_target(7334, "https://example.com")
    service_query = SimpleNamespace(data=service_keyboard.inline_keyboard[0][1].callback_data, answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=service_query, effective_user=SimpleNamespace(id=7334)), context))
    validation_keyboard = service_query.edit_message_text.call_args.kwargs["reply_markup"]
    proposal_message = SimpleNamespace(reply_text=AsyncMock())
    validation_query = SimpleNamespace(data=validation_keyboard.inline_keyboard[0][0].callback_data, answer=AsyncMock(), edit_message_text=AsyncMock(), message=proposal_message)

    with patch("app.bot.handlers.scan.run_metasploit_validation") as runner_mock:
        asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=validation_query, effective_user=SimpleNamespace(id=7334)), context))
        runner_mock.assert_not_called()

    review = proposal_message.reply_text.call_args.args[0]
    proposal_keyboard = proposal_message.reply_text.call_args.kwargs["reply_markup"]
    assert "Metasploit Validation Review" in review
    assert "Target:\nexample.com" in review
    assert "Service:\nHTTPS (443)" in review
    assert "Validation:\nHTTP service fingerprint check" in review
    assert "Module:\nauxiliary/scanner/http/http_version" in review
    assert "Action:\nauxiliary_validation" in review
    assert "Risk:\nLOW" in review
    assert "This action WILL:" in review
    assert "- Collect HTTP service banner/version metadata from the authorized target." in review
    assert "This action WILL NOT:" in review
    assert "- Create a session" in review
    assert "- Upload a payload" in review
    assert "- Perform post-exploitation" in review
    assert "- Move laterally" in review
    assert "- Execute brute force" in review
    assert "Approved options: SSL=true" in review
    assert len(proposal_keyboard.inline_keyboard[0][0].callback_data) <= 64
    assert len(proposal_keyboard.inline_keyboard[0][1].callback_data) <= 64
    proposal_id = next(iter(_metasploit_pending_context))
    proposal = get_metasploit_proposal(proposal_id)
    assert proposal is not None
    approve_query = SimpleNamespace(data=f"msf:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=proposal_message)
    result = {
        "success": True,
        "module": "auxiliary/scanner/http/http_version",
        "action_type": "auxiliary_validation",
        "target": "example.com",
        "port": 443,
        "output": "Server: nginx",
        "error": "",
        "elapsed_seconds": 1,
        "returncode": 0,
    }

    with (
        patch("app.bot.handlers.scan.run_metasploit_validation", return_value=result) as runner_mock,
        patch("app.bot.handlers.scan.generate_metasploit_ai_assessment", return_value=["Executive Summary", "- Metasploit evidence reviewed."]),
    ):
        asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=approve_query, effective_user=SimpleNamespace(id=7334)), context))

    request = runner_mock.call_args.kwargs["request"]
    assert request["module"] == "auxiliary/scanner/http/http_version"
    assert request["action_type"] == "auxiliary_validation"
    assert request["target"] == "example.com"
    assert request["port"] == 443
    assert request["options"] == {"SSL": "true"}


def test_metasploit_guided_token_is_user_bound_and_rejects_cross_user() -> None:
    clear_user_scan_requests(7335)
    context, service_keyboard = _metasploit_guided_service_keyboard_for_target(7335, "https://example.com")
    query = SimpleNamespace(
        data=service_keyboard.inline_keyboard[0][0].callback_data,
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )

    asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9999)), context))

    assert query.edit_message_text.call_args.args[0] == "Metasploit guided selection was not found or has expired."


def test_metasploit_guided_details_and_reject_do_not_execute() -> None:
    clear_user_scan_requests(7336)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    context, service_keyboard = _metasploit_guided_service_keyboard_for_target(7336, "http://example.com")
    service_query = SimpleNamespace(data=service_keyboard.inline_keyboard[0][0].callback_data, answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=service_query, effective_user=SimpleNamespace(id=7336)), context))
    validation_keyboard = service_query.edit_message_text.call_args.kwargs["reply_markup"]
    proposal_message = SimpleNamespace(reply_text=AsyncMock())
    validation_query = SimpleNamespace(data=validation_keyboard.inline_keyboard[0][0].callback_data, answer=AsyncMock(), edit_message_text=AsyncMock(), message=proposal_message)
    asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=validation_query, effective_user=SimpleNamespace(id=7336)), context))
    proposal_id = next(iter(_metasploit_pending_context))
    details_query = SimpleNamespace(data=f"msf:details:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=proposal_message)
    reject_query = SimpleNamespace(data=f"msf:reject:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=proposal_message)

    with patch("app.bot.handlers.scan.run_metasploit_validation") as runner_mock:
        asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=details_query, effective_user=SimpleNamespace(id=7336)), context))
        asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=reject_query, effective_user=SimpleNamespace(id=7336)), context))

    runner_mock.assert_not_called()
    assert "Metasploit Validation Proposal Details" in details_query.edit_message_text.call_args.args[0]
    assert "rejected" in reject_query.edit_message_text.call_args.args[0]


def _start_metasploit_guided_mode(user_id: int) -> SimpleNamespace:
    query = SimpleNamespace(data="scan:metasploit", answer=AsyncMock(), edit_message_text=AsyncMock())
    context = SimpleNamespace(user_data={})
    with patch("app.bot.handlers.scan.check_metasploit_readiness", return_value={"ready": True, "resolved_binary": "msfconsole"}):
        asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=user_id)), context))
    guided_callback = query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data
    guided_query = SimpleNamespace(data=guided_callback, answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=guided_query, effective_user=SimpleNamespace(id=user_id)), context))
    return context


def _metasploit_guided_service_keyboard_for_target(user_id: int, target: str) -> tuple[SimpleNamespace, object]:
    context = _start_metasploit_guided_mode(user_id)
    message = SimpleNamespace(text=target, reply_text=AsyncMock())
    asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=user_id)), context))
    return context, message.reply_text.call_args.kwargs["reply_markup"]


def test_metasploit_scan_callback_missing_binary_shows_clean_readiness_failure() -> None:
    clear_user_scan_requests(7320)
    clear_metasploit_proposals()
    query = SimpleNamespace(data="scan:metasploit", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7320))
    context = SimpleNamespace(user_data={})
    readiness = {
        "ready": False,
        "error": "Metasploit/msfconsole is not installed or configured. Set METASPLOIT_BINARY to the msfconsole path on the VPS.",
        "error_type": "missing_binary",
        "configured_binary": "/opt/metasploit-framework/bin/msfconsole",
    }

    with patch("app.bot.handlers.scan.check_metasploit_readiness", return_value=readiness):
        asyncio.run(scan_callback_handler(update, context))

    text = query.edit_message_text.call_args.args[0]
    assert text == build_metasploit_readiness_failure_text(readiness)
    assert "Metasploit/msfconsole is not installed or configured." in text
    assert "METASPLOIT_BINARY" in text
    assert "Traceback" not in text
    assert "No validation proposal was created" in text
    assert PENDING_NMAP_REQUEST_KEY not in context.user_data


def test_metasploit_structured_request_creates_proposal_without_execution() -> None:
    clear_user_scan_requests(7301)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    scan_request = create_scan_request(user_id=7301, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=7301, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text=_metasploit_request_text(), reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7301))

    with patch("app.bot.handlers.scan.run_metasploit_validation") as runner_mock:
        asyncio.run(scan_target_handler(update, context))

    runner_mock.assert_not_called()
    sent = message.reply_text.call_args.args[0]
    markup = message.reply_text.call_args.kwargs["reply_markup"]
    buttons = [button.text for row in markup.inline_keyboard for button in row]
    assert "Metasploit Validation Proposal" in sent
    assert "Module:\nauxiliary/scanner/http/http_version" in sent
    assert "Action:\nauxiliary_validation" in sent
    assert "Target:\nexample.com" in sent
    assert "Target: example.com" in sent
    assert "Risk tier: LOW" in sent
    assert "Expires:" in sent
    assert "TARGETURI=/" in sent
    assert buttons == ["Approve", "Reject", "Details"]
    assert _metasploit_pending_context


def test_assessment_metasploit_rejects_target_outside_known_assets() -> None:
    clear_user_scan_requests(7312)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    assessment = create_assessment("Metasploit Target Binding")
    target = add_assessment_target(assessment["id"], address="example.com")
    scan_request = create_scan_request(user_id=7312, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=7312, scan_request_id=scan_request.id)
    context = SimpleNamespace(
        user_data={
            PENDING_NMAP_REQUEST_KEY: scan_request.id,
            ASSESSMENT_SCAN_CONTEXT_KEY: {
                "assessment_id": assessment["id"],
                "target_id": target["id"],
                "primary_target": "example.com",
                "known_assets": ["https://www.example.com"],
                "tool": "metasploit",
            },
        }
    )
    request_text = _metasploit_request_text().replace("target=example.com", "target=127.0.0.1")
    message = SimpleNamespace(text=request_text, reply_text=AsyncMock())

    asyncio.run(
        scan_target_handler(
            SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7312)),
            context,
        )
    )

    assert message.reply_text.call_args.args[0] == (
        "Metasploit target is not part of this assessment's known target/assets. "
        "Add it explicitly or run standalone."
    )
    assert not _metasploit_pending_context
    assert list_assessment_scans(assessment["id"]) == []


def test_standalone_metasploit_allows_unrelated_authorized_target() -> None:
    clear_user_scan_requests(7313)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    scan_request = create_scan_request(user_id=7313, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=7313, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    request_text = _metasploit_request_text().replace("target=example.com", "target=127.0.0.1")
    message = SimpleNamespace(text=request_text, reply_text=AsyncMock())

    asyncio.run(
        scan_target_handler(
            SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7313)),
            context,
        )
    )

    assert "Metasploit Validation Proposal" in message.reply_text.call_args.args[0]
    assert "Target: 127.0.0.1" in message.reply_text.call_args.args[0]


def test_metasploit_details_callback_shows_exact_proposal() -> None:
    clear_user_scan_requests(7310)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    scan_request = create_scan_request(user_id=7310, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=7310, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text=_metasploit_request_text(), reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7310))
    asyncio.run(scan_target_handler(update, context))
    proposal_id = next(iter(_metasploit_pending_context))
    query = SimpleNamespace(data=f"msf:details:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=message)
    callback_update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7310))

    asyncio.run(scan_callback_handler(callback_update, context))

    details = query.edit_message_text.call_args.args[0]
    assert "Metasploit Validation Proposal Details" in details
    assert f"Proposal ID: {proposal_id}" in details
    assert "Module:\nauxiliary/scanner/http/http_version" in details
    assert "Action:\nauxiliary_validation" in details
    assert "This action WILL:" in details
    assert "This action WILL NOT:" in details
    assert "Target:\nexample.com" in details
    assert "Target: example.com" in details
    assert "Port: 80" in details
    assert "Expires:" in details
    assert "Approval status: proposed" in details


def test_metasploit_details_callback_handles_message_not_modified() -> None:
    clear_user_scan_requests(7311)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    scan_request = create_scan_request(user_id=7311, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=7311, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text=_metasploit_request_text(), reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7311))
    asyncio.run(scan_target_handler(update, context))
    proposal_id = next(iter(_metasploit_pending_context))
    query = SimpleNamespace(
        data=f"msf:details:{proposal_id}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(side_effect=BadRequest("Message is not modified")),
        message=message,
    )
    callback_update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7311))

    asyncio.run(scan_callback_handler(callback_update, context))

    assert query.answer.call_args_list[-1].args[0] == "Proposal details are already shown."


def test_metasploit_invalid_raw_command_rejected() -> None:
    clear_user_scan_requests(7302)
    scan_request = create_scan_request(user_id=7302, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=7302, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="use exploit/windows/smb/psexec\nrun", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7302))

    asyncio.run(scan_target_handler(update, context))

    assert "Raw msfconsole commands are not accepted" in message.reply_text.call_args.args[0]


def test_metasploit_unknown_module_and_unapproved_option_rejected() -> None:
    clear_user_scan_requests(7303)
    for text in (
        "module=auxiliary/scanner/unknown\naction=auxiliary_validation\ntarget=example.com\nport=80",
        _metasploit_request_text() + "\noption.CMD=id",
    ):
        scan_request = create_scan_request(user_id=7303, scan_type="metasploit")
        mark_scan_request_awaiting_target(user_id=7303, scan_request_id=scan_request.id)
        context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
        message = SimpleNamespace(text=text, reply_text=AsyncMock())
        update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7303))

        asyncio.run(scan_target_handler(update, context))

        assert "Invalid Metasploit validation request" in message.reply_text.call_args.args[0]


def test_metasploit_reject_does_not_execute() -> None:
    clear_user_scan_requests(7304)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    scan_request = create_scan_request(user_id=7304, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=7304, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text=_metasploit_request_text(), reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7304))
    asyncio.run(scan_target_handler(update, context))
    proposal_id = next(iter(_metasploit_pending_context))
    query = SimpleNamespace(data=f"msf:reject:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=message)
    callback_update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7304))

    with patch("app.bot.handlers.scan.run_metasploit_validation") as runner_mock:
        asyncio.run(scan_callback_handler(callback_update, context))

    runner_mock.assert_not_called()
    assert "rejected" in query.edit_message_text.call_args.args[0]


def test_metasploit_wrong_user_approval_denied() -> None:
    clear_user_scan_requests(7305)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    scan_request = create_scan_request(user_id=7305, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=7305, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text=_metasploit_request_text(), reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7305))
    asyncio.run(scan_target_handler(update, context))
    proposal_id = next(iter(_metasploit_pending_context))
    query = SimpleNamespace(data=f"msf:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=message)
    callback_update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9999))

    with patch("app.bot.handlers.scan.run_metasploit_validation") as runner_mock:
        asyncio.run(scan_callback_handler(callback_update, context))

    runner_mock.assert_not_called()
    assert "approval denied" in query.edit_message_text.call_args.args[0].lower()


def test_metasploit_approve_executes_and_stores_evidence() -> None:
    clear_user_findings(7306)
    clear_user_scan_requests(7306)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    scan_request = create_scan_request(user_id=7306, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=7306, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text=_metasploit_request_text(), reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7306))
    asyncio.run(scan_target_handler(update, context))
    proposal_id = next(iter(_metasploit_pending_context))
    query = SimpleNamespace(data=f"msf:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=message)
    callback_update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7306))
    result = {
        "success": True,
        "module": "auxiliary/scanner/http/http_version",
        "action_type": "auxiliary_validation",
        "target": "example.com",
        "port": 80,
        "output": "The target appears vulnerable.",
        "error": "",
        "elapsed_seconds": 2,
        "returncode": 0,
    }

    with (
        patch("app.bot.handlers.scan.run_metasploit_validation", return_value=result) as runner_mock,
        patch("app.bot.handlers.scan.generate_metasploit_ai_assessment", return_value=["Executive Summary", "- Metasploit evidence reviewed."]) as ai_mock,
    ):
        asyncio.run(scan_callback_handler(callback_update, context))

    runner_mock.assert_called_once()
    runner_kwargs = runner_mock.call_args.kwargs
    assert runner_kwargs["user_id"] == 7306
    assert runner_kwargs["proposal_id"] == proposal_id
    assert runner_kwargs["request"]["module"] == "auxiliary/scanner/http/http_version"
    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert any("Metasploit Validation" in text and "VALIDATED" in text for text in sent_messages)
    assert "Generating Metasploit AI assessment..." in sent_messages
    assert any("Metasploit AI Assessment" in text for text in sent_messages)
    ai_mock.assert_called_once()
    finding = get_user_findings(7306)[0]
    assert finding["source"] == "metasploit"
    assert finding["metasploit_evidence"]["validation_state"] == "VALIDATED"
    assert "not proof of full compromise" in finding["metasploit_evidence"]["summary"]
    assert finding["metadata"]["artifact_ref"] == "finding.raw_output"
    assert finding["raw_output"] == "The target appears vulnerable."


def test_metasploit_assessment_context_records_artifact_and_scan(tmp_path) -> None:
    clear_user_findings(7307)
    clear_user_scan_requests(7307)
    clear_metasploit_proposals()
    _metasploit_pending_context.clear()
    assessment = create_assessment("Metasploit Assessment")
    target = add_assessment_target(assessment["id"], address="example.com")
    scan_request = create_scan_request(user_id=7307, scan_type="metasploit")
    mark_scan_request_awaiting_target(user_id=7307, scan_request_id=scan_request.id)
    context = SimpleNamespace(
        user_data={
            PENDING_NMAP_REQUEST_KEY: scan_request.id,
            ASSESSMENT_SCAN_CONTEXT_KEY: {"assessment_id": assessment["id"], "target_id": target["id"], "tool": "metasploit"},
        }
    )
    message = SimpleNamespace(text=_metasploit_request_text(), reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7307))
    asyncio.run(scan_target_handler(update, context))
    proposal_id = next(iter(_metasploit_pending_context))
    query = SimpleNamespace(data=f"msf:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=message)
    callback_update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7307))
    result = {
        "success": True,
        "module": "auxiliary/scanner/http/http_version",
        "action_type": "auxiliary_validation",
        "target": "example.com",
        "port": 80,
        "output": "The target does not appear to be vulnerable.",
        "error": "",
        "elapsed_seconds": 1,
        "returncode": 0,
    }

    with (
        patch("app.bot.handlers.scan.run_metasploit_validation", return_value=result),
        patch("app.bot.handlers.scan.generate_metasploit_ai_assessment", return_value=["Executive Summary", "- Metasploit evidence reviewed."]),
    ):
        asyncio.run(scan_callback_handler(callback_update, context))

    scans = list_assessment_scans(assessment["id"])
    artifacts = list_assessment_artifacts(assessment["id"])
    dashboard = build_assessment_dashboard_text(assessment, [target], scans)
    assessment_context = build_assessment_context(assessment["id"], user_id=7307)
    guard = build_assessment_guard(assessment_context)
    finding = get_user_findings(7307)[0]
    assert scans[0]["tool"] == "metasploit"
    assert scans[0]["status"] == "completed"
    assert "Metasploit: Completed" in dashboard
    assert artifacts[0]["artifact_type"] == "metasploit_raw_output"
    assert finding["metadata"]["artifact_ref"].startswith("assessment_artifact:")
    assert finding["metasploit_evidence"]["validation_state"] == "NOT_REPRODUCED"
    assert "not proof that the target is secure" in finding["metasploit_evidence"]["summary"]
    assert assessment_context["findings"][0]["source"] == "metasploit"
    assert "metasploit" in guard["completed_tools"]
    assert "Metasploit validation not run" not in guard["locked_tool_limitations"]


def test_metasploit_ai_no_evidence_path_does_not_invent_findings() -> None:
    message = SimpleNamespace(reply_text=AsyncMock())

    asyncio.run(_send_metasploit_ai_assessment(message, {"source": "metasploit"}))

    assert message.reply_text.call_args.args[0] == "No normalized Metasploit validation evidence was available from this run."


def test_httpx_result_card_summarizes_observations_without_raw_json() -> None:
    result = {"success": True, "target": "https://example.com", "elapsed_seconds": 2, "output": '{"url":"raw"}'}
    services = [
        {
            "url": "https://example.com",
            "status_code": 301,
            "title": "Example",
            "technologies": ["nginx"],
            "redirect_location": "https://www.example.com",
            "content_type": "text/html",
            "ip": "93.184.216.34",
            "cdn": True,
            "cname": ["edge.example.net"],
            "tls": {"probe": True},
        },
        {"url": "https://www.example.com", "status_code": 200, "title": "Home", "technologies": ["React"]},
    ]

    card = build_httpx_result_text(result, services)

    assert "httpx Scan Complete" in card
    assert "HTTP services/URLs observed: 2" in card
    assert "Status codes: 200: 1, 301: 1" in card
    assert "Titles: https://example.com: Example" in card
    assert "Technologies: nginx, React" in card
    assert "Content types: text/html" in card
    assert "Metadata: IPs: 1, CDN observations: 1, CNAME observations: 1, TLS/certificate metadata: 1" in card
    assert "Redirects: https://example.com -> https://www.example.com" in card
    assert "not vulnerability findings" in card
    assert '{"url":"raw"}' not in card


def test_httpx_scan_starts_timer_stops_on_success_and_renders_result() -> None:
    clear_user_findings(7230)
    clear_user_investigations(7230)
    clear_user_scan_requests(7230)
    scan_request = create_scan_request(user_id=7230, scan_type="httpx")
    mark_scan_request_awaiting_target(user_id=7230, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7230))

    with (
        patch(
            "app.bot.handlers.scan.run_httpx_scan",
            return_value={
                "success": True,
                "target": "https://example.com",
                "output": '{"url":"https://example.com","status_code":200,"title":"Example"}',
                "error": "",
                "returncode": 0,
                "elapsed_seconds": 40,
            },
        ),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock) as start_auto_refresh,
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock) as stop_auto_refresh,
        patch("app.bot.handlers.scan._send_httpx_ai_assessment", new_callable=AsyncMock),
    ):
        asyncio.run(scan_target_handler(update, context))

    start_auto_refresh.assert_awaited_once_with("Running scan...", interval_seconds=5)
    assert stop_auto_refresh.await_count >= 1
    final_progress_text = status_message.edit_text.call_args_list[-1].args[0]
    assert "Status\nComplete" in final_progress_text
    assert "Elapsed\n40s" in final_progress_text
    result_text = message.reply_text.call_args_list[1].args[0]
    assert "httpx Scan Complete" in result_text
    assert "Time\n40s" in result_text


def test_httpx_scan_timer_stops_on_failure_and_renders_failed_result() -> None:
    clear_user_findings(7231)
    clear_user_investigations(7231)
    clear_user_scan_requests(7231)
    scan_request = create_scan_request(user_id=7231, scan_type="httpx")
    mark_scan_request_awaiting_target(user_id=7231, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7231))

    with (
        patch(
            "app.bot.handlers.scan.run_httpx_scan",
            return_value={
                "success": False,
                "target": "https://example.com",
                "output": "",
                "error": "httpx timed out.",
                "returncode": -9,
                "elapsed_seconds": 13,
            },
        ),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock) as start_auto_refresh,
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock) as stop_auto_refresh,
        patch("app.bot.handlers.scan._send_httpx_ai_assessment", new_callable=AsyncMock) as send_ai,
    ):
        asyncio.run(scan_target_handler(update, context))

    start_auto_refresh.assert_awaited_once_with("Running scan...", interval_seconds=5)
    assert stop_auto_refresh.await_count >= 1
    send_ai.assert_not_awaited()
    final_progress_text = status_message.edit_text.call_args_list[-1].args[0]
    assert "Status\nFailed: httpx timed out." in final_progress_text
    assert "Elapsed\n13s" in final_progress_text
    assert "httpx Scan Complete" in message.reply_text.call_args_list[1].args[0]
    assert "Status\nFailed" in message.reply_text.call_args_list[1].args[0]


def test_httpx_scan_timer_stops_on_runner_exception() -> None:
    clear_user_findings(7232)
    clear_user_investigations(7232)
    clear_user_scan_requests(7232)
    scan_request = create_scan_request(user_id=7232, scan_type="httpx")
    mark_scan_request_awaiting_target(user_id=7232, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7232))

    with (
        patch("app.bot.handlers.scan.run_httpx_scan", side_effect=ValueError("bad httpx target")),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock) as start_auto_refresh,
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock) as stop_auto_refresh,
    ):
        asyncio.run(scan_target_handler(update, context))

    start_auto_refresh.assert_awaited_once_with("Running scan...", interval_seconds=5)
    assert stop_auto_refresh.await_count >= 1
    assert "Status\nFailed: bad httpx target" in status_message.edit_text.call_args_list[-1].args[0]
    assert message.reply_text.call_args_list[1].args[0] == "Invalid httpx target: bad httpx target"


def test_playwright_result_card_summarizes_observation_without_raw_details() -> None:
    result = {"success": True, "target": "https://example.com", "elapsed_seconds": 3, "output": {"raw": "not shown"}}
    observation = {
        "requested_url": "https://example.com",
        "final_url": "https://www.example.com",
        "title": "Example",
        "load_status": "loaded",
        "status_code": 200,
        "forms_count": 1,
        "inputs_count": 4,
        "links_count": 12,
        "console_issue_count": 2,
        "network_issue_count": 1,
        "page_error_count": 0,
        "link_samples": ["https://www.example.com/about"],
        "limitations": ["Passive browser observation only."],
    }

    card = build_playwright_result_text(result, observation)

    assert "Playwright Scan Complete" in card
    assert "Final URL: https://www.example.com" in card
    assert "Title: Example" in card
    assert "Load status: loaded" in card
    assert "Status code: 200" in card
    assert "Forms/inputs: 1 forms / 4 inputs" in card
    assert "Links: 12" in card
    assert "Console/network issues: 2 console / 1 network / 0 page errors" in card
    assert "Screenshot/artifact: not captured" in card
    assert "Passive browser observation only." in card
    assert "raw" not in card


def test_katana_result_card_summarizes_observations_without_raw_json() -> None:
    result = {"success": True, "target": "https://example.com", "elapsed_seconds": 2, "output": '{"url":"raw"}'}
    observations = [
        {
            "url": "https://example.com/app.js",
            "host": "example.com",
            "endpoint_type": "javascript",
            "depth": 1,
        },
        {
            "url": "https://example.com/search?q=test",
            "host": "example.com",
            "endpoint_type": "parameterized_url",
            "query_parameters": ["q"],
            "depth": 2,
            "forms": [{"action": "/login", "method": "POST"}],
        },
    ]

    card = build_katana_result_text(result, observations)

    assert "Katana Scan Complete" in card
    assert "URLs/endpoints discovered: 2" in card
    assert "Unique hosts: 1" in card
    assert "JavaScript files: 1" in card
    assert "Query parameters: 1" in card
    assert "Forms/actions: 1" in card
    assert "Max observed crawl depth: 2" in card
    assert "Observed parameters: q" in card
    assert "JavaScript: https://example.com/app.js" in card
    assert '{"url":"raw"}' not in card


def test_katana_scan_failure_uses_sanitized_runner_error() -> None:
    clear_user_findings(7240)
    clear_user_investigations(7240)
    clear_user_scan_requests(7240)
    scan_request = create_scan_request(user_id=7240, scan_type="katana")
    mark_scan_request_awaiting_target(user_id=7240, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7240))
    diagnostic = 'invalid value "robotstxt,sitemapxml" for flag -kf: allowed values are all, robotstxt, sitemapxml'

    with (
        patch(
            "app.bot.handlers.scan.run_katana_scan",
            return_value={
                "success": False,
                "target": "https://example.com",
                "output": "",
                "error": diagnostic,
                "returncode": 2,
                "elapsed_seconds": 0.08,
            },
        ),
        patch("app.bot.handlers.scan.generate_katana_ai_assessment") as generate_katana_ai_assessment,
    ):
        asyncio.run(scan_target_handler(update, context))

    generate_katana_ai_assessment.assert_not_called()
    progress_text = status_message.edit_text.call_args_list[-1].args[0]
    result_text = message.reply_text.call_args_list[1].args[0]
    assert diagnostic in progress_text
    assert diagnostic in result_text
    assert "Unknown error" not in progress_text
    assert "Unknown error" not in result_text


def test_ffuf_result_card_summarizes_observations_without_raw_json() -> None:
    result = {
        "success": True,
        "target": "https://example.com",
        "elapsed_seconds": 2,
        "output": '{"results":[{"url":"raw"}]}',
        "wordlist_count": 19,
        "wordlist_path": "app/resources/wordlists/ffuf_default.txt",
    }
    observations = [
        {"url": "https://example.com/admin", "path": "/admin", "status_code": 200, "classification": "public"},
        {
            "url": "https://example.com/login",
            "path": "/login",
            "status_code": 302,
            "redirect_location": "https://example.com/sso",
            "classification": "redirect",
        },
        {"url": "https://example.com/config", "path": "/config", "status_code": 403, "classification": "forbidden"},
    ]

    card = build_ffuf_result_text(result, observations)

    assert "ffuf Scan Complete" in card
    assert "Wordlist entries: 19" in card
    assert "Discovered paths: 3" in card
    assert "Status codes: 200: 1, 302: 1, 403: 1" in card
    assert "Interesting paths: /admin; /login; /config" in card
    assert "Redirects: /login -> https://example.com/sso" in card
    assert "Forbidden/auth-gated responses: 1" in card
    assert '{"results"' not in card


def test_store_httpx_scan_result_persists_structured_evidence() -> None:
    clear_user_findings(7204)
    services = [{"url": "https://example.com", "status_code": 200, "title": "Example", "technologies": ["nginx"]}]

    finding = store_httpx_scan_result(
        user_id=7204,
        result={"success": True, "target": "https://example.com", "output": "{}", "elapsed_seconds": 1, "returncode": 0},
        services=services,
    )

    stored = get_user_findings(7204)[0]
    assert finding["source"] == "httpx"
    assert stored["httpx_services"] == services
    assert stored["httpx_summary"]["status_codes"] == {"200": 1}


def test_store_katana_scan_result_persists_structured_evidence() -> None:
    clear_user_findings(7206)
    observations = [{"url": "https://example.com/search?q=test", "host": "example.com", "query_parameters": ["q"], "depth": 2}]

    finding = store_katana_scan_result(
        user_id=7206,
        result={
            "success": True,
            "target": "https://example.com",
            "output": "{}",
            "elapsed_seconds": 1,
            "returncode": 0,
            "command": ["katana", "-u", "https://example.com", "-d", "2"],
        },
        observations=observations,
    )

    stored = get_user_findings(7206)[0]
    assert finding["source"] == "katana"
    assert stored["katana_observations"] == observations
    assert stored["katana_summary"]["query_parameters"] == ["q"]


def test_store_playwright_scan_result_persists_structured_evidence() -> None:
    clear_user_findings(7208)
    observation = {
        "requested_url": "https://example.com",
        "final_url": "https://www.example.com",
        "title": "Example",
        "load_status": "loaded",
        "forms_count": 1,
        "inputs_count": 3,
        "links_count": 8,
    }

    finding = store_playwright_scan_result(
        user_id=7208,
        result={"success": True, "target": "https://example.com", "output": observation, "elapsed_seconds": 1},
        observation=observation,
    )

    stored = get_user_findings(7208)[0]
    assert finding["source"] == "playwright"
    assert stored["playwright_observation"]["title"] == "Example"
    assert stored["playwright_summary"]["links_count"] == 8


def test_store_ffuf_scan_result_persists_structured_evidence() -> None:
    clear_user_findings(7209)
    observations = [{"url": "https://example.com/admin", "path": "/admin", "status_code": 200, "classification": "public"}]

    finding = store_ffuf_scan_result(
        user_id=7209,
        result={
            "success": True,
            "target": "https://example.com",
            "output": "{}",
            "elapsed_seconds": 1,
            "returncode": 0,
            "command": ["ffuf", "-u", "https://example.com/FUZZ"],
            "wordlist_count": 19,
            "wordlist_path": "app/resources/wordlists/ffuf_default.txt",
            "fuzz_url": "https://example.com/FUZZ",
        },
        observations=observations,
    )

    stored = get_user_findings(7209)[0]
    assert finding["source"] == "ffuf"
    assert stored["ffuf_results"] == observations
    assert stored["ffuf_summary"]["status_codes"] == {"200": 1}
    assert stored["metadata"]["wordlist_count"] == 19


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
        patch(
            "app.bot.handlers.scan.generate_bbot_ai_assessment",
            return_value=["Executive Summary", "- BBOT observations were reviewed."],
        ),
    ):
        asyncio.run(scan_target_handler(update, context))

    run_bbot_scan.assert_called_once_with("https://example.com")
    assert message.reply_text.call_args_list[0].args[0] == (
        f" BBOT Scan\n\n{icon('target')} Target\nexample.com\n\n"
        f"{icon('running')} Status\nLaunching scan...\n\n{icon('elapsed')} Elapsed\n0s"
    )
    assert "BBOT Recon" in message.reply_text.call_args_list[1].args[0]
    assert "Recon Overview" in message.reply_text.call_args_list[1].args[0]
    assert "subdomains" in message.reply_text.call_args_list[1].args[0]
    assert "1 URLs" in message.reply_text.call_args_list[1].args[0]
    assert "Recommended Next Actions" in message.reply_text.call_args_list[1].args[0]
    keyboard = message.reply_text.call_args_list[1].kwargs["reply_markup"]
    assert keyboard.inline_keyboard[0][0].text == "AI Summary"
    assert keyboard.inline_keyboard[0][0].callback_data.startswith("ai_summary:bbot:")
    assert keyboard.inline_keyboard[1][0].text == "Generate AI Recon Assessment"
    assert keyboard.inline_keyboard[1][0].callback_data.startswith("bbot_ai:")
    assert len(keyboard.inline_keyboard[1][0].callback_data) <= 64
    assert keyboard.inline_keyboard[1][0].callback_data.count(":") == 1
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
    assert [event["event_type"] for event in events] == ["bbot_scan_started", "bbot_scan_completed", "bbot_ai_assessment_generated"]
    assert "Recon Summary Generated" in events[1]["summary"]
    observations = get_investigation_observations(investigation["id"], 7202)
    assert observations
    assert get_user_observations(7202) == observations
    assert context.user_data == {}


def test_bbot_scan_json_output_populates_observation_store_and_summary() -> None:
    clear_user_findings(7220)
    clear_user_investigations(7220)
    clear_user_observations(7220)
    clear_user_scan_requests(7220)
    scan_request = create_scan_request(user_id=7220, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7220, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7220))
    result = {
        "success": True,
        "target": "example.com",
        "output": '{"type":"DNS_NAME","data":"app.example.com"}',
        "error": "",
        "returncode": 0,
        "elapsed_seconds": 19.0,
        "output_dir": "data/bbot/example.com",
        "json_output_found": True,
        "json_output_paths": ["data/bbot/example.com/scan/output/output.jsonl"],
    }

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=True),
        patch("app.bot.handlers.scan.run_bbot_scan", return_value=result),
    ):
        asyncio.run(scan_target_handler(update, context))

    observations = get_user_observations(7220)
    assert len(observations) == 1
    assert observations[0]["observation_type"] == "subdomain"
    assert observations[0]["value"] == "app.example.com"
    summary_text = message.reply_text.call_args_list[1].args[0]
    assert "Observations Collected: 1" in summary_text
    assert "1 subdomains" in summary_text
    assert "app.example.com" in summary_text


def test_bbot_ai_assessment_keyboard_exists() -> None:
    keyboard = build_bbot_ai_assessment_keyboard("investigation-1", "finding-1", user_id=7210)

    assert keyboard is not None
    assert keyboard.inline_keyboard[0][0].text == "Generate AI Recon Assessment"
    callback_data = keyboard.inline_keyboard[0][0].callback_data
    assert callback_data.startswith("bbot_ai:")
    assert len(callback_data) <= 64
    assert callback_data.count(":") == 1


def test_bbot_ai_assessment_callback_success_sends_assessment_and_timeline_event() -> None:
    clear_user_investigations(7210)
    clear_user_observations(7210)
    clear_user_findings(7210)
    investigation = create_investigation(user_id=7210, target="example.com")
    old_finding = add_finding(
        user_id=7210,
        finding={
            "source": "bbot",
            "target": "example.com",
            "risk_level": "info",
            "finding_count": 1,
            "status": "completed",
            "summary": "Old BBOT evidence.",
            "observations": [{"source": "bbot", "observation_type": "subdomain", "value": "old.example.com", "target": "example.com"}],
        },
    )
    finding = add_finding(
        user_id=7210,
        finding={
            "source": "bbot",
            "target": "example.com",
            "risk_level": "info",
            "finding_count": 1,
            "status": "completed",
            "summary": "Current BBOT evidence.",
            "observations": [{"source": "bbot", "observation_type": "subdomain", "value": "admin.example.com", "target": "example.com"}],
        },
    )
    keyboard = build_bbot_ai_assessment_keyboard(investigation["id"], finding["id"], user_id=7210)
    progress_message = SimpleNamespace(edit_text=AsyncMock())
    query_message = SimpleNamespace(reply_text=AsyncMock(side_effect=[progress_message, None]))
    query = SimpleNamespace(
        data=keyboard.inline_keyboard[0][0].callback_data,
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7210))

    def assert_current_finding_context(*args, **kwargs):
        assert old_finding["id"] != finding["id"]
        observations = kwargs["observations"]
        assert [observation["value"] for observation in observations] == ["admin.example.com"]
        assert "admin.example.com" in kwargs["recon_summary"]
        assert "old.example.com" not in kwargs["recon_summary"]
        return ["Executive Summary", "- Admin host observed.", "", "Confidence:", "Medium"]

    with patch(
        "app.bot.handlers.scan.generate_bbot_ai_assessment",
        side_effect=assert_current_finding_context,
    ):
        asyncio.run(scan_callback_handler(update, SimpleNamespace(user_data={})))

    query.answer.assert_called_once()
    query.edit_message_text.assert_not_called()
    assert query_message.reply_text.call_args_list[0].args[0] == "Generating AI Recon Assessment /"
    assert "BBOT AI Assessment" in query_message.reply_text.call_args_list[-1].args[0]
    assert "Executive Summary\n- Admin host observed." in query_message.reply_text.call_args_list[-1].args[0]
    assert "Confidence\nMedium" in query_message.reply_text.call_args_list[-1].args[0]
    assert progress_message.edit_text.call_args_list[-1].args[0] == "AI Recon Assessment ready."
    events = get_investigation_events(investigation["id"], 7210)
    assert events[-1]["event_type"] == "bbot_ai_assessment_generated"
    assert events[-1]["summary"] == "BBOT AI Recon Assessment Generated"


def test_bbot_ai_assessment_callback_failure_sends_fallback_and_timeline_event() -> None:
    clear_user_investigations(7211)
    clear_user_observations(7211)
    clear_user_findings(7211)
    investigation = create_investigation(user_id=7211, target="example.com")
    finding = add_finding(
        user_id=7211,
        finding={
            "source": "bbot",
            "target": "example.com",
            "risk_level": "info",
            "finding_count": 1,
            "status": "completed",
            "summary": "Current BBOT evidence.",
            "observations": [{"source": "bbot", "observation_type": "subdomain", "value": "app.example.com", "target": "example.com"}],
        },
    )
    keyboard = build_bbot_ai_assessment_keyboard(investigation["id"], finding["id"], user_id=7211)
    progress_message = SimpleNamespace(edit_text=AsyncMock())
    query_message = SimpleNamespace(reply_text=AsyncMock(side_effect=[progress_message, None]))
    query = SimpleNamespace(
        data=keyboard.inline_keyboard[0][0].callback_data,
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7211))

    with patch("app.bot.handlers.scan.generate_bbot_ai_assessment", return_value=FALLBACK_LINES):
        asyncio.run(scan_callback_handler(update, SimpleNamespace(user_data={})))

    query.edit_message_text.assert_not_called()
    assert query_message.reply_text.call_args_list[0].args[0] == "Generating AI Recon Assessment /"
    assert query_message.reply_text.call_args_list[-1].args[0] == "\n".join(FALLBACK_LINES)
    assert progress_message.edit_text.call_args_list[-1].args[0] == "AI Recon Assessment unavailable."
    events = get_investigation_events(investigation["id"], 7211)
    assert events[-1]["event_type"] == "bbot_ai_assessment_fallback"
    assert events[-1]["summary"] == "BBOT AI Recon Assessment Fallback"


def test_bbot_ai_assessment_callback_chunks_response() -> None:
    clear_user_investigations(7212)
    clear_user_findings(7212)
    investigation = create_investigation(user_id=7212, target="example.com")
    finding = add_finding(
        user_id=7212,
        finding={
            "source": "bbot",
            "target": "example.com",
            "risk_level": "info",
            "finding_count": 1,
            "status": "completed",
            "summary": "Current BBOT evidence.",
            "observations": [{"source": "bbot", "observation_type": "subdomain", "value": "app.example.com", "target": "example.com"}],
        },
    )
    keyboard = build_bbot_ai_assessment_keyboard(investigation["id"], finding["id"], user_id=7212)
    progress_message = SimpleNamespace(edit_text=AsyncMock())
    query_message = SimpleNamespace(reply_text=AsyncMock(side_effect=[progress_message, None, None]))
    query = SimpleNamespace(
        data=keyboard.inline_keyboard[0][0].callback_data,
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7212))

    assessment_lines = ["AI Recon Assessment", "Confidence:", "LOW"]
    with (
        patch("app.bot.handlers.scan.generate_bbot_ai_assessment", return_value=assessment_lines),
        patch("app.bot.handlers.scan.split_report_text", return_value=["chunk one", "chunk two"]) as splitter,
    ):
        asyncio.run(scan_callback_handler(update, SimpleNamespace(user_data={})))

    split_input = splitter.call_args.args[0]
    assert "BBOT AI Assessment" in split_input
    assert "Confidence\nLOW" in split_input
    assert [call.args[0] for call in query_message.reply_text.call_args_list] == [
        "Generating AI Recon Assessment /",
        "chunk one",
        "chunk two",
    ]


def test_bbot_ai_assessment_callback_invalid_token_rejected_safely() -> None:
    query = SimpleNamespace(
        data="bbot_ai:missing-token",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7214))

    with patch("app.bot.handlers.scan.generate_bbot_ai_assessment") as generate_bbot_ai_assessment:
        asyncio.run(scan_callback_handler(update, SimpleNamespace(user_data={})))

    generate_bbot_ai_assessment.assert_not_called()
    query.edit_message_text.assert_called_once_with("Stored BBOT AI request was not found or has expired.")


def test_bbot_ai_assessment_callback_cross_user_token_rejected() -> None:
    clear_user_investigations(7215)
    clear_user_findings(7215)
    investigation = create_investigation(user_id=7215, target="example.com")
    finding = add_finding(
        user_id=7215,
        finding={
            "source": "bbot",
            "target": "example.com",
            "risk_level": "info",
            "finding_count": 1,
            "status": "completed",
            "summary": "Current BBOT evidence.",
            "observations": [{"source": "bbot", "observation_type": "subdomain", "value": "app.example.com", "target": "example.com"}],
        },
    )
    keyboard = build_bbot_ai_assessment_keyboard(investigation["id"], finding["id"], user_id=7215)
    query = SimpleNamespace(
        data=keyboard.inline_keyboard[0][0].callback_data,
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=9999))

    with patch("app.bot.handlers.scan.generate_bbot_ai_assessment") as generate_bbot_ai_assessment:
        asyncio.run(scan_callback_handler(update, SimpleNamespace(user_data={})))

    generate_bbot_ai_assessment.assert_not_called()
    query.edit_message_text.assert_called_once_with("Stored BBOT AI request was not found or has expired.")


def test_scan_ai_summary_callback_sends_new_summary_message() -> None:
    clear_user_findings(7213)
    finding = add_finding(
        user_id=7213,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "medium",
            "finding_count": 1,
            "status": "completed",
            "summary": "One open SSH service.",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )
    progress_message = SimpleNamespace(edit_text=AsyncMock())
    query_message = SimpleNamespace(reply_text=AsyncMock(side_effect=[progress_message, None]))
    query = SimpleNamespace(
        data=f"ai_summary:nmap:{finding['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7213))
    summary_lines = [
        "Executive Summary",
        "- SSH was observed.",
        "",
        "Observed Facts",
        "- 22/tcp ssh",
        "",
        "Observed Assets",
        "- 127.0.0.1",
        "",
        "Potential Risks",
        "- Public-facing services should be validated.",
        "",
        "Confidence",
        "Medium",
        "",
        "Recommended Next Actions",
        "- Validate externally exposed services.",
    ]

    with patch("app.bot.handlers.scan.generate_scan_ai_summary", return_value=summary_lines):
        asyncio.run(scan_callback_handler(update, SimpleNamespace(user_data={})))

    query.answer.assert_called_once()
    query.edit_message_text.assert_not_called()
    assert query_message.reply_text.call_args_list[0].args[0] == "Generating AI summary..."
    assert query_message.reply_text.call_args_list[1].args[0] == render_ai_summary_card(summary_lines)
    assert progress_message.edit_text.call_args_list[-1].args[0] == "AI summary ready."


def test_scan_ai_summary_callback_missing_finding_edits_callback_message() -> None:
    query = SimpleNamespace(
        data="ai_summary:nmap:missing",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(reply_text=AsyncMock()),
    )
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=7214))

    asyncio.run(scan_callback_handler(update, SimpleNamespace(user_data={})))

    query.edit_message_text.assert_called_once_with("Stored scan result not found.")


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
        patch("app.bot.handlers.scan.generate_bbot_ai_assessment") as generate_bbot_ai_assessment,
    ):
        asyncio.run(scan_target_handler(update, context))

    generate_bbot_ai_assessment.assert_not_called()
    assert "Status\nFailed" in message.reply_text.call_args_list[1].args[0]
    finding = get_user_findings(7204)[0]
    assert finding["source"] == "bbot"
    assert finding["status"] == "failed"
    assert finding["summary"] == "BBOT recon failed."
    investigation = get_user_investigations(7204)[0]
    events = get_investigation_events(investigation["id"], 7204)
    assert [event["event_type"] for event in events] == ["bbot_scan_started", "bbot_scan_failed"]


def test_bbot_scan_nonzero_with_observations_is_partial_and_clean() -> None:
    clear_user_findings(7205)
    clear_user_investigations(7205)
    clear_user_observations(7205)
    clear_user_scan_requests(7205)
    scan_request = create_scan_request(user_id=7205, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7205, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7205))
    raw_output = "NOISY BBOT STDOUT\n{\"type\":\"DNS_NAME\",\"data\":\"app.example.com\"}"

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=True),
        patch(
            "app.bot.handlers.scan.run_bbot_scan",
            return_value={
                "success": False,
                "target": "example.com",
                "output": raw_output,
                "error": "BBOT exited with code 1",
                "returncode": 1,
                "elapsed_seconds": 7,
            },
        ),
        patch(
            "app.bot.handlers.scan.generate_bbot_ai_assessment",
            return_value=["Executive Summary", "- Partial BBOT observations were reviewed."],
        ),
    ):
        asyncio.run(scan_target_handler(update, context))

    result_text = message.reply_text.call_args_list[1].args[0]
    assert "Status\nPartial" in result_text
    assert "BBOT Recon Summary" in result_text
    assert "app.example.com" in result_text
    assert "Partial result:" in result_text
    assert "NOISY BBOT STDOUT" not in result_text
    assert "BBOT exited with code 1" not in result_text
    keyboard = message.reply_text.call_args_list[1].kwargs["reply_markup"]
    assert keyboard.inline_keyboard[1][0].text == "Generate AI Recon Assessment"
    assert len(keyboard.inline_keyboard[1][0].callback_data) <= 64
    finding = get_user_findings(7205)[0]
    assert finding["status"] == "partial"
    assert finding["raw_output"] == raw_output
    assert finding["metadata"]["partial"] is True
    assert finding["finding_count"] == 1
    observations = get_user_observations(7205)
    assert len(observations) == 1
    assert observations[0]["value"] == "app.example.com"
    investigation = get_user_investigations(7205)[0]
    events = get_investigation_events(investigation["id"], 7205)
    assert [event["event_type"] for event in events] == ["bbot_scan_started", "bbot_scan_partial", "bbot_ai_assessment_generated"]


def test_bbot_scan_starts_and_stops_progress_auto_refresh() -> None:
    clear_user_findings(7208)
    clear_user_investigations(7208)
    clear_user_observations(7208)
    clear_user_scan_requests(7208)
    scan_request = create_scan_request(user_id=7208, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7208, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7208))

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
                "elapsed_seconds": 3,
            },
        ),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock) as start_auto_refresh,
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock) as stop_auto_refresh,
    ):
        asyncio.run(scan_target_handler(update, context))

    start_auto_refresh.assert_awaited_once_with("Launching scan...", interval_seconds=5)
    assert stop_auto_refresh.await_count >= 1


def test_assessment_bbot_partial_scan_records_partial_status() -> None:
    clear_user_findings(8124)
    clear_user_investigations(8124)
    clear_user_observations(8124)
    assessment = create_assessment("Assessment BBOT Partial")
    target = add_assessment_target(assessment["id"], address="example.com")
    query_message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=f"assessment:run:bbot:{assessment['id']}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=query_message,
    )

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=True),
        patch(
            "app.bot.handlers.scan.run_bbot_scan",
            return_value={
                "success": False,
                "target": "example.com",
                "output": '{"type":"DNS_NAME","data":"partial.example.com"}',
                "error": "nonzero exit",
                "returncode": 1,
                "elapsed_seconds": 4,
            },
        ),
    ):
        asyncio.run(
            assessment_callback_handler(
                SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8124)),
                SimpleNamespace(user_data={}),
            )
        )

    scans = list_assessment_scans(assessment["id"])
    assert len(scans) == 1
    assert scans[0]["tool"] == "bbot"
    assert scans[0]["status"] == "partial"
    assert scans[0]["target_id"] == target["id"]
    assert "BBOT: Partial" in query_message.reply_text.call_args_list[-1].args[0]


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
                "output": "",
                "error": "",
                "returncode": 0,
                "elapsed_seconds": 1,
            },
        ),
        patch("app.bot.handlers.scan.generate_bbot_ai_assessment") as generate_bbot_ai_assessment,
    ):
        asyncio.run(scan_target_handler(update, context))

    generate_bbot_ai_assessment.assert_not_called()
    assert "Status\nFailed" in message.reply_text.call_args_list[1].args[0]
    assert "no fresh normalized evidence" in message.reply_text.call_args_list[1].args[0]
    finding = get_user_findings(7206)[0]
    assert finding["status"] == "failed"
    assert finding["summary"] == "BBOT completed but produced no fresh normalized evidence for this run."
    assert get_user_observations(7206) == []


def test_bbot_scan_warning_with_no_fresh_evidence_is_failed_without_ai() -> None:
    clear_user_findings(7223)
    clear_user_investigations(7223)
    clear_user_observations(7223)
    clear_user_scan_requests(7223)
    scan_request = create_scan_request(user_id=7223, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7223, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7223))
    warning = 'Could not find flag "loud". Did you mean "cloud-enum"?'

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=True),
        patch(
            "app.bot.handlers.scan.run_bbot_scan",
            return_value={
                "success": True,
                "target": "example.com",
                "output": "",
                "error": warning,
                "returncode": 0,
                "elapsed_seconds": 1,
                "json_output_found": False,
                "json_output_paths": [],
            },
        ),
        patch("app.bot.handlers.scan.generate_bbot_ai_assessment") as generate_bbot_ai_assessment,
    ):
        asyncio.run(scan_target_handler(update, context))

    generate_bbot_ai_assessment.assert_not_called()
    result_text = message.reply_text.call_args_list[1].args[0]
    assert "Status\nFailed" in result_text
    assert warning in result_text
    finding = get_user_findings(7223)[0]
    assert finding["status"] == "failed"
    assert finding["summary"] == warning
    assert get_user_observations(7223) == []


def test_bbot_empty_current_run_does_not_reuse_prior_observations() -> None:
    clear_user_findings(7221)
    clear_user_investigations(7221)
    clear_user_observations(7221)
    clear_user_scan_requests(7221)
    investigation = create_investigation(user_id=7221, target="example.com")
    add_observation(
        user_id=7221,
        source="bbot",
        observation_type="subdomain",
        value="old.example.com",
        target="example.com",
        investigation_id=investigation["id"],
    )
    scan_request = create_scan_request(user_id=7221, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7221, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7221))

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=True),
        patch(
            "app.bot.handlers.scan.run_bbot_scan",
            return_value={
                "success": True,
                "target": "example.com",
                "output": "",
                "error": "",
                "returncode": 0,
                "elapsed_seconds": 0.2,
                "output_dir": "data/bbot/example.com/run-fresh",
                "json_output_found": False,
                "json_output_paths": [],
            },
        ),
        patch("app.bot.handlers.scan.generate_bbot_ai_assessment") as generate_bbot_ai_assessment,
    ):
        asyncio.run(scan_target_handler(update, context))

    generate_bbot_ai_assessment.assert_not_called()
    result_text = message.reply_text.call_args_list[1].args[0]
    assert "Status\nFailed" in result_text
    assert "old.example.com" not in result_text
    finding = get_user_findings(7221)[0]
    assert finding["status"] == "failed"
    assert finding["finding_count"] == 0
    assert finding["metadata"]["observation_count"] == 0
    assert len(get_user_observations(7221)) == 1
    assert get_user_observations(7221)[0]["value"] == "old.example.com"


def test_bbot_current_run_summary_and_ai_ignore_prior_observations() -> None:
    clear_user_findings(7222)
    clear_user_investigations(7222)
    clear_user_observations(7222)
    clear_user_scan_requests(7222)
    investigation = create_investigation(user_id=7222, target="example.com")
    add_observation(
        user_id=7222,
        source="bbot",
        observation_type="subdomain",
        value="old.example.com",
        target="example.com",
        investigation_id=investigation["id"],
    )
    scan_request = create_scan_request(user_id=7222, scan_type="bbot")
    mark_scan_request_awaiting_target(user_id=7222, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    message = SimpleNamespace(text="example.com", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7222))

    def assert_current_ai_context(*args, **kwargs):
        observations = kwargs["observations"]
        recon_summary = kwargs["recon_summary"]
        assert [observation["value"] for observation in observations] == ["fresh.example.com"]
        assert "Observations Collected: 1" in recon_summary
        assert "fresh.example.com" in recon_summary
        assert "old.example.com" not in recon_summary
        return ["Executive Summary", "- Fresh BBOT evidence was reviewed."]

    with (
        patch("app.bot.handlers.scan.is_bbot_available", return_value=True),
        patch(
            "app.bot.handlers.scan.run_bbot_scan",
            return_value={
                "success": True,
                "target": "example.com",
                "output": '{"type":"DNS_NAME","data":"fresh.example.com"}',
                "error": "",
                "returncode": 0,
                "elapsed_seconds": 2,
                "output_dir": "data/bbot/example.com/run-fresh",
                "json_output_found": True,
                "json_output_paths": ["data/bbot/example.com/run-fresh/scan/output/output.jsonl"],
            },
        ),
        patch("app.bot.handlers.scan.generate_bbot_ai_assessment", side_effect=assert_current_ai_context),
    ):
        asyncio.run(scan_target_handler(update, context))

    result_text = message.reply_text.call_args_list[1].args[0]
    assert "Observations Collected: 1" in result_text
    assert "fresh.example.com" in result_text
    assert "old.example.com" not in result_text
    finding = get_user_findings(7222)[0]
    assert finding["status"] == "completed"
    assert finding["finding_count"] == 1
    assert [observation["value"] for observation in finding["observations"]] == ["fresh.example.com"]
    assert {observation["value"] for observation in get_user_observations(7222)} == {"old.example.com", "fresh.example.com"}


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

    assert splitter.call_args_list[0].args[0].startswith("BBOT Scan Complete")
    assert [call.args[0] for call in message.reply_text.call_args_list[:3]] == [
        f" BBOT Scan\n\n{icon('target')} Target\nexample.com\n\n"
        f"{icon('running')} Status\nLaunching scan...\n\n{icon('elapsed')} Elapsed\n0s",
        "chunk one",
        "chunk two",
    ]
    assert "Generating BBOT AI assessment..." in [call.args[0] for call in message.reply_text.call_args_list]


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

    assert "BBOT Scan Complete" in text
    assert "Summary\nBBOT Recon Summary\n\nTarget:\nexample.com" in text
    assert "Findings\n- Observations collected:" not in text


def test_bbot_scan_result_formatter_uses_clean_partial_summary() -> None:
    text = build_bbot_result_text(
        {
            "success": False,
            "partial": True,
            "target": "example.com",
            "output": "raw stdout should not show",
            "error": "raw error should not show",
            "elapsed_seconds": 1,
        },
        recon_summary="BBOT Recon Summary\n\nTarget:\nexample.com",
    )

    assert "Status\nPartial" in text
    assert "BBOT Recon Summary" in text
    assert "Partial result:" in text
    assert "raw stdout should not show" not in text
    assert "raw error should not show" not in text


def test_bbot_scan_result_formatter_keeps_failure_output_concise() -> None:
    text = build_bbot_result_text(
        {
            "success": False,
            "target": "example.com",
            "output": "raw stdout should not show",
            "error": "A" * 1000,
            "elapsed_seconds": 1,
        }
    )

    assert "Status\nFailed" in text
    assert "raw stdout should not show" not in text
    assert "...[truncated]" in text


def test_bbot_runtime_incompatible_traceback_not_shown_in_telegram() -> None:
    text = build_bbot_result_text(
        {
            "success": False,
            "target": "example.com",
            "error": BBOT_RUNTIME_INCOMPATIBLE_ERROR,
            "error_type": "runtime_incompatible",
            "output": "Traceback (most recent call last): ModuleNotFoundError: No module named 'fcntl'",
            "elapsed_seconds": 1,
        }
    )

    assert "BBOT is installed but cannot run in this Windows environment." in text
    assert "BBOT requires a Linux-compatible runtime for this scan mode." in text
    assert "- Run Mongrel under WSL, Kali, or Linux." in text
    assert "Traceback" not in text
    assert "ModuleNotFoundError" not in text
    assert "fcntl" not in text


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
        with (
            patch(
                "app.bot.handlers.scan.run_nuclei_scan",
                return_value={
                    "success": True,
                    "target": "https://example.com",
                    "output": nuclei_output,
                    "error": "",
                    "returncode": 0,
                },
            ) as run_nuclei_scan,
            patch(
                "app.bot.handlers.scan.generate_nuclei_ai_assessment",
                return_value=[
                    "Executive Summary",
                    "- One matched finding was observed.",
                    "",
                    "Observed Facts",
                    "- git-config-exposure matched https://example.com/.git/config.",
                    "",
                    "Confidence",
                    "Medium",
                ],
            ),
        ):
            await scan_target_handler(update, context)
            active_scan = get_active_scan(7102)
            assert active_scan is not None
            assert active_scan.task is not None
            await active_scan.task

        run_nuclei_scan.assert_called_once_with("https://example.com")

    asyncio.run(run_flow())
    assert " Nuclei Scan" in message.reply_text.call_args_list[0].args[0]
    assert f"{icon('running')} Status\nLaunching scan..." in message.reply_text.call_args_list[0].args[0]
    status_edits = [call.args[0] for call in status_message.edit_text.call_args_list]
    assert any(f"{icon('success')} Status\nComplete" in edit for edit in status_edits)
    assert "Nuclei Scan Complete" in message.reply_text.call_args_list[1].args[0]
    assert "Time\n" in message.reply_text.call_args_list[1].args[0]
    assert "Risk\nHIGH" in message.reply_text.call_args_list[1].args[0]
    keyboard = message.reply_text.call_args_list[1].kwargs["reply_markup"]
    assert keyboard.inline_keyboard[0][0].text == "AI Summary"
    assert keyboard.inline_keyboard[0][0].callback_data.startswith("ai_summary:nuclei:")
    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert sent_messages[2] == "Generating Nuclei AI assessment..."
    assert "Nuclei AI Assessment" in sent_messages[3]
    assert "Observed Facts\n- git-config-exposure matched https://example.com/.git/config." in sent_messages[3]
    findings = get_user_findings(7102)
    assert findings[0]["source"] == "nuclei"
    assert findings[0]["target"] == "https://example.com"
    investigation = get_user_investigations(7102)[0]
    events = get_investigation_events(investigation["id"], 7102)
    assert [event["event_type"] for event in events] == ["nuclei_scan_started", "nuclei_scan_completed"]
    assert context.user_data == {}


def test_partial_timeout_nuclei_scan_retains_findings_and_ai_context() -> None:
    clear_user_findings(7115)
    clear_user_investigations(7115)
    clear_user_scan_requests(7115)
    clear_active_scan(7115)
    scan_request = create_scan_request(user_id=7115, scan_type="nuclei")
    mark_scan_request_awaiting_target(user_id=7115, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7115))
    nuclei_output = "\n".join(
        [
            '{"template-id":"tech-detect","info":{"severity":"info","name":"Technology Detection"},"host":"https://example.com"}',
            '{"template-id":"panel-detect","info":{"severity":"info","name":"Panel Detection"},"host":"https://example.com/admin"}',
        ]
    )

    def assert_ai_context(finding: dict) -> list[str]:
        assert finding["finding_count"] == 2
        assert finding["metadata"]["partial"] is True
        assert finding["metadata"]["timed_out"] is True
        assert finding["metadata"]["timeout_reason"] == "Execution time limit reached."
        return [
            "Executive Summary",
            "- The scan reached the configured execution time limit before completion. Two informational observations were collected before termination.",
        ]

    async def run_flow() -> None:
        with (
            patch(
                "app.bot.handlers.scan.run_nuclei_scan",
                return_value={
                    "success": False,
                    "partial": True,
                    "timed_out": True,
                    "scan_completed": False,
                    "target": "https://example.com",
                    "output": nuclei_output,
                    "error": "Execution time limit reached.",
                    "error_type": "timeout",
                    "timeout_reason": "Execution time limit reached.",
                    "returncode": -9,
                },
            ),
            patch("app.bot.handlers.scan.generate_nuclei_ai_assessment", side_effect=assert_ai_context),
        ):
            await scan_target_handler(update, context)
            active_scan = get_active_scan(7115)
            assert active_scan is not None
            assert active_scan.task is not None
            await active_scan.task

    asyncio.run(run_flow())
    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert "Status\nPartial" in sent_messages[1]
    assert "Reason: Execution time limit reached" in sent_messages[1]
    assert "Findings collected before timeout: retained" in sent_messages[1]
    assert "Findings detected: 2" in sent_messages[1]
    assert "No matching Nuclei findings were observed" not in sent_messages[-1]
    finding = get_user_findings(7115)[0]
    assert finding["finding_count"] == 2
    assert finding["metadata"]["partial"] is True


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
        with (
            patch(
                "app.bot.handlers.scan.run_nuclei_scan",
                return_value={"success": True, "target": "https://example.com", "output": "", "error": "", "returncode": 0},
            ),
            patch(
                "app.bot.handlers.scan.generate_nuclei_ai_assessment",
                return_value=[
                    "Executive Summary",
                    "- No matching findings were observed.",
                    "",
                    "Observed Facts",
                    "- No matching Nuclei findings were observed using the selected template/profile.",
                    "",
                    "Confidence",
                    "Low",
                ],
            ),
        ):
            await scan_target_handler(update, context)
            active_scan = get_active_scan(7103)
            assert active_scan is not None
            assert active_scan.task is not None
            await active_scan.task

    asyncio.run(run_flow())
    status_edits = [call.args[0] for call in status_message.edit_text.call_args_list]
    assert any(f"{icon('success')} Status\nComplete" in edit for edit in status_edits)
    verdict_text = message.reply_text.call_args_list[1].args[0]
    assert "Nuclei Scan Complete" in verdict_text
    assert "Target\nhttps://example.com" in verdict_text
    assert "Time\n" in verdict_text
    assert "Risk\nINFO" in verdict_text
    assert "Findings\n- 0 findings" in verdict_text
    assert "No matching Nuclei findings were observed using the selected template/profile." in verdict_text
    assert "- The target was reachable." in verdict_text
    assert "- Nuclei executed successfully." in verdict_text
    assert "- Continue regular patching and monitoring." in verdict_text
    keyboard = message.reply_text.call_args_list[1].kwargs["reply_markup"]
    assert keyboard.inline_keyboard[0][0].text == "AI Summary"
    assert keyboard.inline_keyboard[0][0].callback_data.startswith("ai_summary:nuclei:")
    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert sent_messages[2] == "Generating Nuclei AI assessment..."
    assert "Nuclei AI Assessment" in sent_messages[3]
    clean_record = get_user_findings(7103)[0]
    assert clean_record["source"] == "nuclei"
    assert clean_record["status"] == "clean"
    assert clean_record["risk_level"] == "info"
    assert clean_record["finding_count"] == 0
    assert clean_record["summary"] == "No matching Nuclei findings were identified using the fast scan profile."


def test_nuclei_ai_assessment_failure_does_not_fail_scan() -> None:
    clear_user_findings(7114)
    clear_user_scan_requests(7114)
    clear_active_scan(7114)
    scan_request = create_scan_request(user_id=7114, scan_type="nuclei")
    mark_scan_request_awaiting_target(user_id=7114, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    status_message = SimpleNamespace(edit_text=AsyncMock())
    message = SimpleNamespace(text="https://example.com", reply_text=AsyncMock(return_value=status_message))
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7114))

    async def run_flow() -> None:
        with (
            patch(
                "app.bot.handlers.scan.run_nuclei_scan",
                return_value={"success": True, "target": "https://example.com", "output": "", "error": "", "returncode": 0},
            ),
            patch("app.bot.handlers.scan.generate_nuclei_ai_assessment", return_value=NUCLEI_AI_FALLBACK_LINES),
        ):
            await scan_target_handler(update, context)
            active_scan = get_active_scan(7114)
            assert active_scan is not None
            assert active_scan.task is not None
            await active_scan.task

    asyncio.run(run_flow())
    sent_messages = [call.args[0] for call in message.reply_text.call_args_list]
    assert "Nuclei Scan Complete" in sent_messages[1]
    assert sent_messages[-1] == "\n".join(NUCLEI_AI_FALLBACK_LINES)
    assert get_user_findings(7114)


def test_clean_nuclei_verdict_formatter_for_no_findings() -> None:
    verdict_text = build_clean_nuclei_verdict_text("hellosundaykids.com", elapsed="9s")

    assert "Nuclei Scan Complete" in verdict_text
    assert "Target\nhellosundaykids.com" in verdict_text
    assert "Time\n9s" in verdict_text
    assert "Risk\nINFO" in verdict_text
    assert "Findings\n- 0 findings" in verdict_text
    assert "Summary" in verdict_text


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
    assert f"{icon('success')} Status\nFailed: Nuclei executable was not found." in status_message.edit_text.call_args.args[0]
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
            assert active_scan.target == "https://example.com"
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
    assert "⏳ Status\nCancelled" in status_message.edit_text.call_args.args[0]
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
    assert "⏳ Status\nCancelled" in status_message.edit_text.call_args.args[0]
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
    assert "Nuclei Scan progress edit timed out" in caplog.text


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

    assert "Nuclei Scan Complete" in message.reply_text.call_args_list[1].args[0]
    assert "Risk\nINFO" in message.reply_text.call_args_list[1].args[0]


def test_failed_status_edit_is_logged(caplog) -> None:
    status_message = SimpleNamespace(edit_text=AsyncMock(side_effect=TimedOut("final timeout")))

    async def run_flow() -> None:
        await _finalize_nuclei_status(status_message, "example.com", "Complete", asyncio.get_running_loop().time())

    asyncio.run(run_flow())

    assert "Nuclei Scan progress edit timed out" in caplog.text


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

    assert "Target\n127.0.0.1" in result_text
    assert "Host reachable." in result_text
    assert "22/tcp ssh" in result_text
    assert "Time\n0.32s" in result_text
    assert "Risk\nMEDIUM" in result_text
    assert "SSH service exposed." in result_text
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
    assert target_message.reply_text.call_args_list[0].args[0] == (
        f" Nmap Scan\n\n{icon('target')} Target\n127.0.0.1\n\n"
        f"{icon('running')} Status\nLaunching scan...\n\n{icon('elapsed')} Elapsed\n0s"
    )


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


def _tshark_upload_update(user_id: int, *, file_name: str | None = "capture.pcap", file_size: int | None = 4, content: bytes = b"pcap") -> SimpleNamespace:
    telegram_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(content)))
    document = SimpleNamespace(file_name=file_name, file_size=file_size, get_file=AsyncMock(return_value=telegram_file))
    message = SimpleNamespace(document=document, reply_text=AsyncMock())
    return SimpleNamespace(message=message, effective_user=SimpleNamespace(id=user_id))


def _tshark_normalized(success: bool = True) -> dict:
    return {
        "success": success,
        "source_file": {"name": "capture.pcap", "extension": ".pcap", "size_bytes": 4},
        "packet_count": 2,
        "byte_count": 160,
        "capture_start": "1710000000.1",
        "capture_end": "1710000001.2",
        "observed_protocols": [{"protocol": "dns", "packet_count": 1}, {"protocol": "tls", "packet_count": 1}],
        "observed_endpoints": [{"address": "192.0.2.10", "packet_count": 2}, {"address": "198.51.100.20", "packet_count": 1}],
        "observed_conversations": [{"src": "192.0.2.10", "dst": "198.51.100.20", "src_port": "53000", "dst_port": "53", "transport": "udp", "packet_count": 1}],
        "dns_observations": [{"query_name": "example.com", "response_address": "93.184.216.34"}],
        "http_observations": [{"method": "GET", "host": "example.com", "uri": "/?token=<REDACTED>", "response_code": "200"}],
        "tls_observations": [{"sni": "tls.example.com", "version": "0x0303"}],
        "parser_warnings": [],
        "truncation": {"output_truncated": False},
        "evidence_limitations": [],
    }


def _approved_metasploit_http_proposal(user_id: int, *, assessment_id: int | None = None, target: str = "example.com", port: int = 80):
    request = build_metasploit_action_request(
        module="auxiliary/scanner/http/http_version",
        action_type="auxiliary_validation",
        target=target,
        port=port,
        options={"SSL": "true"} if port in {443, 8443} else {},
    )
    context = {"assessment_id": assessment_id} if assessment_id is not None else None
    return approve_metasploit_proposal(propose_metasploit_action(user_id, request, assessment_context=context).id, user_id=user_id)


def _build_tshark_capture_validation_review(*, user_id: int, settings: Settings, assessment_id: int | None = None) -> SimpleNamespace:
    capture_query = SimpleNamespace(
        data="tshark:capture" if assessment_id is None else f"tshark:capture:{assessment_id}",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
    )
    asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=capture_query, effective_user=SimpleNamespace(id=user_id)), SimpleNamespace()))
    validation_callback = capture_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data
    validation_query = SimpleNamespace(data=validation_callback, answer=AsyncMock(), edit_message_text=AsyncMock())
    with patch("app.bot.handlers.upload.check_tshark_live_readiness", return_value={"ready": True, "allowed_interfaces": ["eth0"], "resolved_binary": "tshark"}):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=validation_query, effective_user=SimpleNamespace(id=user_id)), SimpleNamespace()))
    interface_callback = validation_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data
    review_query = SimpleNamespace(data=interface_callback, answer=AsyncMock(), edit_message_text=AsyncMock())
    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=review_query, effective_user=SimpleNamespace(id=user_id)), SimpleNamespace()))
    return review_query


def test_tshark_live_result_card_polishes_source_time_duration_protocols_and_warnings() -> None:
    normalized = _tshark_normalized()
    normalized["source_file"] = {"name": "mongrel-tshark-live-secret-temp.pcapng", "extension": ".pcapng", "size_bytes": 160}
    normalized["observed_protocols"] = [
        {"protocol": "eth", "packet_count": 2},
        {"protocol": "tcp", "packet_count": 2},
        {"protocol": "ip", "packet_count": 2},
        {"protocol": "http", "packet_count": 1},
        {"protocol": "dns", "packet_count": 1},
    ]
    normalized["parser_warnings"] = ["encrypted traffic limits visibility", "encrypted traffic limits visibility", "bounded capture"]

    card = build_tshark_result_text(normalized, {"source": "tshark_live", "elapsed_seconds": 1.24, "duration_seconds": 5})

    assert "Live Capture" in card
    assert "mongrel-tshark-live-secret-temp.pcapng" not in card
    assert "Start: 2024-03-09 16:00:00 UTC" in card
    assert "End: 2024-03-09 16:00:01 UTC" in card
    assert "Duration: 1.2s" in card
    assert card.index("- http: 1") < card.index("- tcp: 2")
    assert card.index("- dns: 1") < card.index("- ip: 2")
    assert card.count("encrypted traffic limits visibility") == 1
    assert "Packet activity is not automatically malicious." in card
    assert "A connection is not compromise." in card


def test_tshark_result_card_keeps_endpoint_and_conversation_lists_bounded() -> None:
    normalized = _tshark_normalized()
    normalized["observed_endpoints"] = [{"address": f"192.0.2.{index}", "packet_count": index} for index in range(10)]
    normalized["observed_conversations"] = [
        {"src": f"192.0.2.{index}", "dst": "198.51.100.20", "src_port": str(53000 + index), "dst_port": "443", "transport": "tcp", "packet_count": 1}
        for index in range(8)
    ]

    card = build_tshark_result_text(normalized, {"source": "tshark_live", "elapsed_seconds": 1.0})

    assert "192.0.2.7 packets=7" in card
    assert "192.0.2.8 packets=8" not in card
    assert "192.0.2.5:53005" in card
    assert "192.0.2.6:53006" not in card


def test_tshark_offline_result_card_uses_uploaded_filename_readable_time_duration_dns_tls_and_escaping() -> None:
    normalized = _tshark_normalized()
    normalized["source_file"] = {"name": "mongrel-tshark-temp-123.pcap", "extension": ".pcap", "size_bytes": 160}
    normalized["observed_protocols"] = [
        {"protocol": "ethertype", "packet_count": 99},
        {"protocol": "dns", "packet_count": 1},
        {"protocol": "tcp", "packet_count": 9},
        {"protocol": "tls", "packet_count": 4},
        {"protocol": "ip", "packet_count": 6},
        {"protocol": "eth", "packet_count": 7},
    ]
    normalized["observed_endpoints"] = [
        {"address": "192.0.2.10", "packet_count": 2},
        {"address": "198.51.100.20", "packet_count": 8},
        {"address": "203.0.113.30", "packet_count": 5},
    ]
    normalized["observed_conversations"] = [
        {"src": "192.0.2.10", "dst": "198.51.100.20", "src_port": "53000", "dst_port": "443", "transport": "tcp", "packet_count": 2},
        {"src": "192.0.2.10", "dst": "203.0.113.30", "src_port": "53001", "dst_port": "80", "transport": "tcp", "packet_count": 7},
    ]
    normalized["dns_observations"] = [
        {"query_name": "<Root>", "response_address": "192.0.2.10"},
        {"query_name": "<Root>", "response_address": "192.0.2.10"},
        {"query_name": "example.com", "response_address": "198.51.100.20"},
    ]
    normalized["tls_observations"] = [
        {"sni": "", "version": "0x0303"},
        {"sni": "", "version": "0x0303"},
        {"sni": "<Root>", "version": "0x0303"},
    ]

    card = build_tshark_result_text(normalized, {"uploaded_filename": "../Client <Root>.pcap", "elapsed_seconds": 99.0})

    assert "Client &lt;Root&gt;.pcap" in card
    assert "mongrel-tshark-temp-123.pcap" not in card
    assert "Start: 2024-03-09 16:00:00 UTC" in card
    assert "End: 2024-03-09 16:00:01 UTC" in card
    assert "Duration: 1.1s" in card
    assert "Duration: 99.0s" not in card
    assert "Capture Summary:" in card
    assert "Packet Count: 2" in card
    assert "Main Protocols: tcp, eth, ip" in card
    assert "Top Talker: 198.51.100.20 (8 packets)" in card
    assert "Application:" in card
    assert "Transport:" in card
    assert "Network:" in card
    assert "Link:" in card
    assert "ethertype" not in card
    assert card.index("- tls: 4") < card.index("- dns: 1")
    assert card.index("- tcp: 9") < card.index("- ip: 6")
    assert card.index("- eth: 7") > card.index("Link:")
    assert "Top Talkers:" in card
    assert card.index("198.51.100.20 packets=8") < card.index("203.0.113.30 packets=5") < card.index("192.0.2.10 packets=2")
    assert card.index("192.0.2.10 ↔ 203.0.113.30 (7 packets)") < card.index("192.0.2.10 ↔ 198.51.100.20 (2 packets)")
    assert "- &lt;Root&gt;\n  →\n  192.0.2.10" in card
    assert card.count("&lt;Root&gt;\n  →\n  192.0.2.10") == 1
    assert card.count("sni=n/a version=TLS 1.2") == 1
    assert "sni=&lt;Root&gt; version=TLS 1.2" in card
    assert normalized["tls_observations"][0]["version"] == "0x0303"


def test_tshark_offline_upload_result_card_uses_original_safe_filename_not_temp_file() -> None:
    user_id = 5920
    set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    update = _tshark_upload_update(user_id, file_name="nested/Client <Root>.pcap", content=b"pcap")
    normalized = _tshark_normalized()
    normalized["source_file"] = {"name": "mongrel-tshark-generated.pcap", "extension": ".pcap", "size_bytes": 4}

    with (
        patch("app.bot.handlers.upload.check_tshark_readiness", return_value={"ready": True}),
        patch("app.bot.handlers.upload.run_tshark_offline_analysis", return_value={"success": True, "capture_file": "mongrel-tshark-generated.pcap", "output": ""}),
        patch("app.bot.handlers.upload.normalize_tshark_result", return_value=normalized),
    ):
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    card = update.message.reply_text.call_args.args[0]
    assert "Client &lt;Root&gt;.pcap" in card
    assert "mongrel-tshark-generated.pcap" not in card
    assert get_upload_state(user_id) is None


def test_tshark_scan_callback_prompts_for_upload_or_live_choice() -> None:
    query = SimpleNamespace(data="scan:tshark", answer=AsyncMock(), edit_message_text=AsyncMock())
    context = SimpleNamespace(user_data={})

    asyncio.run(scan_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5300)), context))

    assert query.edit_message_text.call_args.args[0] == build_tshark_mode_text()
    callbacks = {button.text: button.callback_data for row in query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard for button in row}
    assert callbacks["Capture During Validation"] == "tshark:capture"
    assert callbacks["Analyze PCAP"] == "tshark:upload"
    assert callbacks["Standalone Live Capture"] == "tshark:live"
    assert get_upload_state(5300) is None


def test_tshark_capture_during_validation_lists_only_eligible_approved_metasploit_validation() -> None:
    clear_metasploit_proposals()
    clear_tshark_capture_proposals()
    assessment = create_assessment("TShark Capture Validation")
    http_proposal = _approved_metasploit_http_proposal(5920, assessment_id=assessment["id"], target="example.com", port=443)
    ssh_request = build_metasploit_action_request(
        module="auxiliary/scanner/ssh/ssh_version",
        action_type="auxiliary_validation",
        target="example.com",
        port=22,
    )
    approve_metasploit_proposal(propose_metasploit_action(5920, ssh_request, assessment_context={"assessment_id": assessment["id"]}).id, user_id=5920)
    query = SimpleNamespace(data=f"tshark:capture:{assessment['id']}", answer=AsyncMock(), edit_message_text=AsyncMock())

    asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5920)), SimpleNamespace()))

    text = query.edit_message_text.call_args.args[0]
    keyboard = query.edit_message_text.call_args.kwargs["reply_markup"]
    buttons = [button.text for row in keyboard.inline_keyboard for button in row]
    assert "Capture During Validation" in text
    assert buttons[0] == "HTTP Service Fingerprint - example.com:443 (approved)"
    assert all("SSH" not in button for button in buttons)
    assert keyboard.inline_keyboard[0][0].callback_data.startswith("tshark:cv:")
    assert len(keyboard.inline_keyboard[0][0].callback_data) <= 64
    assert get_metasploit_proposal(http_proposal.id) is not None


def test_tshark_capture_during_validation_lists_completed_guided_http_validation() -> None:
    clear_metasploit_proposals()
    clear_tshark_capture_proposals()
    assessment = create_assessment("TShark Completed Validation Lookup")
    http_proposal = _approved_metasploit_http_proposal(5925, assessment_id=assessment["id"], target="example.com", port=443)
    mark_metasploit_proposal_status(http_proposal.id, "executed")
    record_metasploit_result_reference(http_proposal.id, "assessment_artifact:42")
    query = SimpleNamespace(data=f"tshark:capture:{assessment['id']}", answer=AsyncMock(), edit_message_text=AsyncMock())

    asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5925)), SimpleNamespace()))

    text = query.edit_message_text.call_args.args[0]
    keyboard = query.edit_message_text.call_args.kwargs["reply_markup"]
    buttons = [button.text for row in keyboard.inline_keyboard for button in row]
    assert "Completed validations are used as exact re-run templates" in text
    assert buttons[0] == "HTTP Service Fingerprint - example.com:443 (completed)"
    assert "No eligible approved" not in text


def test_tshark_capture_validation_interface_selection_enforces_allowlist_and_shows_review_card() -> None:
    clear_metasploit_proposals()
    clear_tshark_capture_proposals()
    settings = Settings(_env_file=None, tshark_live_interface_allowlist="eth0,lo", tshark_live_max_duration_seconds=6, tshark_live_max_packet_count=20, tshark_live_max_file_size_kb=256)
    _approved_metasploit_http_proposal(5921, target="example.com", port=443)
    capture_query = SimpleNamespace(data="tshark:capture", answer=AsyncMock(), edit_message_text=AsyncMock())
    asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=capture_query, effective_user=SimpleNamespace(id=5921)), SimpleNamespace()))
    validation_callback = capture_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data
    validation_query = SimpleNamespace(data=validation_callback, answer=AsyncMock(), edit_message_text=AsyncMock())

    with patch("app.bot.handlers.upload.check_tshark_live_readiness", return_value={"ready": True, "allowed_interfaces": ["eth0", "lo"], "resolved_binary": "tshark"}):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=validation_query, effective_user=SimpleNamespace(id=5921)), SimpleNamespace()))

    interface_text = validation_query.edit_message_text.call_args.args[0]
    interface_keyboard = validation_query.edit_message_text.call_args.kwargs["reply_markup"]
    assert "Choose an allowlisted capture interface" in interface_text
    assert [button.text for row in interface_keyboard.inline_keyboard[:-1] for button in row] == ["eth0", "lo"]
    assert all("wlan0" not in button.text for row in interface_keyboard.inline_keyboard for button in row)
    review_query = SimpleNamespace(data=interface_keyboard.inline_keyboard[0][0].callback_data, answer=AsyncMock(), edit_message_text=AsyncMock())

    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=review_query, effective_user=SimpleNamespace(id=5921)), SimpleNamespace()))

    review = review_query.edit_message_text.call_args.args[0]
    review_keyboard = review_query.edit_message_text.call_args.kwargs["reply_markup"]
    assert "TShark Capture Review" in review
    assert "Validation:\nHTTP Service Fingerprint" in review
    assert "Target:\nexample.com" in review
    assert "Expected Port:\n443" in review
    assert "Interface:\neth0" in review
    assert "Capture Duration:\n6 seconds" in review
    assert "This action WILL:" in review
    assert "- Execute the exact reviewed Metasploit validation" in review
    assert "This action WILL NOT:" in review
    assert "- Continue capturing indefinitely" in review
    assert len(review_keyboard.inline_keyboard[0][0].callback_data) <= 64


def test_tshark_capture_validation_approve_invokes_orchestrator_and_persists_provenance() -> None:
    clear_metasploit_proposals()
    clear_tshark_capture_proposals()
    assessment = create_assessment("TShark Capture Provenance")
    settings = Settings(_env_file=None, tshark_live_interface_allowlist="eth0", tshark_live_max_duration_seconds=5, tshark_live_max_packet_count=25, tshark_live_max_file_size_kb=512)
    validation_proposal = _approved_metasploit_http_proposal(5922, assessment_id=assessment["id"], target="example.com", port=80)
    review_query = _build_tshark_capture_validation_review(user_id=5922, settings=settings, assessment_id=assessment["id"])
    proposal_id = review_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    approve_query = SimpleNamespace(data=f"tshark:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    normalized = _tshark_normalized()
    normalized["observed_endpoints"] = [{"address": "192.0.2.10", "packet_count": 2}, {"address": "93.184.216.34", "packet_count": 2}]
    normalized["observed_conversations"] = [{"src": "192.0.2.10", "dst": "93.184.216.34", "src_port": "53000", "dst_port": "80", "transport": "tcp", "packet_count": 2}]
    result = {
        "source": "tshark_capture_during_validation",
        "success": True,
        "elapsed_seconds": 2.0,
        "offline_result": {"success": True, "source": "tshark_live"},
        "validation_result": {
            "success": True,
            "module": "auxiliary/scanner/http/http_version",
            "action_type": "auxiliary_validation",
            "target": "example.com",
            "port": 80,
            "output": "Server: nginx",
            "error": "",
        },
        "normalized_evidence": normalized,
        "post_validation_tail_seconds": 3,
        "provenance": {
            "user_id": 5922,
            "validation_proposal_id": validation_proposal.id,
            "capture_proposal_id": proposal_id,
            "target": "example.com",
            "module": "auxiliary/scanner/http/http_version",
            "action": "auxiliary_validation",
            "port": 80,
            "interface": "eth0",
            "capture_started_at": "2026-07-23T10:00:00+00:00",
            "capture_ended_at": "2026-07-23T10:00:05+00:00",
            "validation_started_at": "2026-07-23T10:00:01+00:00",
            "validation_ended_at": "2026-07-23T10:00:02+00:00",
            "pcap_artifact_path": "C:/tmp/mongrel-tshark-validation.pcapng",
        },
    }

    with (
        patch("app.bot.handlers.upload.run_tshark_capture_during_validation", return_value=result) as orchestrator,
        patch("app.bot.handlers.upload.generate_tshark_metasploit_correlated_assessment", return_value=["Executive Summary", "Correlated evidence reviewed."]) as correlated_ai,
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=approve_query, effective_user=SimpleNamespace(id=5922)), SimpleNamespace()))

    orchestrator.assert_called_once()
    assert orchestrator.call_args.kwargs["capture_proposal_id"] == proposal_id
    assert orchestrator.call_args.kwargs["metasploit_proposal_id"] == validation_proposal.id
    assert orchestrator.call_args.kwargs["metasploit_request"]["module"] == "auxiliary/scanner/http/http_version"
    assert orchestrator.call_args.kwargs["metasploit_request"]["target"] == "example.com"
    assert "Running bounded capture during validation" in approve_query.edit_message_text.call_args.args[0]
    assert "TShark PCAP Analysis" in approve_query.message.reply_text.call_args_list[0].args[0]
    assert approve_query.message.reply_text.call_args_list[1].args[0].startswith(f"{icon('mongrel_ai')} TShark + Metasploit Correlated Assessment")
    assert "Correlated evidence reviewed." in approve_query.message.reply_text.call_args_list[1].args[0]
    artifacts = list_assessment_artifacts(assessment["id"])
    assert any(artifact["artifact_type"] == "tshark_normalized_evidence" for artifact in artifacts)
    provenance_artifact = [artifact for artifact in artifacts if artifact["artifact_type"] == "tshark_validation_capture_provenance"][-1]
    provenance = json.loads(provenance_artifact["content"])
    assert provenance["validation_proposal_id"] == validation_proposal.id
    assert provenance["capture_proposal_id"] == proposal_id
    assert provenance["interface"] == "eth0"
    correlation_artifact = [artifact for artifact in artifacts if artifact["artifact_type"] == "tshark_metasploit_correlation_record"][-1]
    correlation = json.loads(correlation_artifact["content"])
    assert correlation["validation_proposal_id"] == validation_proposal.id
    assert correlation["capture_provenance_id"].startswith("assessment_artifact:")
    assert correlation["validation_result_id"].startswith("assessment_artifact:")
    assert correlation["correlation_outcome"] == "corroborated"
    assert correlation["agreement_disagreement_state"] == "agreement"
    assert any(artifact["artifact_type"] == "tshark_metasploit_correlated_ai_assessment" for artifact in artifacts)
    correlated_ai.assert_called_once()


def test_tshark_capture_validation_tool_mode_sends_correlated_assessment_without_assessment_context() -> None:
    clear_metasploit_proposals()
    clear_tshark_capture_proposals()
    settings = Settings(_env_file=None, tshark_live_interface_allowlist="eth0", tshark_live_max_duration_seconds=5, tshark_live_max_packet_count=25, tshark_live_max_file_size_kb=512)
    validation_proposal = _approved_metasploit_http_proposal(5930, target="example.com", port=80)
    review_query = _build_tshark_capture_validation_review(user_id=5930, settings=settings)
    proposal_id = review_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    approve_query = SimpleNamespace(data=f"tshark:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    normalized = _tshark_normalized()
    normalized["observed_endpoints"] = [{"address": "192.0.2.10", "packet_count": 2}, {"address": "93.184.216.34", "packet_count": 2}]
    normalized["observed_conversations"] = [{"src": "192.0.2.10", "dst": "93.184.216.34", "src_port": "53000", "dst_port": "80", "transport": "tcp", "packet_count": 2}]
    result = {
        "source": "tshark_capture_during_validation",
        "success": True,
        "elapsed_seconds": 2.0,
        "offline_result": {"success": True, "source": "tshark_live"},
        "validation_result": {
            "success": True,
            "module": "auxiliary/scanner/http/http_version",
            "action_type": "auxiliary_validation",
            "target": "example.com",
            "port": 80,
            "output": "Server: nginx",
            "error": "",
        },
        "normalized_evidence": normalized,
        "post_validation_tail_seconds": 3,
        "provenance": {
            "user_id": 5930,
            "validation_proposal_id": validation_proposal.id,
            "capture_proposal_id": proposal_id,
            "target": "example.com",
            "module": "auxiliary/scanner/http/http_version",
            "action": "auxiliary_validation",
            "port": 80,
            "interface": "eth0",
            "capture_started_at": "2026-07-23T10:00:00+00:00",
            "capture_ended_at": "2026-07-23T10:00:05+00:00",
            "validation_started_at": "2026-07-23T10:00:01+00:00",
            "validation_ended_at": "2026-07-23T10:00:02+00:00",
        },
    }

    with (
        patch("app.bot.handlers.upload.run_tshark_capture_during_validation", return_value=result) as orchestrator,
        patch("app.bot.handlers.upload.generate_tshark_metasploit_correlated_assessment", return_value=["Executive Summary", "Tool mode correlated evidence reviewed."]) as correlated_ai,
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=approve_query, effective_user=SimpleNamespace(id=5930)), SimpleNamespace()))

    orchestrator.assert_called_once()
    assert orchestrator.call_args.kwargs["metasploit_proposal_id"] == validation_proposal.id
    sent_messages = [call.args[0] for call in approve_query.message.reply_text.call_args_list]
    assert "TShark PCAP Analysis" in sent_messages[0]
    assert sent_messages[1].startswith(f"{icon('mongrel_ai')} TShark + Metasploit Correlated Assessment")
    assert "Tool mode correlated evidence reviewed." in sent_messages[1]
    assert len(sent_messages) == 2
    correlation = correlated_ai.call_args.args[0]
    assert correlation["assessment_id"] == 0
    assert correlation["validation_proposal_id"] == validation_proposal.id
    assert correlation["capture_proposal_id"] == proposal_id
    assert correlation["validation_result_id"] == "current_run.validation_result"
    assert correlation["capture_provenance_id"] == ""


def test_tshark_capture_validation_completed_validation_uses_fresh_approved_rerun_proposal() -> None:
    clear_metasploit_proposals()
    clear_tshark_capture_proposals()
    settings = Settings(_env_file=None, tshark_live_interface_allowlist="eth0", tshark_live_max_duration_seconds=5, tshark_live_max_packet_count=25, tshark_live_max_file_size_kb=512)
    completed_validation = _approved_metasploit_http_proposal(5926, target="example.com", port=80)
    mark_metasploit_proposal_status(completed_validation.id, "executed")
    record_metasploit_result_reference(completed_validation.id, "assessment_artifact:42")
    review_query = _build_tshark_capture_validation_review(user_id=5926, settings=settings)
    proposal_id = review_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    approve_query = SimpleNamespace(data=f"tshark:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    result = {
        "source": "tshark_capture_during_validation",
        "success": True,
        "elapsed_seconds": 1.0,
        "offline_result": {"success": True},
        "normalized_evidence": _tshark_normalized(),
        "provenance": {"validation_proposal_id": "filled-by-orchestrator"},
    }

    with patch("app.bot.handlers.upload.run_tshark_capture_during_validation", return_value=result) as orchestrator:
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=approve_query, effective_user=SimpleNamespace(id=5926)), SimpleNamespace()))

    assert "The selected validation already ran" in review_query.edit_message_text.call_args.args[0]
    runner_kwargs = orchestrator.call_args.kwargs
    assert runner_kwargs["metasploit_proposal_id"] != completed_validation.id
    assert runner_kwargs["metasploit_request"] == completed_validation.request
    fresh_proposal = get_metasploit_proposal(runner_kwargs["metasploit_proposal_id"])
    assert fresh_proposal.status == "approved"
    assert fresh_proposal.approved_by_user_id == 5926
    assert fresh_proposal.source_evidence_refs == ["assessment_artifact:42"]


def test_tshark_capture_validation_reject_and_details_do_not_execute() -> None:
    clear_metasploit_proposals()
    clear_tshark_capture_proposals()
    settings = Settings(_env_file=None, tshark_live_interface_allowlist="eth0", tshark_live_max_duration_seconds=5, tshark_live_max_packet_count=25, tshark_live_max_file_size_kb=512)
    _approved_metasploit_http_proposal(5923, target="example.com", port=80)
    review_query = _build_tshark_capture_validation_review(user_id=5923, settings=settings)
    proposal_id = review_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    details_query = SimpleNamespace(data=f"tshark:details:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock())
    reject_query = SimpleNamespace(data=f"tshark:reject:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock())

    with patch("app.bot.handlers.upload.run_tshark_capture_during_validation") as orchestrator:
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=details_query, effective_user=SimpleNamespace(id=5923)), SimpleNamespace()))
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=reject_query, effective_user=SimpleNamespace(id=5923)), SimpleNamespace()))

    orchestrator.assert_not_called()
    assert "Validation Proposal ID:" in details_query.edit_message_text.call_args.args[0]
    assert "rejected" in reject_query.edit_message_text.call_args.args[0]


def test_tshark_capture_validation_token_is_user_bound() -> None:
    clear_metasploit_proposals()
    clear_tshark_capture_proposals()
    _approved_metasploit_http_proposal(5924, target="example.com", port=443)
    capture_query = SimpleNamespace(data="tshark:capture", answer=AsyncMock(), edit_message_text=AsyncMock())
    asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=capture_query, effective_user=SimpleNamespace(id=5924)), SimpleNamespace()))
    validation_callback = capture_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data
    wrong_user = SimpleNamespace(data=validation_callback, answer=AsyncMock(), edit_message_text=AsyncMock())

    asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=wrong_user, effective_user=SimpleNamespace(id=9999)), SimpleNamespace()))

    assert wrong_user.edit_message_text.call_args.args[0] == "TShark capture validation selection was not found or has expired."


def test_scan_menu_includes_tshark_pcap_button() -> None:
    keyboard = build_scan_type_keyboard()
    callbacks = {button.text: button.callback_data for row in keyboard.inline_keyboard for button in row}

    assert callbacks["TShark PCAP"] == "scan:tshark"


def test_tshark_upload_choice_preserves_existing_upload_flow() -> None:
    query = SimpleNamespace(data="tshark:upload", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))

    asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5900)), SimpleNamespace()))

    assert query.edit_message_text.call_args.args[0] == build_tshark_upload_prompt()
    assert "reply_markup" not in query.edit_message_text.call_args.kwargs
    assert get_upload_state(5900) == UPLOAD_STATE_AWAITING_TSHARK_PCAP
    assert get_tshark_assessment_upload_context(5900) is None
    query.message.reply_text.assert_not_called()
    clear_upload_state(5900)


def test_tshark_assessment_upload_choice_uses_separate_cancel_prompt() -> None:
    assessment = create_assessment("TShark Upload Choice")
    query = SimpleNamespace(data=f"tshark:upload:{assessment['id']}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))

    asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5901)), SimpleNamespace()))

    assert get_upload_state(5901) == UPLOAD_STATE_AWAITING_TSHARK_PCAP
    assert get_tshark_assessment_upload_context(5901)["assessment_id"] == assessment["id"]
    assert "upload prompt sent" in query.edit_message_text.call_args.args[0].lower()
    assert "requires an uploaded .pcap or .pcapng artifact" in query.message.reply_text.call_args.args[0]
    keyboard = query.message.reply_text.call_args.kwargs["reply_markup"]
    assert [[button.text for button in row] for row in keyboard.keyboard] == [["Cancel"]]
    clear_upload_state(5901)


def test_tshark_live_choice_shows_only_allowlisted_interfaces() -> None:
    query = SimpleNamespace(data="tshark:live", answer=AsyncMock(), edit_message_text=AsyncMock())

    with patch("app.bot.handlers.upload.check_tshark_live_readiness", return_value={"ready": True, "allowed_interfaces": ["eth0", "lo"]}):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5902)), SimpleNamespace()))

    text = query.edit_message_text.call_args.args[0]
    callbacks = {button.text: button.callback_data for row in query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard for button in row}
    assert "eth0" in text
    assert "lo" in text
    assert "wlan0" not in text
    assert callbacks["eth0"] == "tshark:iface:ZXRoMA"
    assert callbacks["lo"] == "tshark:iface:bG8"


def test_tshark_live_readiness_failure_is_sanitized() -> None:
    query = SimpleNamespace(data="tshark:live", answer=AsyncMock(), edit_message_text=AsyncMock())

    with patch("app.bot.handlers.upload.check_tshark_live_readiness", return_value={"ready": False, "error": "TShark live capture interface allowlist is not configured. <bad>"}):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5910)), SimpleNamespace()))

    assert query.edit_message_text.call_args.args[0] == "TShark live capture interface allowlist is not configured. &lt;bad&gt;"


def test_tshark_live_interface_selection_creates_exact_proposal_without_execution() -> None:
    clear_tshark_capture_proposals()
    query = SimpleNamespace(data="tshark:iface:ZXRoMA", answer=AsyncMock(), edit_message_text=AsyncMock())
    settings = Settings(_env_file=None, tshark_live_interface_allowlist="eth0,lo", tshark_live_max_duration_seconds=7, tshark_live_max_packet_count=11, tshark_live_max_file_size_kb=128)

    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
        patch("app.bot.handlers.upload.run_tshark_live_capture") as runner,
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=5903)), SimpleNamespace()))

    runner.assert_not_called()
    text = query.edit_message_text.call_args.args[0]
    callbacks = {button.text: button.callback_data for row in query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard for button in row}
    proposal_id = callbacks["Approve"].removeprefix("tshark:approve:")
    proposal = get_tshark_capture_proposal(proposal_id)
    assert proposal is not None
    assert proposal.user_id == 5903
    assert proposal.request["interface"] == "eth0"
    assert proposal.request["duration_seconds"] == 7
    assert proposal.request["packet_count"] == 11
    assert proposal.request["file_size_kb"] == 128
    assert "Interface:" in text
    assert "eth0" in text
    assert "Approval is required before capture starts" in text


def test_tshark_live_details_renders_proposal_metadata() -> None:
    clear_tshark_capture_proposals()
    settings = Settings(_env_file=None, tshark_live_interface_allowlist="eth0", tshark_live_max_duration_seconds=5, tshark_live_max_packet_count=25, tshark_live_max_file_size_kb=512)
    create_query = SimpleNamespace(data="tshark:iface:ZXRoMA", answer=AsyncMock(), edit_message_text=AsyncMock())
    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=create_query, effective_user=SimpleNamespace(id=5911)), SimpleNamespace()))
    proposal_id = create_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    details_query = SimpleNamespace(data=f"tshark:details:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock())

    asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=details_query, effective_user=SimpleNamespace(id=5911)), SimpleNamespace()))

    text = details_query.edit_message_text.call_args.args[0]
    assert "Proposal ID:" in text
    assert "Request Fingerprint:" in text
    assert "Status:" in text


def test_tshark_live_approve_runs_bounded_capture_and_cleans_state() -> None:
    clear_tshark_capture_proposals()
    settings = Settings(_env_file=None, tshark_live_interface_allowlist="eth0", tshark_live_max_duration_seconds=5, tshark_live_max_packet_count=25, tshark_live_max_file_size_kb=512)
    create_query = SimpleNamespace(data="tshark:iface:ZXRoMA", answer=AsyncMock(), edit_message_text=AsyncMock())
    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=create_query, effective_user=SimpleNamespace(id=5904)), SimpleNamespace()))
    proposal_id = create_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    approve_query = SimpleNamespace(data=f"tshark:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    live_result = {"success": True, "elapsed_seconds": 1.2, "offline_result": {"success": True}, "normalized_evidence": _tshark_normalized()}

    with patch("app.bot.handlers.upload.run_tshark_live_capture", return_value=live_result) as runner:
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=approve_query, effective_user=SimpleNamespace(id=5904)), SimpleNamespace()))

    runner.assert_called_once()
    assert runner.call_args.kwargs["user_id"] == 5904
    assert runner.call_args.kwargs["proposal_id"] == proposal_id
    assert runner.call_args.kwargs["request"]["interface"] == "eth0"
    assert "Running bounded capture" in approve_query.edit_message_text.call_args.args[0]
    assert "TShark PCAP Analysis" in approve_query.message.reply_text.call_args.args[0]
    assert get_upload_state(5904) is None


def test_tshark_live_reject_wrong_user_expired_and_mutated_request_fail_closed() -> None:
    clear_tshark_capture_proposals()
    settings = Settings(_env_file=None, tshark_live_interface_allowlist="eth0", tshark_live_max_duration_seconds=5, tshark_live_max_packet_count=25, tshark_live_max_file_size_kb=512)
    create_query = SimpleNamespace(data="tshark:iface:ZXRoMA", answer=AsyncMock(), edit_message_text=AsyncMock())
    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=create_query, effective_user=SimpleNamespace(id=5905)), SimpleNamespace()))
    proposal_id = create_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")

    reject_query = SimpleNamespace(data=f"tshark:reject:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock())
    asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=reject_query, effective_user=SimpleNamespace(id=5905)), SimpleNamespace()))
    assert "rejected" in reject_query.edit_message_text.call_args.args[0].lower()

    create_query = SimpleNamespace(data="tshark:iface:ZXRoMA", answer=AsyncMock(), edit_message_text=AsyncMock())
    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=create_query, effective_user=SimpleNamespace(id=5906)), SimpleNamespace()))
    proposal_id = create_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    wrong_user = SimpleNamespace(data=f"tshark:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    with patch("app.bot.handlers.upload.run_tshark_live_capture") as runner:
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=wrong_user, effective_user=SimpleNamespace(id=9999)), SimpleNamespace()))
    runner.assert_not_called()
    assert "denied for user" in wrong_user.edit_message_text.call_args.args[0]

    create_query = SimpleNamespace(data="tshark:iface:ZXRoMA", answer=AsyncMock(), edit_message_text=AsyncMock())
    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=create_query, effective_user=SimpleNamespace(id=5912)), SimpleNamespace()))
    proposal_id = create_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    import app.services.tshark_approval as approval_module

    proposal = get_tshark_capture_proposal(proposal_id)
    approval_module._proposals[proposal_id] = replace(proposal, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    expired = SimpleNamespace(data=f"tshark:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    with patch("app.bot.handlers.upload.run_tshark_live_capture") as runner:
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=expired, effective_user=SimpleNamespace(id=5912)), SimpleNamespace()))
    runner.assert_not_called()
    assert "not awaiting approval" in expired.edit_message_text.call_args.args[0]

    create_query = SimpleNamespace(data="tshark:iface:ZXRoMA", answer=AsyncMock(), edit_message_text=AsyncMock())
    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=create_query, effective_user=SimpleNamespace(id=5907)), SimpleNamespace()))
    proposal_id = create_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    import app.bot.handlers.upload as upload_module

    upload_module._tshark_live_contexts[proposal_id]["request"] = {**upload_module._tshark_live_contexts[proposal_id]["request"], "packet_count": 26}
    mutated = SimpleNamespace(data=f"tshark:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    with patch("app.bot.handlers.upload.run_tshark_live_capture", return_value={"success": False, "error_type": "approval_required", "error": "TShark approved capture details changed."}) as runner:
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=mutated, effective_user=SimpleNamespace(id=5907)), SimpleNamespace()))
    runner.assert_called_once()
    assert "Failed" in mutated.message.reply_text.call_args.args[0]


def test_tshark_assessment_live_success_and_permission_failure_persist_and_cleanup() -> None:
    clear_tshark_capture_proposals()
    assessment = create_assessment("TShark Live Assessment")
    settings = Settings(_env_file=None, tshark_live_interface_allowlist="eth0", tshark_live_max_duration_seconds=5, tshark_live_max_packet_count=25, tshark_live_max_file_size_kb=512)
    create_query = SimpleNamespace(data=f"tshark:iface_assessment:{assessment['id']}:ZXRoMA", answer=AsyncMock(), edit_message_text=AsyncMock())
    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=create_query, effective_user=SimpleNamespace(id=5908)), SimpleNamespace()))
    proposal_id = create_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    approve_query = SimpleNamespace(data=f"tshark:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    live_result = {"success": True, "elapsed_seconds": 1.2, "offline_result": {"success": True}, "normalized_evidence": _tshark_normalized()}

    with patch("app.bot.handlers.upload.run_tshark_live_capture", return_value=live_result):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=approve_query, effective_user=SimpleNamespace(id=5908)), SimpleNamespace()))

    scans = list_assessment_scans(assessment["id"])
    artifacts = list_assessment_artifacts(assessment["id"])
    assert scans[-1]["tool"] == "tshark"
    assert scans[-1]["status"] == "completed"
    assert artifacts[-1]["artifact_type"] == "tshark_normalized_evidence"
    assert "TShark: Completed" in approve_query.message.reply_text.call_args_list[-1].args[0]

    create_query = SimpleNamespace(data=f"tshark:iface_assessment:{assessment['id']}:ZXRoMA", answer=AsyncMock(), edit_message_text=AsyncMock())
    with (
        patch("app.bot.handlers.upload.get_settings", return_value=settings),
        patch("app.services.tshark_policy.get_settings", return_value=settings),
    ):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=create_query, effective_user=SimpleNamespace(id=5909)), SimpleNamespace()))
    proposal_id = create_query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].callback_data.removeprefix("tshark:approve:")
    approve_query = SimpleNamespace(data=f"tshark:approve:{proposal_id}", answer=AsyncMock(), edit_message_text=AsyncMock(), message=SimpleNamespace(reply_text=AsyncMock()))
    permission = {"success": False, "error_type": "permission_denied", "error": "TShark live capture could not start with the current interface permissions.", "elapsed_seconds": 0}

    with patch("app.bot.handlers.upload.run_tshark_live_capture", return_value=permission):
        asyncio.run(tshark_callback_handler(SimpleNamespace(callback_query=approve_query, effective_user=SimpleNamespace(id=5909)), SimpleNamespace()))

    assert list_assessment_scans(assessment["id"])[-1]["status"] == "failed"
    assert "current interface permissions" in approve_query.message.reply_text.call_args_list[0].args[0]
    assert "dumpcap" not in approve_query.message.reply_text.call_args_list[0].args[0]


def test_valid_tshark_pcap_upload_uses_safe_temp_file_and_cleans_up() -> None:
    user_id = 5301
    set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    update = _tshark_upload_update(user_id, file_name="client name.pcap", content=b"pcap-bytes")
    seen_paths = []

    def fake_runner(path):
        seen_paths.append(Path(path))
        assert Path(path).name.startswith("mongrel-tshark-")
        assert Path(path).suffix == ".pcap"
        assert Path(path).exists()
        return {"success": True, "capture_file": str(path), "output": "structured", "command": ["tshark", "-r", str(path)], "error": ""}

    with (
        patch("app.bot.handlers.upload.check_tshark_readiness", return_value={"ready": True}),
        patch("app.bot.handlers.upload.run_tshark_offline_analysis", side_effect=fake_runner) as runner,
        patch("app.bot.handlers.upload.normalize_tshark_result", return_value=_tshark_normalized()) as parser,
    ):
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    runner.assert_called_once()
    parser.assert_called_once()
    assert seen_paths and not seen_paths[0].exists()
    assert get_upload_state(user_id) is None
    text = update.message.reply_text.call_args.args[0]
    assert "TShark PCAP Analysis" in text
    assert "Packets: 2" in text
    assert "Bytes: 160" in text
    assert "connection is not compromise" in text.lower()


def test_valid_tshark_pcapng_upload_is_accepted() -> None:
    user_id = 5302
    set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    update = _tshark_upload_update(user_id, file_name="capture.pcapng", content=b"pcapng")

    with (
        patch("app.bot.handlers.upload.check_tshark_readiness", return_value={"ready": True}),
        patch("app.bot.handlers.upload.run_tshark_offline_analysis", return_value={"success": True, "capture_file": "tmp.pcapng", "output": ""}) as runner,
        patch("app.bot.handlers.upload.normalize_tshark_result", return_value=_tshark_normalized()),
    ):
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    runner.assert_called_once()
    assert get_upload_state(user_id) is None


def test_valid_tshark_assessment_upload_records_scan_artifact_and_dashboard() -> None:
    user_id = 5310
    assessment = create_assessment("Assessment PCAP")
    add_assessment_target(assessment["id"], address="example.com")
    set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    from app.bot.handlers.upload import set_tshark_assessment_upload_context

    set_tshark_assessment_upload_context(user_id, {"assessment_id": assessment["id"], "user_id": user_id})
    update = _tshark_upload_update(user_id, file_name="capture.pcap", content=b"pcap")
    runner_paths = []

    def fake_runner(path):
        runner_paths.append(str(path))
        return {"success": True, "capture_file": str(path), "output": "structured", "command": ["tshark", "-r", str(path)], "elapsed_seconds": 1.4}

    with (
        patch("app.bot.handlers.upload.check_tshark_readiness", return_value={"ready": True}),
        patch("app.bot.handlers.upload.run_tshark_offline_analysis", side_effect=fake_runner),
        patch("app.bot.handlers.upload.normalize_tshark_result", return_value=_tshark_normalized()),
    ):
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    scans = list_assessment_scans(assessment["id"])
    artifacts = list_assessment_artifacts(assessment["id"])
    assert scans[0]["tool"] == "tshark"
    assert scans[0]["status"] == "completed"
    assert scans[0]["target_id"] is None
    assert artifacts[0]["artifact_type"] == "tshark_normalized_evidence"
    assert artifacts[0]["scan_id"] == scans[0]["id"]
    assert '"packet_count": 2' in artifacts[0]["content"]
    assert runner_paths and "example.com" not in runner_paths[0]
    assert "-i" not in str(update.message.reply_text.call_args_list[0].args[0])
    assert "TShark PCAP Analysis" in update.message.reply_text.call_args_list[0].args[0]
    assert "TShark: Completed" in update.message.reply_text.call_args_list[-1].args[0]
    assert get_upload_state(user_id) is None
    assert get_tshark_assessment_upload_context(user_id) is None


def test_tshark_assessment_upload_failure_records_failed_scan_and_artifact() -> None:
    user_id = 5311
    assessment = create_assessment("Assessment PCAP Failure")
    set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    from app.bot.handlers.upload import set_tshark_assessment_upload_context

    set_tshark_assessment_upload_context(user_id, {"assessment_id": assessment["id"], "user_id": user_id})
    update = _tshark_upload_update(user_id, file_name="capture.pcap", content=b"pcap")
    normalized = _tshark_normalized(success=False)
    normalized["error_type"] = "timeout"

    with (
        patch("app.bot.handlers.upload.check_tshark_readiness", return_value={"ready": True}),
        patch("app.bot.handlers.upload.run_tshark_offline_analysis", return_value={"success": False, "capture_file": "tmp.pcap", "output": "", "error_type": "timeout", "error": "timeout", "elapsed_seconds": 2}),
        patch("app.bot.handlers.upload.normalize_tshark_result", return_value=normalized),
    ):
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    scans = list_assessment_scans(assessment["id"])
    artifacts = list_assessment_artifacts(assessment["id"])
    assert scans[0]["tool"] == "tshark"
    assert scans[0]["status"] == "failed"
    assert artifacts[0]["artifact_type"] == "tshark_normalized_evidence"
    assert '"error_type": "timeout"' in artifacts[0]["content"]
    assert "TShark: Failed" in update.message.reply_text.call_args_list[-1].args[0]


def test_tshark_assessment_upload_wrong_user_and_missing_assessment_are_blocked() -> None:
    from app.bot.handlers.upload import set_tshark_assessment_upload_context

    set_upload_state(5312, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    set_tshark_assessment_upload_context(5312, {"assessment_id": 999999, "user_id": 5312})
    update = _tshark_upload_update(5312, file_name="capture.pcap", content=b"pcap")
    with patch("app.bot.handlers.upload.run_tshark_offline_analysis") as runner:
        asyncio.run(upload_document_handler(update, SimpleNamespace()))
    assert "context is no longer valid" in update.message.reply_text.call_args.args[0]
    runner.assert_not_called()
    assert get_upload_state(5312) is None

    set_upload_state(5313, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    set_tshark_assessment_upload_context(5313, {"assessment_id": create_assessment("Wrong User")["id"], "user_id": 9999})
    update = _tshark_upload_update(5313, file_name="capture.pcap", content=b"pcap")
    with patch("app.bot.handlers.upload.run_tshark_offline_analysis") as runner:
        asyncio.run(upload_document_handler(update, SimpleNamespace()))
    assert "not authorized" in update.message.reply_text.call_args.args[0]
    runner.assert_not_called()
    assert get_upload_state(5313) is None


def test_tshark_standalone_upload_remains_unbound_to_assessment() -> None:
    user_id = 5314
    set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    update = _tshark_upload_update(user_id, file_name="capture.pcap", content=b"pcap")
    with (
        patch("app.bot.handlers.upload.check_tshark_readiness", return_value={"ready": True}),
        patch("app.bot.handlers.upload.run_tshark_offline_analysis", return_value={"success": True, "capture_file": "tmp.pcap", "output": "", "command": ["tshark", "-r", "tmp.pcap"]}),
        patch("app.bot.handlers.upload.normalize_tshark_result", return_value=_tshark_normalized()),
    ):
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    assert "TShark PCAP Analysis" in update.message.reply_text.call_args.args[0]
    assert not list_assessment_scans(create_assessment("No TShark Link")["id"])


def test_tshark_assessment_upload_cancel_clears_state() -> None:
    from app.bot.handlers.upload import set_tshark_assessment_upload_context

    user_id = 5315
    assessment = create_assessment("Cancel PCAP")
    set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    set_tshark_assessment_upload_context(user_id, {"assessment_id": assessment["id"], "user_id": user_id})
    message = SimpleNamespace(text="Cancel", reply_text=AsyncMock())

    asyncio.run(cancel_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=user_id)), SimpleNamespace(user_data={})))

    assert get_upload_state(user_id) is None
    assert get_tshark_assessment_upload_context(user_id) is None
    assert "Ask Mongrel session closed." in message.reply_text.call_args.args[0]


def test_tshark_upload_rejects_missing_invalid_empty_and_oversized_files() -> None:
    cases = [
        (5303, None, 4, b"pcap", "requires a .pcap or .pcapng filename"),
        (5304, "capture.txt", 4, b"pcap", "Please upload a .pcap or .pcapng file"),
        (5305, "capture.pcap", 0, b"", "TShark capture file is empty."),
        (5306, "capture.pcap", 30 * 1024 * 1024, b"pcap", "exceeds maximum size"),
    ]
    for user_id, file_name, file_size, content, expected in cases:
        set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
        update = _tshark_upload_update(user_id, file_name=file_name, file_size=file_size, content=content)
        with (
            patch("app.bot.handlers.upload.check_tshark_readiness", return_value={"ready": True}),
            patch("app.bot.handlers.upload.run_tshark_offline_analysis") as runner,
        ):
            asyncio.run(upload_document_handler(update, SimpleNamespace()))
        assert expected in update.message.reply_text.call_args.args[0]
        assert get_upload_state(user_id) is None
        runner.assert_not_called()


def test_tshark_upload_readiness_failure_clears_state_and_does_not_download() -> None:
    user_id = 5307
    set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    update = _tshark_upload_update(user_id)

    with patch("app.bot.handlers.upload.check_tshark_readiness", return_value={"ready": False, "error": "TShark is not installed <bad>"}) as readiness:
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    readiness.assert_called_once()
    update.message.document.get_file.assert_not_called()
    assert "TShark is not installed &lt;bad&gt;" in update.message.reply_text.call_args.args[0]
    assert get_upload_state(user_id) is None


def test_tshark_upload_runner_failure_and_timeout_render_bounded_card() -> None:
    user_id = 5308
    set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    update = _tshark_upload_update(user_id)
    normalized = _tshark_normalized(success=False)
    normalized["parser_warnings"] = ["Malformed row <script>"]
    normalized["truncation"] = {"output_truncated": True, "packets_truncated": True}

    with (
        patch("app.bot.handlers.upload.check_tshark_readiness", return_value={"ready": True}),
        patch("app.bot.handlers.upload.run_tshark_offline_analysis", return_value={"success": False, "error_type": "timeout", "error": "timeout <bad>", "command": ["tshark", "-r", "tmp.pcap"]}),
        patch("app.bot.handlers.upload.normalize_tshark_result", return_value=normalized),
    ):
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    text = update.message.reply_text.call_args.args[0]
    assert "Status:\nFailed" in text
    assert "Malformed row &lt;script&gt;" in text
    assert "timeout &lt;bad&gt;" in text
    assert "output_truncated" in text
    assert len(text) <= 3820
    assert get_upload_state(user_id) is None


def test_tshark_result_card_escapes_bounds_and_omits_sensitive_content() -> None:
    normalized = _tshark_normalized()
    normalized["http_observations"] = [
        {"method": "GET", "host": "example.com<script>", "uri": "/?token=<REDACTED>", "response_code": "200"},
        *[{"method": "GET", "host": f"h{index}.example", "uri": "/", "response_code": "200"} for index in range(200)],
    ]

    text = build_tshark_result_text(normalized, {"error": ""})

    assert "&lt;script&gt;" in text
    assert "secret-value" not in text
    assert "authorization" not in text.lower()
    assert "cookie" not in text.lower()
    assert "raw hex" not in text.lower()
    assert "Packet activity is not automatically malicious." in text
    assert "A DNS query is not exfiltration." in text
    assert len(text) <= 3820


def test_tshark_upload_confirms_no_live_capture_path() -> None:
    user_id = 5309
    set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
    update = _tshark_upload_update(user_id)

    with (
        patch("app.bot.handlers.upload.check_tshark_readiness", return_value={"ready": True}),
        patch("app.bot.handlers.upload.run_tshark_offline_analysis", return_value={"success": True, "capture_file": "tmp.pcap", "output": "", "command": ["tshark", "-r", "tmp.pcap"]}) as runner,
        patch("app.bot.handlers.upload.normalize_tshark_result", return_value=_tshark_normalized()),
    ):
        asyncio.run(upload_document_handler(update, SimpleNamespace()))

    command = runner.return_value["command"]
    assert "-r" in command
    assert "-i" not in command


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
    assert "Nuclei Scan Complete" in message.reply_text.call_args.args[0]


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
    assert "Nuclei Scan Complete" in message.reply_text.call_args.args[0]


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
    assert "Nuclei Scan Complete" in report
    assert "Target\nhttps://example.com" in report
    assert "Risk\nHIGH" in report
    assert "Findings detected: 2" in report
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
    assert "Nuclei Scan Complete" in message.reply_text.call_args.args[0]
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

    assert "Risk\nHIGH" in report
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
    assert "Risk\nMEDIUM" in build_nuclei_import_success_text(finding)


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
    assert reply_markup.inline_keyboard[1][0].text == "AI Summary"
    assert reply_markup.inline_keyboard[1][0].callback_data.startswith("ai_summary:nmap_xml:")
    assert reply_markup.inline_keyboard[2][0].text == "Explain with Mongrel AI"
    assert reply_markup.inline_keyboard[2][0].callback_data == UPLOAD_EXPLAIN_CALLBACK
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
    keyboard = build_upload_success_keyboard("finding-1", "nmap_xml")

    assert keyboard.inline_keyboard[1][0].text == "AI Summary"
    assert keyboard.inline_keyboard[1][0].callback_data == "ai_summary:nmap_xml:finding-1"
    assert keyboard.inline_keyboard[2][0].text == "Explain with Mongrel AI"
    assert keyboard.inline_keyboard[2][0].callback_data == UPLOAD_EXPLAIN_CALLBACK


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
