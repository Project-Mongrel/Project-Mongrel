import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.bot.auth import is_admin
from app.bot.handlers.findings import (
    MAX_FINDINGS_MESSAGE_LENGTH,
    build_finding_detail_keyboard,
    build_finding_detail_text,
    build_findings_keyboard,
    build_findings_text,
    findings_callback_handler,
    findings_handler,
)
from app.bot.handlers.home import build_home_text
from app.bot.handlers.scan import (
    append_change_summary,
    build_nmap_scan_result_text,
    build_nmap_target_prompt,
    build_scan_created_text,
    build_scan_text,
    store_successful_nmap_finding,
)
from app.bot.handlers.settings import build_settings_text
from app.bot.handlers.start import build_start_text
from app.bot.handlers.upload import build_upload_text
from app.bot.handlers.upload import (
    UPLOAD_STATE_AWAITING_NMAP_XML,
    build_nmap_xml_import_success_text,
    build_upload_success_keyboard,
    clear_upload_state,
    get_upload_state,
    set_upload_state,
    upload_document_handler,
)
from app.bot.keyboards import MAIN_MENU_BUTTONS, build_main_menu_keyboard
from app.core.config import Settings
from app.services.findings_store import add_finding, clear_user_findings, get_user_findings
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
    assert "Send an Nmap XML file to begin analysis." in build_upload_text()


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

    assert message.reply_text.call_args.args[0] == "Please upload an Nmap XML file."


def test_uploaded_scan_creates_finding() -> None:
    clear_user_findings(5002)
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
    assert "Nmap XML Imported" in success_text
    assert "MEDIUM RISK" in success_text
    assert "- SSH remote administration service exposed." in success_text
    assert "Analysis stored successfully." in success_text
    assert "Comparison" in success_text
    assert "No previous scan found for this target." in success_text
    assert "This scan has been stored as the baseline for future comparisons." in success_text
    assert "Impact Assessment" in success_text
    assert "Change Impact: N/A" in success_text
    assert "No historical comparison available." in success_text
    assert reply_markup.inline_keyboard[0][0].text == "Open Findings"
    assert reply_markup.inline_keyboard[0][0].callback_data == "finding:list"


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

    assert "HIGH RISK" in success_text


def test_upload_success_includes_key_findings() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "192.168.0.24",
            "risk_level": "high",
            "open_ports": [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}],
        }
    )

    assert "Top Findings:" in success_text
    assert "- Windows SMB file sharing service exposed." in success_text


def test_upload_success_includes_open_findings_button() -> None:
    keyboard = build_upload_success_keyboard()

    assert keyboard.inline_keyboard[0][0].text == "Open Findings"
    assert keyboard.inline_keyboard[0][0].callback_data == "finding:list"


def test_upload_success_no_findings_fallback_message() -> None:
    success_text = build_nmap_xml_import_success_text(
        {
            "target": "192.168.0.24",
            "risk_level": "low",
            "open_ports": [],
        }
    )

    assert "- No significant findings identified." in success_text


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
