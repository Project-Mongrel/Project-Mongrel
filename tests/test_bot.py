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
    build_nmap_scan_result_text,
    build_nmap_target_prompt,
    build_scan_created_text,
    build_scan_text,
    store_successful_nmap_finding,
)
from app.bot.handlers.settings import build_settings_text
from app.bot.handlers.start import build_start_text
from app.bot.handlers.upload import build_upload_text
from app.bot.keyboards import MAIN_MENU_BUTTONS, build_main_menu_keyboard
from app.core.config import Settings
from app.services.findings_store import add_finding, clear_user_findings, get_user_findings


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
    assert finding["host_status"] == "Up"
    assert finding["open_ports"][0]["port"] == "22"
    assert finding["open_ports"][0]["protocol"] == "tcp"
    assert finding["open_ports"][0]["service"] == "ssh"
    assert finding["duration"] == "0.32s"
    assert finding["risk_level"] == "medium"
    assert finding["risk_notes"] == ["SSH exposed"]
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
