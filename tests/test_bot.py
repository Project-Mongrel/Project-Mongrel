from app.bot.auth import is_admin
from app.bot.handlers.findings import build_findings_text
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
from app.services.findings_store import clear_user_findings, get_user_findings


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
    findings_text = build_findings_text(
        [
            {
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
        ]
    )

    assert "Latest findings:" in findings_text
    assert "Source: nmap" in findings_text
    assert "Target: 127.0.0.1" in findings_text
    assert "Host Status: Up" in findings_text
    assert "Open Ports: 2" in findings_text
    assert "Risk Level: high" in findings_text
    assert "Risk Notes: SMB exposed" in findings_text
    assert "Created At: 2026-06-18T12:00:00Z" in findings_text


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
    findings_text = build_findings_text(
        [
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
                "created_at": "2026-06-18T12:00:00Z",
                "risk_level": "high",
                "risk_notes": ["SMB exposed"],
            }
        ]
    )

    assert "Service: SMB" in findings_text
    assert "Description: Windows file sharing and remote administration service." in findings_text
    assert "Common Risk: File exposure and lateral movement." in findings_text
    assert "Recommendation: Block internet exposure." in findings_text
