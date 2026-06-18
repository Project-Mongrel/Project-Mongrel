from app.bot.auth import is_admin
from app.bot.handlers.home import build_home_text
from app.bot.handlers.scan import (
    MAX_SCAN_OUTPUT_LENGTH,
    build_nmap_scan_result_text,
    build_nmap_target_prompt,
    build_scan_created_text,
    build_scan_text,
)
from app.bot.handlers.settings import build_settings_text
from app.bot.handlers.start import build_start_text
from app.bot.handlers.upload import build_upload_text
from app.bot.keyboards import MAIN_MENU_BUTTONS, build_main_menu_keyboard
from app.core.config import Settings


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
    assert "Choose a scan workflow" in build_scan_text()
    assert "pending" in build_scan_created_text("nmap")
    assert "authorized target" in build_nmap_target_prompt()
    assert "Nmap XML" in build_upload_text()


def test_nmap_result_text_reports_status_and_truncates_output() -> None:
    result_text = build_nmap_scan_result_text(
        {
            "success": True,
            "target": "example.com",
            "returncode": 0,
            "output": "x" * (MAX_SCAN_OUTPUT_LENGTH + 1),
            "error": "",
        }
    )

    assert "completed" in result_text
    assert "example.com" in result_text
    assert "[output truncated]" in result_text
