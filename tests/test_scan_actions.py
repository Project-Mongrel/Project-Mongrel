from app.ui.scan_actions import build_scan_result_actions


def test_build_scan_result_actions_uses_shared_ai_summary_button() -> None:
    keyboard = build_scan_result_actions("finding-1", "NMAP")

    assert keyboard is not None
    assert keyboard.inline_keyboard[0][0].text == "Summarize with AI"
    assert keyboard.inline_keyboard[0][0].callback_data == "ai_summary:nmap:finding-1"


def test_build_scan_result_actions_requires_identifier_and_tool() -> None:
    assert build_scan_result_actions(None, "nmap") is None
    assert build_scan_result_actions("finding-1", "") is None
