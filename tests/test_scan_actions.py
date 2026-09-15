from app.ui.scan_actions import build_scan_recovery_actions, build_scan_result_actions


def test_build_scan_result_actions_uses_shared_ai_summary_button() -> None:
    keyboard = build_scan_result_actions("finding-1", "NMAP")

    assert keyboard is not None
    assert keyboard.inline_keyboard[0][0].text == "AI Summary"
    assert keyboard.inline_keyboard[0][0].callback_data == "ai_summary:nmap:finding-1"


def test_build_scan_result_actions_requires_identifier_and_tool() -> None:
    assert build_scan_result_actions(None, "nmap") is None
    assert build_scan_result_actions("finding-1", "") is None


def test_build_scan_result_actions_appends_success_recovery_buttons() -> None:
    keyboard = build_scan_result_actions("finding-1", "nmap", recovery_token="tok123", assessment_id=42)

    assert keyboard is not None
    assert [row[0].text for row in keyboard.inline_keyboard] == [
        "AI Summary",
        "Re-run Scan",
        "Return to Assessment",
        "Scan Menu",
    ]
    assert keyboard.inline_keyboard[1][0].callback_data == "scanrx:rerun:tok123"
    assert keyboard.inline_keyboard[2][0].callback_data == "assessment:dashboard:42"


def test_build_scan_recovery_actions_uses_failed_and_invalid_variants() -> None:
    failed = build_scan_recovery_actions("tok123", "failed")
    invalid = build_scan_recovery_actions("tok456", "invalid")

    assert failed is not None
    assert [row[0].text for row in failed.inline_keyboard] == [
        "🔄 Run Again",
        "✏️ Edit Target",
        "✦ Ask Mongrel",
        "⬅️ Back to Tools",
    ]
    assert invalid is not None
    assert [row[0].text for row in invalid.inline_keyboard] == ["✏️ Edit Input", "Scan Menu"]
