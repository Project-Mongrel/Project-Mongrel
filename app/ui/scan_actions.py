from telegram import InlineKeyboardButton, InlineKeyboardMarkup

AI_SUMMARY_CALLBACK_PREFIX = "ai_summary"
AI_SUMMARY_BUTTON_TEXT = "AI Summary"


def build_scan_result_actions(scan_id: str | None, tool: str | None) -> InlineKeyboardMarkup | None:
    if not scan_id or not tool:
        return None

    normalized_tool = str(tool).strip().lower()
    if not normalized_tool:
        return None

    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    AI_SUMMARY_BUTTON_TEXT,
                    callback_data=f"{AI_SUMMARY_CALLBACK_PREFIX}:{normalized_tool}:{scan_id}",
                )
            ]
        ]
    )
