from telegram import InlineKeyboardButton, InlineKeyboardMarkup

AI_SUMMARY_CALLBACK_PREFIX = "ai_summary"
AI_SUMMARY_BUTTON_TEXT = "AI Summary"
SCAN_RECOVERY_CALLBACK_PREFIX = "scanrx"


def build_scan_recovery_actions(
    recovery_token: str | None,
    outcome: str,
    *,
    assessment_id: int | None = None,
) -> InlineKeyboardMarkup | None:
    if not recovery_token:
        return None

    normalized_outcome = str(outcome or "").strip().lower()
    rows = []
    if normalized_outcome == "success":
        rows.append([InlineKeyboardButton("Re-run Scan", callback_data=f"{SCAN_RECOVERY_CALLBACK_PREFIX}:rerun:{recovery_token}")])
    elif normalized_outcome == "failed":
        rows.append([InlineKeyboardButton("Re-run Scan", callback_data=f"{SCAN_RECOVERY_CALLBACK_PREFIX}:rerun:{recovery_token}")])
        rows.append([InlineKeyboardButton("✏️ Edit Target", callback_data=f"{SCAN_RECOVERY_CALLBACK_PREFIX}:edit_target:{recovery_token}")])
    elif normalized_outcome == "invalid":
        rows.append([InlineKeyboardButton("✏️ Edit Input", callback_data=f"{SCAN_RECOVERY_CALLBACK_PREFIX}:edit_input:{recovery_token}")])

    if not rows:
        return None

    if assessment_id is not None:
        rows.append([InlineKeyboardButton("Return to Assessment", callback_data=f"assessment:dashboard:{assessment_id}")])
    rows.append([InlineKeyboardButton("Scan Menu", callback_data=f"{SCAN_RECOVERY_CALLBACK_PREFIX}:menu:{recovery_token}")])

    return InlineKeyboardMarkup(rows)


def build_scan_result_actions(
    scan_id: str | None,
    tool: str | None,
    *,
    recovery_token: str | None = None,
    outcome: str = "success",
    assessment_id: int | None = None,
) -> InlineKeyboardMarkup | None:
    rows = []

    normalized_tool = str(tool).strip().lower()
    if scan_id and normalized_tool:
        rows.append(
            [
                InlineKeyboardButton(
                    AI_SUMMARY_BUTTON_TEXT,
                    callback_data=f"{AI_SUMMARY_CALLBACK_PREFIX}:{normalized_tool}:{scan_id}",
                )
            ]
        )

    recovery_actions = build_scan_recovery_actions(recovery_token, outcome, assessment_id=assessment_id)
    if recovery_actions is not None:
        rows.extend(recovery_actions.inline_keyboard)

    return InlineKeyboardMarkup(rows) if rows else None
