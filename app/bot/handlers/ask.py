import logging
from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.bot.handlers.assessment import (
    ASSESSMENT_ASK_TASK_KEY,
    ASSESSMENT_CHAT_CLOSED_KEY,
    ASSESSMENT_CHAT_STATE_KEY,
    ACTIVE_ASSESSMENT_ID_KEY,
    build_assessment_chat_intro,
    build_assessment_chat_keyboard,
    clear_assessment_flow_state,
    clear_assessment_chat_state,
    is_assessment_chat_active,
)
from app.services.active_scan_state import cancel_active_scan, clear_active_scan
from app.services.assessment_store import get_user_assessment, list_assessment_targets
from app.services.chat_state import clear_ai_waiting, clear_finding_analysis_context, is_finding_analysis_active, set_ai_waiting

logger = logging.getLogger(__name__)


def build_ask_text() -> str:
    return "Ask Mongrel anything. Cybersecurity is my specialty."


async def ask_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return
    context.user_data.pop(ASSESSMENT_CHAT_CLOSED_KEY, None)

    if is_assessment_chat_active(context):
        state = context.user_data.get(ASSESSMENT_CHAT_STATE_KEY)
        assessment_id = int(state.get(ACTIVE_ASSESSMENT_ID_KEY) or state.get("assessment_id"))
        user_id = update.effective_user.id if update.effective_user is not None else None
        assessment = get_user_assessment(user_id, assessment_id) if user_id is not None else None
        if assessment is not None:
            await update.message.reply_text(
                build_assessment_chat_intro(assessment, list_assessment_targets(assessment_id)),
                reply_markup=build_assessment_chat_keyboard(assessment_id),
            )
            return
        context.user_data.pop(ASSESSMENT_CHAT_STATE_KEY, None)

    if update.effective_user is not None:
        set_ai_waiting(update.effective_user.id)

    await update.message.reply_text(
        build_ask_text(),
        reply_markup=build_main_menu_keyboard(),
    )


def build_cancel_text() -> str:
    return "Ask Mongrel session closed."


async def cancel_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    already_closed = bool(context.user_data.get(ASSESSMENT_CHAT_CLOSED_KEY))
    assessment_exited = bool(
        context.user_data.get(ASSESSMENT_CHAT_STATE_KEY) or context.user_data.get(ASSESSMENT_ASK_TASK_KEY)
    )
    if assessment_exited:
        clear_assessment_chat_state(context)
    elif already_closed:
        return

    cancelled_scan = None
    exited_finding_analysis = False
    if update.effective_user is not None:
        clear_ai_waiting(update.effective_user.id)
        exited_finding_analysis = is_finding_analysis_active(update.effective_user.id)
        clear_finding_analysis_context(update.effective_user.id)
        clear_assessment_flow_state(context)
        from app.bot.handlers.upload import clear_upload_state

        clear_upload_state(update.effective_user.id)
        if exited_finding_analysis:
            logger.info("Finding analysis ended for user_id=%s", update.effective_user.id)
        cancelled_scan = cancel_active_scan(update.effective_user.id)
        if cancelled_scan is not None and cancelled_scan.status_message is not None:
            from app.ui.scan_progress import ScanProgressCard

            progress_card = ScanProgressCard.from_status_message(
                cancelled_scan.status_message,
                f"{cancelled_scan.scan_type.title()} Scan",
                cancelled_scan.target,
                cancelled_scan.progress_started_at,
            )
            await progress_card.update("Cancelled")
        clear_active_scan(update.effective_user.id)

    await update.message.reply_text(
        _build_cancel_response(cancelled_scan is not None, exited_finding_analysis),
        reply_markup=build_main_menu_keyboard(),
    )


def _build_cancel_response(scan_cancelled: bool, finding_analysis_exited: bool) -> str:
    if finding_analysis_exited:
        return "Exited Finding Analysis Mode."

    if scan_cancelled:
        return "Nuclei scan cancelled."

    return build_cancel_text()
