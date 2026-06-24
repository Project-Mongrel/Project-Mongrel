import logging
from datetime import UTC, datetime

from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.active_scan_state import cancel_active_scan, clear_active_scan
from app.services.chat_state import clear_ai_waiting, clear_finding_analysis_context, is_finding_analysis_active, set_ai_waiting

logger = logging.getLogger(__name__)


def build_ask_text() -> str:
    return "Ask Mongrel anything. Cybersecurity is my specialty."


async def ask_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

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

    cancelled_scan = None
    exited_finding_analysis = False
    if update.effective_user is not None:
        clear_ai_waiting(update.effective_user.id)
        exited_finding_analysis = is_finding_analysis_active(update.effective_user.id)
        clear_finding_analysis_context(update.effective_user.id)
        if exited_finding_analysis:
            logger.info("Finding analysis ended for user_id=%s", update.effective_user.id)
        cancelled_scan = cancel_active_scan(update.effective_user.id)
        if cancelled_scan is not None and cancelled_scan.status_message is not None:
            from app.bot.handlers.scan import build_nuclei_status_card, _edit_status_message

            elapsed_seconds = int((datetime.now(UTC) - cancelled_scan.started_at).total_seconds())
            await _edit_status_message(
                cancelled_scan.status_message,
                build_nuclei_status_card(cancelled_scan.target, "Cancelled", elapsed_seconds),
            )
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
