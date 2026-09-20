import logging
from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.bot.handlers.assessment import ASSESSMENT_CHAT_CLOSED_KEY, clear_assessment_flow_state
from app.services.active_scan_state import cancel_active_scan, clear_active_scan
from app.services.chat_state import clear_ai_waiting, clear_finding_analysis_context, is_finding_analysis_active

logger = logging.getLogger(__name__)


def build_home_text() -> str:
    return (
        "Project Mongrel control panel\n\n"
        "Use this assistant for authorized defensive security work only.\n\n"
        "Available actions:\n"
        "- Home: return to this control panel\n"
        "- New Assessment: create an assessment workspace\n"
        "- Previous Assessments: reopen saved assessment workspaces\n"
        "- Scan: prepare authorized scan workflows\n"
        "- Upload Findings: send scan output for analysis\n"
        "- Findings: review security findings\n"
        "- Ask Mongrel: ask a defensive security question\n"
        "- Reports: prepare report workflows\n"
        "- Settings: view your Telegram profile context"
    )


async def home_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    if update.effective_user is not None:
        clear_ai_waiting(update.effective_user.id)
        finding_analysis_exited = is_finding_analysis_active(update.effective_user.id)
        clear_finding_analysis_context(update.effective_user.id)
        clear_assessment_flow_state(context)
        if finding_analysis_exited:
            logger.info("Finding analysis ended for user_id=%s", update.effective_user.id)
        cancelled_scan = cancel_active_scan(update.effective_user.id)
        native_cancellation = bool(
            cancelled_scan is not None
            and cancelled_scan.cancellation_event is not None
            and cancelled_scan.cancellation_requested
        )
        if cancelled_scan is not None and cancelled_scan.status_message is not None:
            from app.ui.scan_progress import ScanProgressCard

            progress_card = ScanProgressCard.from_status_message(
                cancelled_scan.status_message,
                f"{cancelled_scan.scan_type.title()} Scan",
                cancelled_scan.target,
                cancelled_scan.progress_started_at,
            )
            await progress_card.update("Cancellation requested" if native_cancellation else "Cancelled")
        if cancelled_scan is not None and cancelled_scan.cancellation_event is None:
            clear_active_scan(update.effective_user.id, cancelled_scan)
        if finding_analysis_exited:
            await update.message.reply_text("Exited Finding Analysis Mode.")

    await update.message.reply_text(
        build_home_text(),
        reply_markup=build_main_menu_keyboard(),
    )
    user_data = getattr(context, "user_data", None)
    if isinstance(user_data, dict):
        user_data.pop(ASSESSMENT_CHAT_CLOSED_KEY, None)
