import logging

from telegram import Update
from telegram.error import BadRequest, Conflict, Forbidden, InvalidToken, NetworkError, TelegramError
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

from app.bot.handlers import (
    ask_handler,
    assessment_callback_handler,
    cancel_handler,
    findings_callback_handler,
    findings_handler,
    home_handler,
    new_assessment_handler,
    previous_assessments_handler,
    reports_handler,
    reports_callback_handler,
    scan_callback_handler,
    scan_handler,
    scan_target_handler,
    settings_handler,
    start_handler,
    tshark_callback_handler,
    tool_mode_callback_handler,
    upload_document_handler,
    upload_callback_handler,
    upload_handler,
)
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.services.assessment_store import recover_interrupted_assessment_scans
from app.services.active_scan_state import cancel_all_active_scans, clear_all_active_scans
from app.tools.process_lifecycle import _cleanup_active_scanners

logger = logging.getLogger(__name__)
SCAN_CALLBACK_PATTERN = "^(scan:(nmap|nuclei|bbot|httpx|katana|playwright|ffuf|testssl|gitleaks|prowler|metasploit|tshark)|scanrx:.+|ffufp:.+|bbot_ai:.+|ai_summary:.+|glev:.+|glrv:.+|glcx:.+|msf:.+|nav:home)$"
GENERIC_TELEGRAM_ERROR = "Mongrel could not complete that request. Please try again or review the service status."
TELEGRAM_BOOTSTRAP_RETRIES = 3
TELEGRAM_FATAL_ERROR_KEY = "telegram_fatal_error"


class TelegramPollingFatalError(RuntimeError):
    pass


async def telegram_error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Log protected diagnostics while keeping Telegram error responses generic."""

    error = getattr(context, "error", None)
    application = getattr(context, "application", None)
    if update is None and isinstance(error, (Conflict, InvalidToken, Forbidden)):
        category = "conflict" if isinstance(error, Conflict) else "authentication"
        logger.critical("Fatal Telegram polling failure: category=%s type=%s.", category, type(error).__name__)
        if application is not None:
            application.bot_data[TELEGRAM_FATAL_ERROR_KEY] = category
            application.stop_running()
        return
    if update is None and isinstance(error, BadRequest):
        logger.critical("Fatal Telegram polling failure: category=telegram_api type=%s.", type(error).__name__)
        if application is not None:
            application.bot_data[TELEGRAM_FATAL_ERROR_KEY] = "telegram_api"
            application.stop_running()
        return
    if update is None and isinstance(error, NetworkError):
        logger.warning("Temporary Telegram polling failure: type=%s; PTB retry remains active.", type(error).__name__)
        return
    if update is None and isinstance(error, TelegramError):
        logger.critical("Fatal Telegram polling failure: category=telegram_api type=%s.", type(error).__name__)
        if application is not None:
            application.bot_data[TELEGRAM_FATAL_ERROR_KEY] = "telegram_api"
            application.stop_running()
        return

    logger.error("Unhandled Telegram update error: type=%s", type(error).__name__)
    try:
        callback_query = getattr(update, "callback_query", None)
        message = getattr(update, "effective_message", None)
        if callback_query is not None:
            await callback_query.answer(GENERIC_TELEGRAM_ERROR, show_alert=True)
        elif message is not None:
            await message.reply_text(GENERIC_TELEGRAM_ERROR)
    except Exception as notification_error:
        logger.warning("Unable to send generic Telegram error response: type=%s", type(notification_error).__name__)


async def telegram_post_stop(application: Application) -> None:
    """Request scanner cancellation and enforce process-tree cleanup on shutdown."""

    active_scans = cancel_all_active_scans()
    _cleanup_active_scanners()
    clear_all_active_scans()
    if active_scans:
        logger.info("Shutdown cleanup requested for %d active scanner(s).", len(active_scans))


def build_application(settings: Settings) -> Application:
    if not settings.telegram_bot_token:
        raise ValueError("TELEGRAM_BOT_TOKEN is required to start the Telegram bot.")

    application = Application.builder().token(settings.telegram_bot_token).post_stop(telegram_post_stop).build()
    application.add_handler(CommandHandler("start", start_handler))
    application.add_handler(CommandHandler("home", home_handler))
    application.add_handler(CommandHandler("cancel", cancel_handler))
    application.add_handler(MessageHandler(filters.Regex("^Home$"), home_handler))
    application.add_handler(MessageHandler(filters.Regex("^New Assessment$"), new_assessment_handler))
    application.add_handler(MessageHandler(filters.Regex("^Previous Assessments$"), previous_assessments_handler))
    application.add_handler(MessageHandler(filters.Regex("^Scan$"), scan_handler))
    application.add_handler(MessageHandler(filters.Regex("^(Upload|Upload Findings)$"), upload_handler))
    application.add_handler(MessageHandler(filters.Regex("^Findings$"), findings_handler))
    application.add_handler(MessageHandler(filters.Regex("^Ask Mongrel$"), ask_handler))
    application.add_handler(MessageHandler(filters.Regex("^Cancel$"), cancel_handler))
    application.add_handler(MessageHandler(filters.Regex("^Reports$"), reports_handler))
    application.add_handler(MessageHandler(filters.Regex("^Settings$"), settings_handler))
    application.add_handler(CallbackQueryHandler(tool_mode_callback_handler, pattern="^toolmode:"))
    application.add_handler(CallbackQueryHandler(scan_callback_handler, pattern=SCAN_CALLBACK_PATTERN))
    application.add_handler(CallbackQueryHandler(tshark_callback_handler, pattern="^tshark:"))
    application.add_handler(CallbackQueryHandler(assessment_callback_handler, pattern="^assessment:"))
    application.add_handler(CallbackQueryHandler(findings_callback_handler, pattern="^(finding:(view:.+|list|clear)|explain:finding:.+)$"))
    application.add_handler(CallbackQueryHandler(reports_callback_handler, pattern="^report:"))
    application.add_handler(CallbackQueryHandler(upload_callback_handler, pattern="^upload:explain_ai$"))
    application.add_handler(MessageHandler(filters.Document.ALL, upload_document_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_target_handler))
    application.add_error_handler(telegram_error_handler)
    return application


def run_bot(settings: Settings | None = None) -> None:
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.log_level)

    if not resolved_settings.telegram_bot_token:
        logger.warning("TELEGRAM_BOT_TOKEN is not configured; Telegram bot was not started.")
        raise TelegramPollingFatalError("Telegram bot credentials are not configured.")

    logger.info(
        "AI config: enabled=%s provider=%s ollama_base_url=%s ollama_model=%s",
        resolved_settings.ai_enabled,
        resolved_settings.ai_provider,
        resolved_settings.ollama_base_url or "<empty>",
        resolved_settings.ollama_model,
    )
    logger.info("Starting Project Mongrel Telegram bot")
    recovered_scans = recover_interrupted_assessment_scans()
    if recovered_scans:
        logger.warning("Marked %d abandoned assessment scan(s) as interrupted.", recovered_scans)
    application = build_application(resolved_settings)
    try:
        application.run_polling(
            bootstrap_retries=TELEGRAM_BOOTSTRAP_RETRIES,
            drop_pending_updates=False,
        )
    except (InvalidToken, Forbidden):
        raise TelegramPollingFatalError("Telegram authentication failed.") from None
    except Conflict:
        raise TelegramPollingFatalError("Telegram polling conflict detected.") from None
    except NetworkError:
        raise TelegramPollingFatalError("Telegram bootstrap network recovery was exhausted.") from None
    fatal_category = application.bot_data.get(TELEGRAM_FATAL_ERROR_KEY)
    if fatal_category:
        raise TelegramPollingFatalError(f"Telegram polling stopped after fatal {fatal_category} failure.")


if __name__ == "__main__":
    run_bot()
