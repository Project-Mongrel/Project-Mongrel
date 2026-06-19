import logging

from telegram import Update
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

from app.bot.handlers import (
    ask_handler,
    findings_callback_handler,
    findings_handler,
    home_handler,
    reports_handler,
    scan_callback_handler,
    scan_handler,
    scan_target_handler,
    settings_handler,
    start_handler,
    upload_handler,
)
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging

logger = logging.getLogger(__name__)


def build_application(settings: Settings) -> Application:
    if not settings.telegram_bot_token:
        raise ValueError("TELEGRAM_BOT_TOKEN is required to start the Telegram bot.")

    application = Application.builder().token(settings.telegram_bot_token).build()
    application.add_handler(CommandHandler("start", start_handler))
    application.add_handler(MessageHandler(filters.Regex("^Home$"), home_handler))
    application.add_handler(MessageHandler(filters.Regex("^Scan$"), scan_handler))
    application.add_handler(MessageHandler(filters.Regex("^Upload$"), upload_handler))
    application.add_handler(MessageHandler(filters.Regex("^Findings$"), findings_handler))
    application.add_handler(MessageHandler(filters.Regex("^Ask Mongrel$"), ask_handler))
    application.add_handler(MessageHandler(filters.Regex("^Reports$"), reports_handler))
    application.add_handler(MessageHandler(filters.Regex("^Settings$"), settings_handler))
    application.add_handler(CallbackQueryHandler(scan_callback_handler, pattern="^(scan:(nmap|nuclei|bbot)|nav:home)$"))
    application.add_handler(CallbackQueryHandler(findings_callback_handler, pattern="^finding:(view:.+|list|clear)$"))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_target_handler))
    return application


def run_bot(settings: Settings | None = None) -> None:
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.log_level)

    if not resolved_settings.telegram_bot_token:
        logger.warning("TELEGRAM_BOT_TOKEN is not configured; Telegram bot was not started.")
        return

    logger.info("Starting Project Mongrel Telegram bot")
    build_application(resolved_settings).run_polling()


if __name__ == "__main__":
    run_bot()
