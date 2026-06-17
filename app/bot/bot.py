import logging

from telegram.ext import Application, CommandHandler, MessageHandler, filters
from telegram import Update
from telegram.ext import ContextTypes

from app.bot.handlers import home_handler, settings_handler, start_handler
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging

logger = logging.getLogger(__name__)


async def unavailable_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    await update.message.reply_text("This workflow is not available yet. Use Home or Settings for now.")


def build_application(settings: Settings) -> Application:
    if not settings.telegram_bot_token:
        raise ValueError("TELEGRAM_BOT_TOKEN is required to start the Telegram bot.")

    application = Application.builder().token(settings.telegram_bot_token).build()
    application.add_handler(CommandHandler("start", start_handler))
    application.add_handler(MessageHandler(filters.Regex("^Home$"), home_handler))
    application.add_handler(MessageHandler(filters.Regex("^Settings$"), settings_handler))
    application.add_handler(
        MessageHandler(
            filters.Regex("^(Scan|Upload|Findings|Ask Mongrel|Reports)$"),
            unavailable_handler,
        )
    )
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
