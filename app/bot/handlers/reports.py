from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard


def build_reports_text() -> str:
    return "No reports generated yet."


async def reports_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    await update.message.reply_text(
        build_reports_text(),
        reply_markup=build_main_menu_keyboard(),
    )
