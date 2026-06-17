from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard


def build_findings_text() -> str:
    return "No findings available yet."


async def findings_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    await update.message.reply_text(
        build_findings_text(),
        reply_markup=build_main_menu_keyboard(),
    )
