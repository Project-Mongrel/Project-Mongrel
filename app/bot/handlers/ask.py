from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard


def build_ask_text() -> str:
    return "Ask a security question. AI support is coming in a later mission."


async def ask_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    await update.message.reply_text(
        build_ask_text(),
        reply_markup=build_main_menu_keyboard(),
    )
