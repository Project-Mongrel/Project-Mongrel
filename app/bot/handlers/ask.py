from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.chat_state import set_ai_waiting


def build_ask_text() -> str:
    return "Ask a cybersecurity question."


async def ask_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    if update.effective_user is not None:
        set_ai_waiting(update.effective_user.id)

    await update.message.reply_text(
        build_ask_text(),
        reply_markup=build_main_menu_keyboard(),
    )
