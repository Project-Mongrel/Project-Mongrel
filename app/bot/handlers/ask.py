from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.active_scan_state import cancel_active_scan, clear_active_scan
from app.services.chat_state import clear_ai_waiting, set_ai_waiting


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
    if update.effective_user is not None:
        clear_ai_waiting(update.effective_user.id)
        cancelled_scan = cancel_active_scan(update.effective_user.id)
        clear_active_scan(update.effective_user.id)

    await update.message.reply_text(
        "Nuclei scan cancelled." if cancelled_scan is not None else build_cancel_text(),
        reply_markup=build_main_menu_keyboard(),
    )
