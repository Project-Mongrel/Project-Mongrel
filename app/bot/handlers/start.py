from telegram import Update
from telegram.ext import ContextTypes

from app.bot.handlers.home import build_home_text
from app.bot.keyboards import build_main_menu_keyboard


def build_start_text(first_name: str | None = None) -> str:
    greeting_name = f", {first_name}" if first_name else ""

    return (
        f"Welcome to Project Mongrel{greeting_name}.\n\n"
        f"{build_home_text()}"
    )


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    first_name = update.effective_user.first_name if update.effective_user is not None else None
    await update.message.reply_text(
        build_start_text(first_name),
        reply_markup=build_main_menu_keyboard(),
    )
