from telegram import Update
from telegram.ext import ContextTypes

from app.bot.auth import is_admin
from app.bot.keyboards import build_main_menu_keyboard
from app.core.config import Settings, get_settings


def build_settings_text(user_id: int | None, settings: Settings) -> str:
    telegram_id = str(user_id) if user_id is not None else "unknown"
    admin_status = "yes" if is_admin(user_id, settings) else "no"

    return (
        "Settings\n\n"
        f"Telegram ID: {telegram_id}\n"
        f"Admin: {admin_status}\n\n"
        "Secrets and bot tokens are never shown here."
    )


async def settings_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    await update.message.reply_text(
        build_settings_text(user_id, get_settings()),
        reply_markup=build_main_menu_keyboard(),
    )
