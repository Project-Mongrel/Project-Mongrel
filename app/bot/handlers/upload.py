from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard


def build_upload_text() -> str:
    return (
        "Upload center\n\n"
        "Supported upload types:\n"
        "- Nmap XML\n"
        "- Nuclei output\n"
        "- BBOT output\n"
        "- logs"
    )


async def upload_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    await update.message.reply_text(
        build_upload_text(),
        reply_markup=build_main_menu_keyboard(),
    )
