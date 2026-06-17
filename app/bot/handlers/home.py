from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard


def build_home_text() -> str:
    return (
        "Project Mongrel control panel\n\n"
        "Use this assistant for authorized defensive security work only.\n\n"
        "Available actions:\n"
        "- Home: return to this control panel\n"
        "- Scan: prepare authorized scan workflows\n"
        "- Upload: send scan output for future analysis\n"
        "- Findings: review security findings\n"
        "- Ask Mongrel: ask a defensive security question\n"
        "- Reports: prepare report workflows\n"
        "- Settings: view your Telegram profile context"
    )


async def home_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    await update.message.reply_text(
        build_home_text(),
        reply_markup=build_main_menu_keyboard(),
    )
