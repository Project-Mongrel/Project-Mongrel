from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.active_scan_state import cancel_active_scan, clear_active_scan
from app.services.chat_state import clear_ai_waiting


def build_home_text() -> str:
    return (
        "Project Mongrel control panel\n\n"
        "Use this assistant for authorized defensive security work only.\n\n"
        "Available actions:\n"
        "- Home: return to this control panel\n"
        "- Scan: prepare authorized scan workflows\n"
        "- Upload Findings: send scan output for analysis\n"
        "- Findings: review security findings\n"
        "- Ask Mongrel: ask a defensive security question\n"
        "- Reports: prepare report workflows\n"
        "- Settings: view your Telegram profile context"
    )


async def home_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    if update.effective_user is not None:
        clear_ai_waiting(update.effective_user.id)
        cancel_active_scan(update.effective_user.id)
        clear_active_scan(update.effective_user.id)

    await update.message.reply_text(
        build_home_text(),
        reply_markup=build_main_menu_keyboard(),
    )
