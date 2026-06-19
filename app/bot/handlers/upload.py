from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.bot.handlers.scan import store_parsed_nmap_finding
from app.parsers.nmap_xml_parser import parse_nmap_xml

UPLOAD_STATE_AWAITING_NMAP_XML = "awaiting_nmap_xml"
MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024
_upload_states: dict[int, str] = {}


def build_upload_text() -> str:
    return (
        "Supported Uploads\n\n"
        "- Nmap XML (supported)\n"
        "- Nuclei (coming soon)\n"
        "- BBOT (coming soon)\n"
        "- Logs (coming soon)\n\n"
        "Send an Nmap XML file to begin analysis."
    )


def set_upload_state(user_id: int, state: str) -> None:
    _upload_states[user_id] = state


def get_upload_state(user_id: int) -> str | None:
    return _upload_states.get(user_id)


def clear_upload_state(user_id: int) -> None:
    _upload_states.pop(user_id, None)


def build_nmap_xml_import_success_text(finding: dict) -> str:
    return (
        "Nmap XML imported successfully.\n\n"
        f"Target: {finding.get('target', 'unknown')}\n\n"
        f"Open Ports: {len(finding.get('open_ports') or [])}\n\n"
        f"Risk: {str(finding.get('risk_level', 'unknown')).upper()}"
    )


async def upload_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is not None:
        set_upload_state(user_id, UPLOAD_STATE_AWAITING_NMAP_XML)

    await update.message.reply_text(
        build_upload_text(),
        reply_markup=build_main_menu_keyboard(),
    )


async def upload_document_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None or update.message.document is None:
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is None or get_upload_state(user_id) != UPLOAD_STATE_AWAITING_NMAP_XML:
        return

    document = update.message.document
    if not str(document.file_name or "").lower().endswith(".xml"):
        await update.message.reply_text("Please upload an Nmap XML file.")
        return

    if document.file_size is not None and document.file_size > MAX_UPLOAD_SIZE_BYTES:
        await update.message.reply_text("File exceeds maximum size.")
        return

    telegram_file = await document.get_file()
    file_bytes = await telegram_file.download_as_bytearray()

    try:
        parsed_output = parse_nmap_xml(bytes(file_bytes).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        await update.message.reply_text("Unable to parse Nmap XML file.")
        return

    finding = store_parsed_nmap_finding(user_id=user_id, parsed_output=parsed_output, source="nmap_xml")
    clear_upload_state(user_id)
    await update.message.reply_text(build_nmap_xml_import_success_text(finding))
