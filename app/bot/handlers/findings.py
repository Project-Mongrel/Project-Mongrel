from telegram import Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.findings_store import get_user_findings


def build_findings_text(findings: list[dict] | None = None) -> str:
    if not findings:
        return "No findings available yet."

    lines = ["Latest findings:"]
    for finding in reversed(findings[-5:]):
        open_ports = finding.get("open_ports") or []
        risk_notes = finding.get("risk_notes") or []
        lines.extend(
            [
                "",
                f"Source: {finding.get('source', 'unknown')}",
                f"Target: {finding.get('target', 'unknown')}",
                f"Host Status: {finding.get('host_status', 'unknown')}",
                f"Open Ports: {len(open_ports)}",
                f"Risk Level: {finding.get('risk_level', 'unknown')}",
                f"Risk Notes: {_format_risk_notes(risk_notes)}",
                f"Created At: {finding.get('created_at', 'unknown')}",
            ]
        )

    return "\n".join(lines)


def _format_risk_notes(risk_notes: object) -> str:
    if isinstance(risk_notes, list) and risk_notes:
        return ", ".join(str(note) for note in risk_notes)

    return "None"


async def findings_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    findings = get_user_findings(user_id) if user_id is not None else []

    await update.message.reply_text(
        build_findings_text(findings),
        reply_markup=build_main_menu_keyboard(),
    )
