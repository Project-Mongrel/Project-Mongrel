from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.findings_store import get_user_finding, get_user_findings


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
                f"ID: {finding.get('id', 'unknown')}",
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


def build_findings_keyboard(findings: list[dict] | None = None) -> InlineKeyboardMarkup | None:
    if not findings:
        return None

    buttons = [
        [InlineKeyboardButton(f"View Finding {finding.get('id')}", callback_data=f"finding:view:{finding.get('id')}")]
        for finding in reversed(findings[-5:])
        if finding.get("id")
    ]
    return InlineKeyboardMarkup(buttons) if buttons else None


def build_finding_detail_text(finding: dict | None) -> str:
    if finding is None:
        return "Finding not found."

    open_ports = finding.get("open_ports") or []
    risk_notes = finding.get("risk_notes") or []
    lines = [
        "Finding detail:",
        "",
        f"Source: {finding.get('source', 'unknown')}",
        f"Target: {finding.get('target', 'unknown')}",
        f"Host Status: {finding.get('host_status', 'unknown')}",
        f"Risk Level: {finding.get('risk_level', 'unknown')}",
        f"Risk Notes: {_format_risk_notes(risk_notes)}",
        f"Scan Duration: {finding.get('duration', 'unknown')}",
        f"Created At: {finding.get('created_at', 'unknown')}",
        "",
        "Open Ports:",
    ]

    if not open_ports:
        lines.append("No open ports found.")
    else:
        lines.extend(_format_open_port_intelligence(open_ports))

    return "\n".join(lines)


def build_finding_detail_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("Back to Findings", callback_data="finding:list")]])


def _format_risk_notes(risk_notes: object) -> str:
    if isinstance(risk_notes, list) and risk_notes:
        return ", ".join(str(note) for note in risk_notes)

    return "None"


def _format_open_port_intelligence(open_ports: list[dict]) -> list[str]:
    if not open_ports:
        return []

    lines = []
    for open_port in open_ports:
        intelligence = open_port.get("intelligence") or {}
        service_label = f"{open_port.get('port', '?')}/{open_port.get('protocol', '?')} {open_port.get('service', 'unknown')}"
        lines.extend(
            [
                service_label,
                f"Service: {intelligence.get('name', open_port.get('service', 'unknown'))}",
                f"Description: {intelligence.get('description', 'Description unavailable.')}",
                f"Common Risk: {intelligence.get('common_risk', 'Description unavailable.')}",
                f"Recommendation: {intelligence.get('recommendation', 'Manual review recommended.')}",
            ]
        )

    return lines


async def findings_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    findings = get_user_findings(user_id) if user_id is not None else []

    await update.message.reply_text(
        build_findings_text(findings),
        reply_markup=build_findings_keyboard(findings) or build_main_menu_keyboard(),
    )


async def findings_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return

    await query.answer()

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is None:
        await query.edit_message_text("Unable to identify Telegram user.")
        return

    findings = get_user_findings(user_id)
    if query.data == "finding:list":
        await query.edit_message_text(
            build_findings_text(findings),
            reply_markup=build_findings_keyboard(findings),
        )
        return

    if query.data is None or not query.data.startswith("finding:view:"):
        return

    finding_id = query.data.removeprefix("finding:view:")
    finding = get_user_finding(user_id=user_id, finding_id=finding_id)
    await query.edit_message_text(
        build_finding_detail_text(finding),
        reply_markup=build_finding_detail_keyboard(),
    )
