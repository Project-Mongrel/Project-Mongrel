from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.findings_store import clear_user_findings, get_user_finding, get_user_findings
from app.services.verdict_engine import generate_mongrel_verdict

MAX_FINDINGS_MESSAGE_LENGTH = 3800
MAX_LATEST_FINDINGS = 5


def build_findings_text(findings: list[dict] | None = None) -> str:
    if not findings:
        return "No findings available yet."

    lines = ["Latest Findings"]
    for index, finding in enumerate(_latest_findings(findings), start=1):
        open_ports = finding.get("open_ports") or []
        risk_notes = finding.get("risk_notes") or []
        lines.extend(
            [
                "",
                f"#{index} {_format_risk_level(finding.get('risk_level'))} - {finding.get('source', 'unknown')}",
                f"Target: {finding.get('target', 'unknown')}",
                f"Host: {finding.get('host_status', 'unknown')}",
                f"Open Ports: {len(open_ports)}",
                f"Notes: {_format_risk_notes(risk_notes)}",
            ]
        )

    return _truncate_message("\n".join(lines))


def build_findings_keyboard(findings: list[dict] | None = None) -> InlineKeyboardMarkup | None:
    if not findings:
        return None

    buttons = []
    for index, finding in enumerate(_latest_findings(findings), start=1):
        if finding.get("id"):
            buttons.append(
                [InlineKeyboardButton(f"View Details #{index}", callback_data=f"finding:view:{finding.get('id')}")]
            )

    buttons.append([InlineKeyboardButton("Clear Findings", callback_data="finding:clear")])
    return InlineKeyboardMarkup(buttons) if buttons else None


def build_finding_detail_text(finding: dict | None, display_number: int | None = None) -> str:
    if finding is None:
        return "Finding not found."

    open_ports = finding.get("open_ports") or []
    verdict = generate_mongrel_verdict(finding)
    title = f"Finding #{display_number}" if display_number is not None else "Finding"
    lines = [
        "Mongrel Verdict",
        "",
        f"Target: {finding.get('target', 'unknown')}",
        "",
        f"{_format_risk_level(verdict.get('risk_level'))} RISK",
        "",
        "Summary:",
        str(verdict.get("summary", "")),
        "",
        "Key Findings:",
        *_format_bullets(verdict.get("key_findings") or []),
        "",
        "Recommended Actions:",
        *_format_bullets(verdict.get("recommended_actions") or []),
        "",
        "--------------------------------",
        "",
        "Comparison",
        *_format_comparison(finding.get("comparison")),
        "",
        "--------------------------------",
        "",
        "Technical Details",
        "",
        title,
        "",
        f"Target: {finding.get('target', 'unknown')}",
        f"Host Status: {finding.get('host_status', 'unknown')}",
        f"Risk: {_format_risk_level(finding.get('risk_level'))}",
        f"Duration: {finding.get('duration', 'unknown')}",
        f"Created At: {finding.get('created_at', 'unknown')}",
        "",
        "Open Ports:",
    ]

    if not open_ports:
        lines.append("No open ports found.")
    else:
        lines.extend(_format_open_port_intelligence(open_ports))

    return _truncate_message("\n".join(lines))


def build_finding_detail_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("Back to Findings", callback_data="finding:list")]])


def _format_risk_notes(risk_notes: object) -> str:
    if isinstance(risk_notes, list) and risk_notes:
        return ", ".join(str(note) for note in risk_notes)

    return "None"


def _format_risk_level(risk_level: object) -> str:
    return str(risk_level or "unknown").upper()


def _format_bullets(items: list[str]) -> list[str]:
    if not items:
        return ["- None"]

    return [f"- {item}" for item in items]


def _format_comparison(comparison: object) -> list[str]:
    if not isinstance(comparison, dict):
        return ["No previous scan found for this target."]

    lines = [str(comparison.get("summary", "No previous scan found for this target."))]
    lines.extend(
        [
            f"New Ports: {_format_ports(comparison.get('new_ports') or [])}",
            f"Removed Ports: {_format_ports(comparison.get('removed_ports') or [])}",
            f"Risk Change: {_format_detail_risk_change(comparison)}",
            f"Unchanged Ports: {len(comparison.get('unchanged_ports') or [])}",
        ]
    )

    return lines


def _format_ports(open_ports: list[dict]) -> str:
    if not open_ports:
        return "none"

    return ", ".join(
        f"{open_port.get('port')}/{open_port.get('protocol')} {open_port.get('service')}" for open_port in open_ports
    )


def _format_detail_risk_change(comparison: dict) -> str:
    if comparison.get("risk_changed"):
        return f"{str(comparison.get('previous_risk')).upper()} -> {str(comparison.get('current_risk')).upper()}"

    return "none"


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
                f"{intelligence.get('description', 'Description unavailable.')}",
                f"Risk: {intelligence.get('common_risk', 'Description unavailable.')}",
                f"Recommendation: {intelligence.get('recommendation', 'Manual review recommended.')}",
                "",
            ]
        )

    return lines


def _latest_findings(findings: list[dict]) -> list[dict]:
    return list(reversed(findings[-MAX_LATEST_FINDINGS:]))


def _find_display_number(findings: list[dict], finding_id: str) -> int | None:
    for index, finding in enumerate(_latest_findings(findings), start=1):
        if finding.get("id") == finding_id:
            return index

    return None


def _truncate_message(message: str) -> str:
    if len(message) <= MAX_FINDINGS_MESSAGE_LENGTH:
        return message

    return f"{message[:MAX_FINDINGS_MESSAGE_LENGTH]}\n\n[output truncated]"


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

    if query.data == "finding:clear":
        clear_user_findings(user_id)
        await query.edit_message_text("No findings available yet.")
        return

    if query.data is None or not query.data.startswith("finding:view:"):
        return

    finding_id = query.data.removeprefix("finding:view:")
    finding = get_user_finding(user_id=user_id, finding_id=finding_id)
    await query.edit_message_text(
        build_finding_detail_text(finding, display_number=_find_display_number(findings, finding_id)),
        reply_markup=build_finding_detail_keyboard(),
    )
