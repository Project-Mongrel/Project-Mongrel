import asyncio
import logging

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.ai_client import ask_ai
from app.services.chat_state import clear_finding_analysis_context, set_finding_analysis_context
from app.services.findings_store import clear_user_findings, get_user_finding, get_user_findings
from app.services.icon_helper import section_label
from app.services.verdict_engine import generate_mongrel_verdict

MAX_FINDINGS_MESSAGE_LENGTH = 3800
MAX_LATEST_FINDINGS = 5
logger = logging.getLogger(__name__)


def build_findings_text(findings: list[dict] | None = None) -> str:
    if not findings:
        return "No findings available yet."

    lines = [section_label("observation", "Latest Findings")]
    for index, finding in enumerate(_latest_findings(findings), start=1):
        if _is_clean_nuclei_scan(finding):
            lines.extend(
                [
                    "",
                    section_label("nuclei", "Nuclei Clean Scan"),
                    f"Target: {finding.get('target', 'unknown')}",
                    "Result: No selected templates matched",
                    f"Findings: {finding.get('finding_count', 0)}",
                    f"Risk Level: {_format_risk_level(finding.get('risk_level'))}",
                ]
            )
            continue

        open_ports = finding.get("open_ports") or []
        risk_notes = finding.get("risk_notes") or []
        lines.extend(
            [
                "",
                f"#{index} {_format_risk_level(finding.get('risk_level'))} - {_source_with_icon(finding.get('source', 'unknown'))}",
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

    if _is_clean_nuclei_scan(finding):
        return _truncate_message(
            "\n".join(
                [
                    section_label("nuclei", "Nuclei Clean Scan"),
                    "",
                    f"Target: {finding.get('target', 'unknown')}",
                    "Result: No selected templates matched",
                    f"Findings: {finding.get('finding_count', 0)}",
                    f"Risk Level: {_format_risk_level(finding.get('risk_level'))}",
                    f"Created At: {finding.get('created_at', 'unknown')}",
                    "",
                    "Summary:",
                    _format_clean_nuclei_summary(finding),
                ]
            )
        )

    open_ports = finding.get("open_ports") or []
    verdict = generate_mongrel_verdict(finding)
    title = f"Finding #{display_number}" if display_number is not None else "Finding"
    lines = [
        section_label("mongrel_ai", "Mongrel Verdict"),
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
        section_label("statistics", "Comparison"),
        *_format_comparison(finding.get("comparison")),
        "",
        "--------------------------------",
        "",
        section_label("risk", "Impact Assessment"),
        *_format_impact(finding.get("impact"), finding.get("comparison")),
        "",
        "--------------------------------",
        "",
        section_label("observation", "Technical Details"),
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


def build_finding_detail_keyboard(finding_id: str | None = None) -> InlineKeyboardMarkup:
    buttons = []
    if finding_id:
        buttons.append([InlineKeyboardButton("Explain with Mongrel AI", callback_data=f"explain:finding:{finding_id}")])

    buttons.append([InlineKeyboardButton("Back to Findings", callback_data="finding:list")])
    return InlineKeyboardMarkup(buttons)


def build_finding_ai_prompt(finding: dict) -> str | None:
    if _is_clean_nuclei_scan(finding):
        return _build_clean_nuclei_ai_prompt(finding)

    if finding.get("source") == "nuclei":
        return _build_nuclei_ai_prompt(finding)

    if finding.get("source") in {"nmap", "nmap_xml"}:
        return _build_nmap_ai_prompt(finding)

    return None


def build_finding_analysis_mode_text(finding: dict) -> str:
    return "\n".join(
        [
            "------------------",
            "Finding Analysis Mode",
            f"Target: {finding.get('target', 'unknown')}",
            "",
            "You can now ask follow-up questions about this finding.",
            "",
            "Use Home or Cancel to exit.",
            "------------------",
        ]
    )


def build_finding_analysis_context(finding: dict) -> dict:
    return {
        "finding_id": finding.get("id"),
        "source": finding.get("source"),
        "target": finding.get("target"),
        "summary": _summarize_finding_for_context(finding),
        "finding": dict(finding),
    }


def build_finding_followup_ai_prompt(context: dict, question: str) -> str:
    finding = context.get("finding") if isinstance(context.get("finding"), dict) else {}
    source = context.get("source") or finding.get("source") or "unknown"
    tools_used = _tools_used_for_source(str(source))
    lines = [
        "Answer this follow-up question about a stored Project Mongrel finding.",
        "",
        "Guardrails:",
        "- Never invent scan results.",
        "- Never invent ports.",
        "- Never invent services.",
        "- Never invent CVEs.",
        "- Never invent vulnerabilities.",
        "- Never claim Nuclei assessed compromise.",
        "- Never imply a clean Nuclei result means the target is safe, secure, or free of vulnerabilities.",
        "- Base answers only on stored finding plus user question.",
        "- If information is unknown, explicitly say so.",
        "- Keep the answer concise and practical.",
        "- Do not recommend the same tool as the primary next step if it was already used, unless suggesting a specific re-scan or different scan mode.",
        "",
        "Stored finding context:",
        f"Finding ID: {context.get('finding_id') or finding.get('id') or 'unknown'}",
        f"Finding source: {source}",
        f"Tools already used: {tools_used}",
        f"Target: {context.get('target') or finding.get('target') or 'unknown'}",
        f"Summary: {context.get('summary') or _summarize_finding_for_context(finding)}",
    ]
    if source in {"nmap", "nmap_xml"}:
        lines.extend(
            [
                "",
                "Useful next tools for Nmap findings:",
                "- Nuclei",
                "- OWASP ZAP baseline scan",
                "- Burp Suite manual testing",
                "- SSL Labs / testssl.sh for TLS",
                "- securityheaders.com or header checks",
                "- technology fingerprinting",
                "- manual config review",
            ]
        )
        lines.extend(["", "Open ports:"])
        open_ports = finding.get("open_ports") or []
        lines.extend(_format_port_for_prompt(open_port) for open_port in open_ports) if open_ports else lines.append("none")
        lines.extend(["", f"Risk level: {_format_risk_level(finding.get('risk_level'))}"])
        lines.append(f"Risk notes: {_format_risk_notes(finding.get('risk_notes') or [])}")
    elif source == "nuclei":
        lines.extend(
            [
                "",
                "Useful next actions/tools for Nuclei findings:",
                "- manual validation",
                "- browser verification",
                "- Burp Suite/ZAP",
                "- patch/config review",
                "- re-scan after remediation",
                "",
                f"Status: {finding.get('status', 'findings')}",
                f"Risk level: {_format_risk_level(finding.get('risk_level'))}",
                f"Finding count: {finding.get('finding_count', len(finding.get('nuclei_findings') or []))}",
                "Severity summary:",
                *_format_severity_summary_for_prompt(finding.get("severity_summary") or {}),
                "",
                "Nuclei findings:",
            ]
        )
        nuclei_findings = finding.get("nuclei_findings") or []
        lines.extend(_format_nuclei_finding_for_prompt(nuclei_finding) for nuclei_finding in nuclei_findings) if nuclei_findings else lines.append("none")

    lines.extend(["", "Latest user question:", question])
    return "\n".join(lines)


def _tools_used_for_source(source: str) -> str:
    if source in {"nmap", "nmap_xml"}:
        return "Nmap"

    if source == "nuclei":
        return "Nuclei"

    return source or "unknown"


def _source_with_icon(source: object) -> str:
    normalized = str(source or "unknown")
    if normalized in {"nmap", "nmap_xml"}:
        return f"{normalized} ⌁"
    if normalized == "nuclei":
        return f"{normalized} ◇"
    if normalized == "bbot":
        return f"{normalized} ◆"

    return f"{normalized} ◌"


def _summarize_finding_for_context(finding: dict) -> str:
    if _is_clean_nuclei_scan(finding):
        return _format_clean_nuclei_summary(finding)

    if finding.get("source") == "nuclei":
        return (
            f"{finding.get('finding_count', len(finding.get('nuclei_findings') or []))} Nuclei finding(s) "
            f"for {finding.get('target', 'unknown')} with risk {_format_risk_level(finding.get('risk_level'))}."
        )

    open_ports = finding.get("open_ports") or []
    return (
        f"{finding.get('target', 'unknown')} has {len(open_ports)} open port(s) "
        f"with risk {_format_risk_level(finding.get('risk_level'))}."
    )


def _format_risk_notes(risk_notes: object) -> str:
    if isinstance(risk_notes, list) and risk_notes:
        return ", ".join(str(note) for note in risk_notes)

    return "None"


def _is_clean_nuclei_scan(finding: dict) -> bool:
    return finding.get("source") == "nuclei" and finding.get("status") == "clean"


def _prompt_guardrails() -> list[str]:
    return [
        "Rules:",
        "- Use only the supplied stored finding data.",
        "- Do not invent ports.",
        "- Do not invent services.",
        "- Do not invent CVEs.",
        "- Do not invent vulnerabilities.",
        "- Do not claim compromise.",
        "- Do not claim the target is safe or secure.",
        "- Preserve scanner-reported severity exactly.",
        "- Do not reassign services to ports.",
        "- Accuracy is more important than completeness.",
        "- Keep output concise.",
    ]


def _build_nmap_ai_prompt(finding: dict) -> str:
    open_ports = finding.get("open_ports") or []
    lines = [
        "Explain this stored Nmap finding in plain English.",
        *_prompt_guardrails(),
        "",
        "Use these sections:",
        "What this means",
        "Highest priority risks",
        "What to check first",
        "Suggested next steps",
        "",
        "Stored finding data:",
        f"Source: {finding.get('source', 'nmap')}",
        f"Target: {finding.get('target', 'unknown')}",
        f"Host status: {finding.get('host_status', 'unknown')}",
        f"Risk level: {_format_risk_level(finding.get('risk_level'))}",
        f"Risk notes: {_format_risk_notes(finding.get('risk_notes') or [])}",
        "",
        "Open ports:",
    ]
    if not open_ports:
        lines.append("none")
    else:
        lines.extend(_format_port_for_prompt(open_port) for open_port in open_ports)

    return "\n".join(lines)


def _build_nuclei_ai_prompt(finding: dict) -> str:
    nuclei_findings = finding.get("nuclei_findings") or []
    severity_summary = finding.get("severity_summary") or {}
    lines = [
        "Explain these stored Nuclei findings in plain English.",
        *_prompt_guardrails(),
        "",
        "Use these sections:",
        "What this means",
        "Highest priority risks",
        "What to verify first",
        "Suggested remediation",
        "",
        "Stored finding data:",
        f"Source: {finding.get('source', 'nuclei')}",
        f"Target: {finding.get('target', 'unknown')}",
        f"Risk level: {_format_risk_level(finding.get('risk_level'))}",
        f"Finding count: {finding.get('finding_count', len(nuclei_findings))}",
        "Severity summary:",
        *_format_severity_summary_for_prompt(severity_summary),
        "",
        "Nuclei findings:",
    ]
    if not nuclei_findings:
        lines.append("none")
    else:
        lines.extend(_format_nuclei_finding_for_prompt(nuclei_finding) for nuclei_finding in nuclei_findings)

    return "\n".join(lines)


def _build_clean_nuclei_ai_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "Explain this stored clean Nuclei result in plain English.",
            *_prompt_guardrails(),
            "",
            "Use these sections:",
            "What this means",
            "What it does not prove",
            "What to do next",
            "",
            "Stored finding data:",
            "Source: nuclei",
            f"Target: {finding.get('target', 'unknown')}",
            "Status: clean",
            "Risk level: INFO",
            "Finding count: 0",
            f"Summary: {_format_clean_nuclei_summary(finding)}",
        ]
    )


def _format_clean_nuclei_summary(finding: dict) -> str:
    summary = str(finding.get("summary") or "No matching Nuclei findings were observed using the selected template/profile.")
    metadata = finding.get("metadata") or {}
    if "fast scan profile" in summary.lower() and not (metadata.get("scan_profile") or metadata.get("profile")):
        return "No matching Nuclei findings were observed using the selected template/profile."
    return summary


def _format_port_for_prompt(open_port: dict) -> str:
    return f"{open_port.get('port')}/{open_port.get('protocol')} {open_port.get('service')}"


def _format_severity_summary_for_prompt(severity_summary: dict) -> list[str]:
    if not severity_summary:
        return ["none"]

    return [f"{severity}: {count}" for severity, count in severity_summary.items()]


def _format_nuclei_finding_for_prompt(finding: dict) -> str:
    return (
        f"{finding.get('severity', 'info')} | "
        f"{finding.get('name') or finding.get('template_id') or 'Unnamed finding'} | "
        f"template={finding.get('template_id') or 'unknown'} | "
        f"host={finding.get('host') or 'unknown'}"
    )


def _format_risk_level(risk_level: object) -> str:
    return str(risk_level or "unknown").upper()


def _format_bullets(items: list[str]) -> list[str]:
    if not items:
        return ["- None"]

    return [f"- {item}" for item in items]


def _format_comparison(comparison: object) -> list[str]:
    if not isinstance(comparison, dict):
        return ["No previous scan found for this target."]

    if comparison.get("has_previous") is False:
        return [
            str(comparison.get("summary", "No previous scan found for this target.")),
            "",
            "This scan has been stored as the baseline for future comparisons.",
        ]

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


def _format_impact(impact: object, comparison: object = None) -> list[str]:
    if isinstance(comparison, dict) and comparison.get("has_previous") is False:
        return [
            "Change Impact: N/A",
            "",
            "Summary:",
            "No historical comparison available.",
            "",
            "Reason:",
            "This is the first recorded scan for this target.",
        ]

    if not isinstance(impact, dict):
        return [
            "Change Impact: LOW",
            "",
            "Summary:",
            "No material exposure changes detected.",
            "",
            "Reason:",
            "No new services appeared and no risky services were removed since the previous scan.",
        ]

    lines = [
        f"Change Impact: {_format_risk_level(impact.get('impact_level'))}",
        "",
        "Summary:",
        str(impact.get("summary", "No material exposure changes detected.")),
        "",
        "Reason:",
        _format_impact_reason(impact),
    ]
    if impact.get("impacts"):
        lines.extend(["", "Impacts:", *_format_bullets(impact.get("impacts") or [])])
    if impact.get("recommendations"):
        lines.extend(["", "Recommendations:", *_format_bullets(impact.get("recommendations") or [])])

    return lines


def _format_impact_reason(impact: dict) -> str:
    if not impact.get("impacts"):
        return "No new services appeared and no risky services were removed since the previous scan."

    if _format_risk_level(impact.get("impact_level")) == "HIGH":
        return "A new high-risk service became exposed."

    if _format_risk_level(impact.get("impact_level")) == "MEDIUM":
        return "A new medium-risk service became exposed."

    return "Detected changes reduced or did not materially increase exposure."


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
    if user_id is not None:
        clear_finding_analysis_context(user_id)

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

    if query.data is not None and query.data.startswith("explain:finding:"):
        await _explain_finding_callback(update, user_id, query.data.removeprefix("explain:finding:"))
        return

    if query.data is None or not query.data.startswith("finding:view:"):
        return

    finding_id = query.data.removeprefix("finding:view:")
    finding = get_user_finding(user_id=user_id, finding_id=finding_id)
    await query.edit_message_text(
        build_finding_detail_text(finding, display_number=_find_display_number(findings, finding_id)),
        reply_markup=build_finding_detail_keyboard(finding.get("id") if finding else None),
    )


async def _explain_finding_callback(update: Update, user_id: int, finding_id: str) -> None:
    query = update.callback_query
    if query is None:
        return

    finding = get_user_finding(user_id=user_id, finding_id=finding_id)
    if finding is None:
        await query.edit_message_text("Finding not found.")
        return

    prompt = build_finding_ai_prompt(finding)
    if prompt is None:
        if query.message is not None:
            await query.message.reply_text("Unsupported finding source.")
        else:
            await query.edit_message_text("Unsupported finding source.")
        return

    if query.message is None:
        await query.edit_message_text("Mongrel is analyzing this finding...")
        return

    await query.message.reply_text("Mongrel is analyzing this finding...")
    try:
        ai_response = await asyncio.to_thread(ask_ai, prompt, path="finding_analysis")
    except Exception:
        logger.exception("Finding AI explanation failed for user_id=%s finding_id=%s", user_id, finding_id)
        await query.message.reply_text("AI explanation failed. Check bot logs.")
        return

    set_finding_analysis_context(user_id, build_finding_analysis_context(finding))
    logger.info("Finding analysis started for user_id=%s finding_id=%s", user_id, finding_id)
    await query.message.reply_text(ai_response)
    await query.message.reply_text(build_finding_analysis_mode_text(finding))
