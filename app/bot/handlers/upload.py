import asyncio
import logging

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.bot.handlers.scan import store_parsed_nmap_finding
from app.parsers.nmap_xml_parser import parse_nmap_xml
from app.services.ai_client import ask_ai
from app.services.verdict_engine import generate_mongrel_verdict

UPLOAD_STATE_AWAITING_NMAP_XML = "awaiting_nmap_xml"
UPLOAD_EXPLAIN_CALLBACK = "upload:explain_ai"
MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024
MAX_OPEN_SERVICES_IN_UPLOAD_SUMMARY = 10
MAX_UPLOAD_REPORT_LENGTH = 3800
_upload_states: dict[int, str] = {}
_latest_upload_scan_summaries: dict[int, dict] = {}
logger = logging.getLogger(__name__)


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


def store_latest_upload_scan_summary(user_id: int, finding: dict) -> dict:
    verdict = generate_mongrel_verdict(finding)
    summary = {
        "target": finding.get("target"),
        "risk_level": verdict.get("risk_level", finding.get("risk_level")),
        "open_ports": list(finding.get("open_ports") or []),
        "key_findings": _build_upload_key_findings(finding, verdict),
        "recommended_actions": _build_upload_recommended_actions(finding, verdict),
        "comparison": finding.get("comparison"),
        "impact": finding.get("impact"),
    }
    _latest_upload_scan_summaries[user_id] = summary
    return summary


def get_latest_upload_scan_summary(user_id: int) -> dict | None:
    return _latest_upload_scan_summaries.get(user_id)


def clear_latest_upload_scan_summary(user_id: int) -> None:
    _latest_upload_scan_summaries.pop(user_id, None)


def build_nmap_xml_import_success_text(finding: dict) -> str:
    verdict = generate_mongrel_verdict(finding)
    open_ports = finding.get("open_ports") or []
    key_findings = _build_upload_key_findings(finding, verdict)
    recommended_actions = _build_upload_recommended_actions(finding, verdict)

    lines = [
        "Mongrel Verdict",
        "",
        "Target:\n"
        f"{finding.get('target') or 'unknown'}",
        "",
        "Risk Level:",
        str(verdict.get("risk_level", finding.get("risk_level", "unknown"))).upper(),
        "",
        "Summary:",
        str(verdict.get("summary", "")),
        "",
        "Open Services:",
        *_format_open_services(open_ports),
        "",
        "Key Findings:",
        *_format_bullets(key_findings),
        "",
        "Recommended Actions:",
        *_format_bullets(recommended_actions),
        "",
        "Comparison:",
        *_format_upload_comparison(finding.get("comparison")),
        "",
        "Impact Assessment:",
        *_format_upload_impact(finding.get("impact"), finding.get("comparison")),
        "",
        "Technical Details:",
        *_format_technical_details(open_ports),
    ]
    return _truncate_message("\n".join(lines))


def _format_open_services(open_ports: list[dict]) -> list[str]:
    if not open_ports:
        return ["- No open services detected."]

    lines = []
    for open_port in open_ports[:MAX_OPEN_SERVICES_IN_UPLOAD_SUMMARY]:
        service_name = _format_service_name(open_port)
        version = open_port.get("version")
        version_suffix = f" ({version})" if version else ""
        lines.append(f"- {_format_port_service(open_port, service_name, version_suffix)}")

    remaining_count = len(open_ports) - MAX_OPEN_SERVICES_IN_UPLOAD_SUMMARY
    if remaining_count > 0:
        lines.append(f"...and {remaining_count} more services.")

    return lines


def _format_service_name(open_port: dict) -> str:
    intelligence = open_port.get("intelligence") or {}
    normalized_service = str(open_port.get("service") or "").lower()
    if normalized_service == "microsoft-ds":
        return "microsoft-ds"

    return normalized_service or str(intelligence.get("name") or "unknown").lower()


def _format_port_service(open_port: dict, service_name: str | None = None, suffix: str = "") -> str:
    service = service_name or _format_service_name(open_port)
    return f"{open_port.get('port')}/{open_port.get('protocol')} {service}{suffix}"


def _build_upload_key_findings(finding: dict, verdict: dict) -> list[str]:
    key_findings = _deduplicate_text(list(verdict.get("key_findings") or []))
    if not key_findings:
        key_findings.append("No significant findings identified.")

    http_ports = _find_http_ports(finding.get("open_ports") or [])
    if len(http_ports) > 1:
        key_findings.append("HTTP services are reachable on multiple ports.")

    has_smb_finding = _has_smb_finding(key_findings)
    represented_services = {str(key_finding).split(" ", 1)[0].upper() for key_finding in key_findings}
    for open_port in finding.get("open_ports") or []:
        if len(http_ports) > 1 and open_port in http_ports:
            continue

        service_name = _format_finding_service_name(open_port)
        if service_name == "Microsoft-DS / SMB" and has_smb_finding:
            continue

        if service_name not in represented_services:
            key_findings.append(f"{service_name} service is reachable.")

    return _deduplicate_text(key_findings)


def _format_finding_service_name(open_port: dict) -> str:
    normalized_service = str(open_port.get("service") or "").lower()
    if normalized_service == "microsoft-ds":
        return "Microsoft-DS / SMB"

    intelligence = open_port.get("intelligence") or {}
    service_name = intelligence.get("name") or normalized_service or "unknown"
    return str(service_name).upper()


def _build_upload_recommended_actions(finding: dict, verdict: dict) -> list[str]:
    actions = _deduplicate_text(list(verdict.get("recommended_actions") or []))
    http_ports = _find_http_ports(finding.get("open_ports") or [])
    if len(http_ports) > 1:
        actions.append("Review exposed HTTP services and redirect to HTTPS where appropriate.")

    for open_port in finding.get("open_ports") or []:
        if len(http_ports) > 1 and open_port in http_ports:
            continue

        recommendation = (open_port.get("intelligence") or {}).get("recommendation")
        if recommendation and recommendation not in actions:
            actions.append(str(recommendation))

    return _deduplicate_text(actions) or ["No immediate action required."]


def _deduplicate_text(items: list[str]) -> list[str]:
    deduplicated = []
    seen = set()
    for item in items:
        text = str(item)
        if text in seen:
            continue

        seen.add(text)
        deduplicated.append(text)

    return deduplicated


def _find_http_ports(open_ports: list[dict]) -> list[dict]:
    return [open_port for open_port in open_ports if _is_http_service(open_port)]


def _is_http_service(open_port: dict) -> bool:
    intelligence = open_port.get("intelligence") or {}
    service = str(open_port.get("service") or "").lower()
    intelligence_name = str(intelligence.get("name") or "").lower()
    return service == "http" or intelligence_name == "http"


def _has_smb_finding(key_findings: list[str]) -> bool:
    return any("SMB" in key_finding.upper() for key_finding in key_findings)


def _format_bullets(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items]


def _format_upload_comparison(comparison: object) -> list[str]:
    if not isinstance(comparison, dict):
        return ["No previous scan found for this target."]

    if comparison.get("has_previous") is False:
        return [
            str(comparison.get("summary", "No previous scan found for this target.")),
            "This scan has been stored as the baseline for future comparisons.",
        ]

    lines = [str(comparison.get("summary", "No material changes detected."))]
    lines.extend(
        [
            f"New Ports: {_format_ports(comparison.get('new_ports') or [])}",
            f"Removed Ports: {_format_ports(comparison.get('removed_ports') or [])}",
            f"Risk Change: {_format_risk_change(comparison)}",
            f"Unchanged Ports: {len(comparison.get('unchanged_ports') or [])}",
        ]
    )
    return lines


def _format_upload_impact(impact: object, comparison: object) -> list[str]:
    if isinstance(comparison, dict) and comparison.get("has_previous") is False:
        return [
            "Change Impact: N/A",
            "No historical comparison available.",
            "Reason: This is the first recorded scan for this target.",
        ]

    if not isinstance(impact, dict):
        return [
            "Change Impact: LOW",
            "No material exposure changes detected.",
            "Reason: No new services appeared and no risky services were removed since the previous scan.",
        ]

    lines = [
        f"Change Impact: {str(impact.get('impact_level', 'unknown')).upper()}",
        str(impact.get("summary", "No material exposure changes detected.")),
    ]
    if impact.get("impacts"):
        lines.extend(_format_bullets(impact.get("impacts") or []))
    if impact.get("recommendations"):
        lines.extend(_format_bullets(impact.get("recommendations") or []))

    return lines


def _format_technical_details(open_ports: list[dict]) -> list[str]:
    if not open_ports:
        return ["No open services detected."]

    lines = []
    for index, open_port in enumerate(open_ports[:MAX_OPEN_SERVICES_IN_UPLOAD_SUMMARY], start=1):
        intelligence = open_port.get("intelligence") or {}
        lines.extend(
            [
                f"{index}. {_format_port_service(open_port)}",
                f"   Purpose: {_clean_unknown_text(intelligence.get('description'))}",
                f"   Risk: {_clean_unknown_text(intelligence.get('common_risk'))}",
                f"   Recommendation: {_clean_unknown_recommendation(intelligence.get('recommendation'))}",
                "",
            ]
        )

    remaining_count = len(open_ports) - MAX_OPEN_SERVICES_IN_UPLOAD_SUMMARY
    if remaining_count > 0:
        lines.append(f"...and {remaining_count} more services.")

    return lines


def _clean_unknown_text(value: object) -> str:
    if not value or str(value) == "Description unavailable.":
        return "Manual review required."

    return str(value)


def _clean_unknown_recommendation(value: object) -> str:
    if not value:
        return "Manual review recommended."

    return str(value)


def _format_ports(open_ports: list[dict]) -> str:
    if not open_ports:
        return "none"

    return ", ".join(_format_port_service(open_port) for open_port in open_ports)


def _format_risk_change(comparison: dict) -> str:
    if comparison.get("risk_changed"):
        return f"{str(comparison.get('previous_risk')).upper()} -> {str(comparison.get('current_risk')).upper()}"

    return "none"


def _truncate_message(message: str) -> str:
    if len(message) <= MAX_UPLOAD_REPORT_LENGTH:
        return message

    return f"{message[:MAX_UPLOAD_REPORT_LENGTH]}\n\n[output truncated]"


def build_upload_success_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Open Findings", callback_data="finding:list")],
            [InlineKeyboardButton("Explain with Mongrel AI", callback_data=UPLOAD_EXPLAIN_CALLBACK)],
        ]
    )


def build_upload_ai_prompt(summary: dict) -> str:
    open_ports = summary.get("open_ports") or []
    key_findings = summary.get("key_findings") or []
    recommended_actions = summary.get("recommended_actions") or []
    comparison_lines = _format_upload_comparison(summary.get("comparison"))
    impact_lines = _format_upload_impact(summary.get("impact"), summary.get("comparison"))

    return "\n".join(
        [
            "Explain these deterministic Nmap XML scan findings in plain English.",
            "Focus on risk meaning and practical next steps.",
            "Keep the response concise.",
            "Accuracy is more important than completeness.",
            "",
            "Rules:",
            "- Use only the supplied findings.",
            "- Do not invent services.",
            "- Do not invent ports.",
            "- Do not invent CVEs.",
            "- Do not invent vulnerabilities or scan results.",
            "- Do not merge services together.",
            "- Do not reassign services to different ports.",
            "- Assume the user has already read the deterministic report.",
            "- Do not repeat Scan Summary.",
            "- The exact port list has already been shown to the user. Do not repeat it.",
            "- Do not repeat Open Services.",
            "- Do not repeat Risk Level.",
            "- Do not restate the Open Services list.",
            "- Do not produce service-on-port mapping lines.",
            "- Refer to exact ports only when quoting directly from the supplied Open Services list.",
            "- If uncertain, state uncertainty rather than guessing.",
            "",
            "Output restrictions:",
            "- Use only these four section titles: What this means, Highest priority risks, What to check first, Suggested next steps.",
            "- Do not create sections titled Scan Summary, Open Services, or Risk Level.",
            "- Use a maximum of 8 bullet points total.",
            "",
            "Use these output sections:",
            "What this means:",
            "- Explain the overall exposure in plain English without restating every port.",
            "",
            "Highest priority risks:",
            "- Focus on SSH, SMB, remote administration, file sharing, and exposed web/management surfaces if present in supplied findings.",
            "",
            "What to check first:",
            "- Practical checks based on supplied findings.",
            "",
            "Suggested next steps:",
            "- Defensive remediation steps.",
            "",
            "Grounding data for reference only:",
            f"Target: {summary.get('target') or 'unknown'}",
            f"Risk level: {str(summary.get('risk_level') or 'unknown').upper()}",
            "",
            "Open Services:",
            *_format_prompt_open_services(open_ports),
            "",
            "Key findings:",
            *_format_prompt_bullets(key_findings),
            "",
            "Recommended actions:",
            *_format_prompt_bullets(recommended_actions),
            "",
            "Comparison summary:",
            *_format_prompt_bullets(comparison_lines),
            "",
            "Impact summary:",
            *_format_prompt_bullets(impact_lines),
        ]
    )


def _format_prompt_open_services(open_ports: list[dict]) -> list[str]:
    if not open_ports:
        return ["none"]

    return [_format_port_service(open_port) for open_port in open_ports]


def _format_prompt_bullets(items: list[str]) -> list[str]:
    if not items:
        return ["- none"]

    return [item if str(item).startswith("- ") else f"- {item}" for item in items]


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
    store_latest_upload_scan_summary(user_id, finding)
    clear_upload_state(user_id)
    await update.message.reply_text(
        build_nmap_xml_import_success_text(finding),
        reply_markup=build_upload_success_keyboard(),
    )


async def upload_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return

    await query.answer()

    if query.data != UPLOAD_EXPLAIN_CALLBACK:
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is None:
        await query.edit_message_text("Upload an Nmap XML file first.")
        return

    summary = get_latest_upload_scan_summary(user_id)
    if summary is None:
        await query.edit_message_text("Upload an Nmap XML file first.")
        return

    if query.message is None:
        return

    await query.message.reply_text("Mongrel is analyzing the findings...")
    prompt = build_upload_ai_prompt(summary)
    try:
        logger.info("Upload findings AI explanation started for user_id=%s", user_id)
        ai_response = await asyncio.to_thread(ask_ai, prompt)
        logger.info("Upload findings AI explanation completed for user_id=%s", user_id)
    except Exception:
        logger.exception("Upload findings AI explanation failed for user_id=%s", user_id)
        await query.message.reply_text("AI explanation failed. Check bot logs.")
        return

    await query.message.reply_text(ai_response)
