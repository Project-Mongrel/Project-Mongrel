import asyncio
import logging
import time

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from app.bot.handlers.home import build_home_text
from app.bot.handlers.assessment import (
    ASSESSMENT_SCAN_CONTEXT_KEY,
    assessment_chat_text_handler,
    assessment_text_handler,
    build_assessment_dashboard_keyboard,
    build_assessment_dashboard_text,
    clear_assessment_flow_state,
    is_assessment_chat_active,
    is_assessment_flow_active,
)
from app.bot.handlers.findings import build_finding_followup_ai_prompt
from app.bot.keyboards import MAIN_MENU_BUTTONS, build_main_menu_keyboard, build_scan_type_keyboard
from app.bot.progress import build_spinner_frames, run_progress_frames, safe_edit_text
from app.models.scan_request import SUPPORTED_SCAN_TYPES
from app.parsers.bbot_normalizer import normalize_bbot_output, summarize_observations
from app.bot.handlers.reports import split_report_text
from app.parsers.httpx_parser import parse_httpx_output, summarize_httpx_services
from app.parsers.katana_parser import parse_katana_output, summarize_katana_observations
from app.parsers.nuclei_parser import NucleiParserError, parse_nuclei_results
from app.services.ai_client import ask_ai
from app.services.assessment_store import (
    get_assessment,
    list_assessment_scans,
    list_assessment_targets,
    record_assessment_scan,
)
from app.services.active_scan_state import (
    clear_active_scan,
    get_active_scan,
    set_active_scan,
    set_active_scan_status_task,
    set_active_scan_task,
)
from app.services.bbot_ai_assessment import FALLBACK_LINES, generate_bbot_ai_assessment
from app.services.bbot_summary import build_bbot_recon_summary
from app.services.chat_state import clear_finding_analysis_context, get_finding_analysis_context, is_ai_waiting
from app.services.comparison_engine import compare_findings
from app.services.findings_store import add_finding, get_latest_user_finding_for_target
from app.services.findings_store import get_user_finding
from app.services.icon_helper import section_label
from app.services.impact_engine import assess_change_impact
from app.services.investigation_store import add_investigation_event, get_investigation, get_or_create_latest_open_investigation
from app.services.observation_store import add_observations
from app.services.risk_rules import assess_nmap_ports
from app.services.scan_manager import (
    complete_scan_request,
    create_scan_request,
    get_scan_request,
    mark_scan_request_awaiting_target,
)
from app.services.scan_ai_summary import FALLBACK_SUMMARY_LINES, generate_scan_ai_summary
from app.services.nmap_ai_assessment import FALLBACK_LINES as NMAP_AI_FALLBACK_LINES
from app.services.nmap_ai_assessment import generate_nmap_ai_assessment
from app.services.nuclei_ai_assessment import FALLBACK_LINES as NUCLEI_AI_FALLBACK_LINES
from app.services.nuclei_ai_assessment import generate_nuclei_ai_assessment
from app.services.httpx_ai_assessment import FALLBACK_LINES as HTTPX_AI_FALLBACK_LINES
from app.services.httpx_ai_assessment import generate_httpx_ai_assessment
from app.services.katana_ai_assessment import FALLBACK_LINES as KATANA_AI_FALLBACK_LINES
from app.services.katana_ai_assessment import generate_katana_ai_assessment
from app.services.service_intelligence import get_service_intelligence
from app.services.target_normalizer import normalize_for_bbot, normalize_for_httpx, normalize_for_katana, normalize_for_nmap, normalize_for_nuclei, normalize_target_key
from app.tools.nmap_parser import parse_nmap_output
from app.tools.nmap_runner import run_nmap_scan
from app.tools.nuclei_runner import run_nuclei_scan
from app.tools.httpx_runner import run_httpx_scan
from app.tools.katana_runner import run_katana_scan
from app.tools.bbot_runner import is_bbot_available, run_bbot_scan
from app.ui.ai_summary import render_ai_summary_card
from app.ui.scan_progress import ScanProgressCard, render_scan_loading_card
from app.ui.scan_actions import AI_SUMMARY_CALLBACK_PREFIX, build_scan_result_actions
from app.ui.result_cards import render_scan_result_card, render_section

PENDING_NMAP_REQUEST_KEY = "pending_nmap_scan_request_id"
NUCLEI_STATUS_UPDATE_INTERVAL_SECONDS = 15
BBOT_AI_ASSESSMENT_CALLBACK_PREFIX = "bbot_ai"
logger = logging.getLogger(__name__)


def build_scan_text() -> str:
    return "Choose a scan workflow to prepare. No external tools will run yet."


def build_scan_created_text(scan_type: str) -> str:
    return (
        f"{scan_type.upper()} scan request created with status: pending.\n\n"
        "Target collection and tool execution will be added in a later mission."
    )


def build_nmap_target_prompt() -> str:
    return "\n".join(
        [
            "NMAP scan request created. Send the authorized target hostname or IP address.",
            "",
            "Examples:",
            "scanme.nmap.org",
            "192.168.1.10",
        ]
    )


def build_nuclei_target_prompt() -> str:
    return "\n".join(
        [
            "Nuclei scan request created. Send the authorized target URL.",
            "",
            "Examples:",
            "https://example.com",
            "https://scanme.nmap.org",
            "",
            "HTTPS is recommended.",
        ]
    )


def build_bbot_target_prompt() -> str:
    return "\n".join(
        [
            "BBOT recon request created. Send the authorized target domain or hostname.",
            "",
            "Examples:",
            "scanme.nmap.org",
            "example.com",
        ]
    )


def build_httpx_target_prompt() -> str:
    return "\n".join(
        [
            "httpx fingerprint request created. Send the authorized HTTP target URL or hostname.",
            "",
            "Examples:",
            "https://example.com",
            "example.com",
        ]
    )


def build_katana_target_prompt() -> str:
    return "\n".join(
        [
            "Katana crawl request created. Send the authorized HTTP target URL or hostname.",
            "",
            "Examples:",
            "https://example.com",
            "example.com",
        ]
    )


def build_nmap_scan_started_text(target: str) -> str:
    return render_scan_loading_card("Nmap Scan", target, "Launching scan...", 0)


def build_nuclei_scan_started_text() -> str:
    return "Running Nuclei scan..."


def build_nuclei_status_card(target: str, status: str, elapsed_seconds: int, reason: str | None = None) -> str:
    status_text = f"{status}: {reason}" if reason else status
    return render_scan_loading_card("Nuclei Scan", target, status_text, elapsed_seconds)


def build_clean_nuclei_verdict_text(target: str | None, elapsed: str | None = None) -> str:
    return render_scan_result_card(
        tool_name="Nuclei",
        target=str(target or "unknown"),
        elapsed=elapsed,
        risk="INFO",
        summary="\n".join(
            [
                "No matching Nuclei findings were observed using the selected template/profile.",
                "",
                "Recommended Actions:",
                "- Continue regular patching and monitoring.",
                "- Re-scan after major site, server, or plugin changes.",
                "- Consider a deeper scan profile if additional assurance is required.",
            ]
        ),
        findings=[
            "0 findings",
            "The target was reachable.",
            "Nuclei executed successfully.",
            "No exposures, misconfigurations, or known issues matched the selected template set.",
        ],
        assets=[str(target)] if target else None,
        ai_assessment=None,
    )


def build_bbot_scan_started_text(target: str) -> str:
    return render_scan_loading_card("BBOT Scan", target, "Launching scan...", 0)


def build_bbot_ai_assessment_keyboard(investigation_id: str | None) -> InlineKeyboardMarkup | None:
    if not investigation_id:
        return None

    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("Generate AI Recon Assessment", callback_data=f"{BBOT_AI_ASSESSMENT_CALLBACK_PREFIX}:{investigation_id}")]]
    )


def _combine_inline_keyboards(*keyboards: InlineKeyboardMarkup | None) -> InlineKeyboardMarkup | None:
    rows = []
    for keyboard in keyboards:
        if keyboard is not None:
            rows.extend(keyboard.inline_keyboard)

    return InlineKeyboardMarkup(rows) if rows else None


def _bbot_result_findings_from_counts(counts: dict[str, int]) -> list[str]:
    if sum(int(value or 0) for value in counts.values()) == 0:
        return []
    return [
        f"Observations collected: {sum(int(value or 0) for value in counts.values())}",
        f"Subdomains: {counts.get('subdomain', 0)}",
        f"URLs: {counts.get('url', 0)}",
        f"IP Addresses: {counts.get('ip_address', 0)}",
        f"Technologies: {counts.get('technology', 0)}",
        f"Raw Events: {counts.get('raw_event', 0)}",
    ]


def _bbot_result_assets_from_counts(counts: dict[str, int]) -> list[str]:
    if sum(int(value or 0) for value in counts.values()) == 0:
        return []
    return [
        f"Subdomains: {counts.get('subdomain', 0)}",
        f"URLs: {counts.get('url', 0)}",
        f"IP Addresses: {counts.get('ip_address', 0)}",
        f"Emails: {counts.get('email', 0)}",
        f"Technologies: {counts.get('technology', 0)}",
    ]


def build_bbot_result_text(
    result: dict[str, object],
    observation_counts: dict[str, int] | None = None,
    recon_summary: str | None = None,
) -> str:
    if (result.get("success") is True or result.get("partial") is True) and recon_summary:
        summary = recon_summary
        if result.get("partial") is True:
            summary = "\n\n".join(
                [
                    recon_summary,
                    "Partial result: BBOT exited before a clean completion, but useful observations were collected.",
                ]
            )
        return render_scan_result_card(
            tool_name="BBOT",
            target=str(result.get("target") or "unknown"),
            status="Partial" if result.get("partial") is True else "Complete",
            elapsed=f"{int(float(result.get('elapsed_seconds') or 0))}s",
            risk="INFO",
            summary=summary,
        )

    if result.get("error_type") == "runtime_incompatible":
        return render_scan_result_card(
            tool_name="BBOT",
            target=str(result.get("target") or "unknown"),
            status="Failed",
            summary=str(result.get("error") or "BBOT is installed but cannot run in this Windows environment."),
        )

    status = "Complete" if result.get("success") is True else "Failed"
    output = _truncate_bbot_output(
        str(
            result.get("output")
            if result.get("success") is True
            else (result.get("error") or "BBOT recon failed before useful observations were collected.")
        )
    )
    counts = observation_counts or {}
    return render_scan_result_card(
        tool_name="BBOT",
        target=str(result.get("target") or "unknown"),
        status=status,
        elapsed=f"{int(float(result.get('elapsed_seconds') or 0))}s",
        risk="INFO" if result.get("success") is True else None,
        summary=output,
        findings=_bbot_result_findings_from_counts(counts),
        assets=_bbot_result_assets_from_counts(counts),
    )


def build_httpx_result_text(result: dict[str, object], services: list[dict] | None = None) -> str:
    services = services or []
    summary = summarize_httpx_services(services)
    limitations = []
    if result.get("success") is not True:
        limitations.append(str(result.get("error") or "httpx did not complete successfully."))
    if not services:
        limitations.append("No structured httpx JSON observations were stored.")
    status_codes = summary.get("status_codes") or {}
    titles = [
        f"{service.get('url') or service.get('host')}: {service.get('title')}"
        for service in services
        if service.get("title")
    ]
    technologies = [str(value) for value in summary.get("technologies") or []]
    redirects = [
        f"{service.get('url') or service.get('host')} -> {service.get('redirect_location') or service.get('final_url')}"
        for service in services
        if service.get("redirect_location") or service.get("final_url")
    ]
    findings = [
        f"HTTP services/URLs observed: {summary.get('service_count', 0)}",
        "Status codes: " + (", ".join(f"{code}: {count}" for code, count in sorted(status_codes.items())) if status_codes else "none"),
    ]
    if titles:
        findings.append("Titles: " + "; ".join(titles[:3]))
    if technologies:
        findings.append("Technologies: " + ", ".join(technologies[:8]))
    if redirects:
        findings.append("Redirects: " + "; ".join(redirects[:3]))
    if limitations:
        findings.append("Limitations: " + " ".join(limitations))
    return render_scan_result_card(
        tool_name="httpx",
        target=str(result.get("target") or "unknown"),
        status="Complete" if result.get("success") is True else "Failed",
        elapsed=f"{int(float(result.get('elapsed_seconds') or 0))}s",
        risk="INFO" if result.get("success") is True else None,
        summary=f"{summary.get('service_count', 0)} HTTP service/URL observation(s) recorded.",
        findings=findings,
        assets=[str(service.get("url") or service.get("host")) for service in services if service.get("url") or service.get("host")],
    )


def store_httpx_scan_result(user_id: int, result: dict[str, object], services: list[dict] | None = None) -> dict:
    services = services or []
    status = "completed" if result.get("success") is True else "failed"
    summary = summarize_httpx_services(services)
    if result.get("success") is True:
        finding_summary = f"httpx observed {len(services)} HTTP service/URL record(s)."
    else:
        finding_summary = str(result.get("error") or "httpx fingerprinting failed.")
    target = str(result.get("target") or "")
    return add_finding(
        user_id=user_id,
        finding={
            "source": "httpx",
            "target": target,
            "target_key": normalize_target_key(target),
            "status": status,
            "summary": finding_summary,
            "risk_level": "info" if result.get("success") is True else "unknown",
            "finding_count": len(services),
            "raw_output": str(result.get("output") or ""),
            "httpx_services": services,
            "httpx_summary": summary,
            "metadata": {
                "returncode": result.get("returncode"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "command": result.get("command"),
                "working_directory": result.get("working_directory"),
                "error": result.get("error"),
                "error_type": result.get("error_type"),
                "parser": "jsonl",
            },
        },
    )


def build_katana_result_text(result: dict[str, object], observations: list[dict] | None = None) -> str:
    observations = observations or []
    summary = summarize_katana_observations(observations)
    limitations = []
    if result.get("success") is not True:
        limitations.append(str(result.get("error") or "Katana did not complete successfully."))
    if not observations:
        limitations.append("No structured Katana JSON observations were stored.")
    findings = [
        f"URLs/endpoints discovered: {summary.get('url_count', 0)}",
        f"Unique hosts: {summary.get('host_count', 0)}",
        f"JavaScript files: {summary.get('javascript_count', 0)}",
        f"Query parameters: {summary.get('query_parameter_count', 0)}",
        f"Forms/actions: {summary.get('form_count', 0)}",
        f"Max observed crawl depth: {summary.get('max_depth', 0)}",
    ]
    parameters = [str(value) for value in summary.get("query_parameters") or []]
    if parameters:
        findings.append("Observed parameters: " + ", ".join(parameters[:10]))
    js_files = [str(value) for value in summary.get("javascript_files") or []]
    if js_files:
        findings.append("JavaScript: " + "; ".join(js_files[:3]))
    forms = [
        f"{observation.get('url') or 'unknown'} -> {form.get('action') or 'unknown'}"
        for observation in observations
        for form in (observation.get("forms") or [])
    ]
    if forms:
        findings.append("Forms/actions: " + "; ".join(forms[:3]))
    if limitations:
        findings.append("Limitations: " + " ".join(limitations))
    findings_text = "\n".join(f"- {finding}" for finding in findings)
    return render_scan_result_card(
        tool_name="Katana",
        target=str(result.get("target") or "unknown"),
        status="Complete" if result.get("success") is True else "Failed",
        elapsed=f"{int(float(result.get('elapsed_seconds') or 0))}s",
        risk="INFO" if result.get("success") is True else None,
        summary=f"{summary.get('url_count', 0)} URL/endpoint observation(s) recorded.",
        findings=findings_text,
        assets=[str(observation.get("url")) for observation in observations if observation.get("url")],
    )


def store_katana_scan_result(user_id: int, result: dict[str, object], observations: list[dict] | None = None) -> dict:
    observations = observations or []
    status = "completed" if result.get("success") is True else "failed"
    summary = summarize_katana_observations(observations)
    if result.get("success") is True:
        finding_summary = f"Katana observed {len(observations)} URL/endpoint record(s)."
    else:
        finding_summary = str(result.get("error") or "Katana crawl failed.")
    target = str(result.get("target") or "")
    command = result.get("command") or []
    crawl_depth = None
    if isinstance(command, list) and "-d" in command:
        depth_index = command.index("-d") + 1
        if depth_index < len(command):
            crawl_depth = command[depth_index]
    return add_finding(
        user_id=user_id,
        finding={
            "source": "katana",
            "target": target,
            "target_key": normalize_target_key(target),
            "status": status,
            "summary": finding_summary,
            "risk_level": "info" if result.get("success") is True else "unknown",
            "finding_count": len(observations),
            "raw_output": str(result.get("output") or ""),
            "katana_observations": observations,
            "katana_summary": summary,
            "metadata": {
                "returncode": result.get("returncode"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "command": result.get("command"),
                "working_directory": result.get("working_directory"),
                "error": result.get("error"),
                "error_type": result.get("error_type"),
                "parser": "jsonl",
                "crawl_depth": crawl_depth,
            },
        },
    )


def store_bbot_scan_result(user_id: int, result: dict[str, object], observations: list[dict] | None = None) -> dict:
    observations = observations or []
    observation_counts = summarize_observations(observations)
    if result.get("partial") is True:
        status = "partial"
    elif result.get("success") is True:
        status = "completed"
    else:
        status = "failed"
    if result.get("success") is True or result.get("partial") is True:
        summary = _build_bbot_summary(observation_counts)
    else:
        summary = str(result.get("error") or "BBOT recon failed.")
    target = str(result.get("target") or "")
    return add_finding(
        user_id=user_id,
        finding={
            "source": "bbot",
            "target": target,
            "target_key": normalize_target_key(target),
            "status": status,
            "summary": summary,
            "risk_level": "info",
            "finding_count": len(observations),
            "raw_output": str(result.get("output") or ""),
            "observation_counts": observation_counts,
            "metadata": {
                "returncode": result.get("returncode"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "output_dir": result.get("output_dir"),
                "command": result.get("command"),
                "working_directory": result.get("working_directory"),
                "json_output_found": result.get("json_output_found"),
                "json_output_paths": result.get("json_output_paths"),
                "error": result.get("error"),
                "partial": result.get("partial") is True,
                "parser_error": result.get("parser_error"),
                "observation_count": len(observations),
            },
        },
    )


def store_clean_nuclei_scan(user_id: int, target: str | None) -> dict:
    summary = "No matching Nuclei findings were identified using the fast scan profile."
    return add_finding(
        user_id=user_id,
        finding={
            "source": "nuclei",
            "target": target,
            "target_key": normalize_target_key(target),
            "risk_level": "info",
            "finding_count": 0,
            "status": "clean",
            "summary": summary,
            "metadata": {"scan_profile": "fast"},
        },
    )


def build_nmap_scan_result_text(result: dict[str, object]) -> str:
    output = str(result.get("output") or "")
    fallback_output = str(result.get("error") or output or "No output returned.")
    parsed_output = parse_nmap_result(result)
    target = str(parsed_output.get("target") or result.get("target") or "unknown")
    open_ports = parsed_output.get("open_ports") or []
    if not parsed_output.get("target") and not parsed_output.get("host_status") and not open_ports and not parsed_output.get("duration"):
        summary = _safe_truncated_text(fallback_output)
        return render_scan_result_card(
            tool_name="Nmap",
            target=target,
            status="Complete" if result.get("success") is True else "Failed",
            summary=summary,
        )

    findings = (
        [f"{open_port.get('port')}/{open_port.get('protocol')} {open_port.get('service')}" for open_port in open_ports]
        if open_ports
        else ["No open ports found."]
    )
    host_status = parsed_output.get("host_status") or "Unknown"
    notes = parsed_output.get("risk_notes") or []
    summary_lines = [_format_nmap_host_status(host_status)]
    if notes:
        summary_lines.extend(_format_nmap_notes(notes))
    return render_scan_result_card(
        tool_name="Nmap",
        target=target,
        status="Complete" if result.get("success") is True else "Failed",
        elapsed=str(parsed_output.get("duration") or "") or None,
        risk=str(parsed_output.get("risk_level") or "").upper() or None,
        summary="\n".join(summary_lines),
        findings=findings,
        assets=[target],
    )


def _format_nmap_host_status(host_status: object) -> str:
    normalized = str(host_status or "").strip().lower()
    if normalized == "up":
        return "Host reachable."
    if normalized == "down":
        return "Host appears unreachable."
    return "Host status unknown."


def _format_nmap_notes(notes: list[object]) -> list[str]:
    formatted_notes = []
    for note in notes:
        text = str(note or "").strip()
        if not text:
            continue
        if text.lower().endswith(" exposed"):
            service = text[: -len(" exposed")].strip()
            text = f"{service} service exposed."
        elif not text.endswith("."):
            text = f"{text}."
        formatted_notes.append(text)
    return formatted_notes


def _pop_assessment_scan_context(context: ContextTypes.DEFAULT_TYPE, tool: str) -> dict | None:
    user_data = getattr(context, "user_data", None)
    if not isinstance(user_data, dict):
        return None
    assessment_context = user_data.get(ASSESSMENT_SCAN_CONTEXT_KEY)
    if not isinstance(assessment_context, dict):
        return None
    if str(assessment_context.get("tool") or "").lower() != tool:
        return None
    return user_data.pop(ASSESSMENT_SCAN_CONTEXT_KEY)


def _record_assessment_scan(
    assessment_context: dict | None,
    *,
    tool: str,
    result: dict,
    finding: dict | None = None,
) -> dict | None:
    if not assessment_context:
        return None
    if result.get("partial") is True:
        status = "partial"
    elif result.get("success") is True:
        status = "completed"
    else:
        status = "failed"
    return record_assessment_scan(
        assessment_id=int(assessment_context["assessment_id"]),
        target_id=int(assessment_context["target_id"]) if assessment_context.get("target_id") is not None else None,
        tool=tool,
        status=status,
        finding_id=finding.get("id") if finding else None,
        elapsed_seconds=_scan_elapsed_seconds(result, finding),
        risk=_scan_risk(result, finding),
        raw_reference=_scan_raw_reference(result, finding),
    )


async def _send_assessment_dashboard(message: object, assessment_context: dict | None) -> None:
    if not assessment_context:
        return
    assessment_id = int(assessment_context["assessment_id"])
    assessment = get_assessment(assessment_id)
    if assessment is None:
        return
    await message.reply_text(
        build_assessment_dashboard_text(
            assessment,
            list_assessment_targets(assessment_id),
            list_assessment_scans(assessment_id),
        ),
        reply_markup=build_assessment_dashboard_keyboard(assessment_id),
    )


def _scan_elapsed_seconds(result: dict, finding: dict | None = None) -> int | None:
    for value in (
        result.get("elapsed_seconds"),
        (finding or {}).get("duration"),
        ((finding or {}).get("metadata") or {}).get("elapsed_seconds"),
    ):
        parsed = _parse_elapsed_seconds(value)
        if parsed is not None:
            return parsed
    return None


def _parse_elapsed_seconds(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return max(0, int(value))
    text = str(value).strip().lower()
    if text.endswith("s"):
        text = text[:-1]
    try:
        return max(0, int(float(text)))
    except ValueError:
        return None


def _scan_risk(result: dict, finding: dict | None = None) -> str | None:
    return str((finding or {}).get("risk_level") or result.get("risk_level") or "").lower() or None


def _scan_raw_reference(result: dict, finding: dict | None = None) -> str | None:
    if finding and finding.get("scan_run_id"):
        return f"scan_runs/{finding['scan_run_id']}"
    if result.get("output_dir"):
        return str(result["output_dir"])
    return None


def append_change_summary(message: str, comparison: dict | None, impact: dict | None = None) -> str:
    if comparison is None:
        return message

    if comparison.get("has_previous") is False:
        return "\n".join(
            [
                message,
                "",
                render_section("Comparison", "\n".join(
                    [
                        comparison.get("summary", "No previous scan found for this target."),
                        "This scan has been stored as the baseline for future comparisons.",
                    ]
                ), "comparison"),
                "",
                render_section("Impact", "\n".join(
                    [
                        "Change Impact: N/A",
                        "",
                        "Summary:",
                        "No historical comparison available.",
                        "",
                        "Reason:",
                        "This is the first recorded scan for this target.",
                    ]
                ), "impact"),
            ]
        )

    lines = [
        message,
        "",
        render_section("Comparison", "\n".join(
            [
                comparison.get("summary", "No previous scan found for this target."),
                "",
                f"New Ports: {_format_ports(comparison.get('new_ports') or [])}",
                f"Removed Ports: {_format_ports(comparison.get('removed_ports') or [])}",
                f"Risk Change: {_format_risk_change(comparison)}",
                f"Unchanged Ports: {len(comparison.get('unchanged_ports') or [])}",
            ]
        ), "comparison"),
    ]
    if impact is not None:
        lines.extend(["", render_section("Impact", impact.get("summary", "No material exposure changes detected."), "impact")])

    return "\n".join(lines)


def parse_nmap_result(result: dict[str, object]) -> dict:
    parsed_output = parse_nmap_output(str(result.get("output") or ""))
    if result.get("target") is not None and parsed_output.get("target") is None:
        parsed_output["target"] = result["target"]

    parsed_output.update(assess_nmap_ports(parsed_output.get("open_ports", [])))
    return parsed_output


def store_successful_nmap_finding(user_id: int, result: dict[str, object]) -> dict | None:
    if result.get("success") is not True:
        return None

    parsed_output = parse_nmap_result(result)
    return store_parsed_nmap_finding(user_id=user_id, parsed_output=parsed_output, source="nmap")


def store_parsed_nmap_finding(user_id: int, parsed_output: dict, source: str) -> dict:
    assessed_output = dict(parsed_output)
    assessed_output.update(assess_nmap_ports(assessed_output.get("open_ports", [])))
    enriched_open_ports = enrich_open_ports(assessed_output.get("open_ports", []))
    previous_finding = get_latest_user_finding_for_target(
        user_id,
        assessed_output.get("target"),
        sources=_comparison_sources_for(source),
    )
    comparison = compare_findings(
        previous=previous_finding,
        current={
            **assessed_output,
            "open_ports": enriched_open_ports,
        },
    )
    impact = assess_change_impact(comparison)
    return add_finding(
        user_id=user_id,
        finding={
            "source": source,
            "target": assessed_output.get("target"),
            "target_key": normalize_target_key(assessed_output.get("target")),
            "host_status": assessed_output.get("host_status"),
            "open_ports": enriched_open_ports,
            "duration": assessed_output.get("duration"),
            "risk_level": assessed_output.get("risk_level"),
            "risk_notes": assessed_output.get("risk_notes", []),
            "comparison": comparison,
            "impact": impact,
        },
    )


def _comparison_sources_for(source: str) -> set[str]:
    if source in {"nmap", "nmap_xml"}:
        return {"nmap", "nmap_xml"}
    if source == "nuclei":
        return {"nuclei"}

    return {source}


def enrich_open_ports(open_ports: list[dict]) -> list[dict]:
    enriched_ports = []
    for open_port in open_ports:
        enriched_ports.append(
            {
                **open_port,
                "intelligence": get_service_intelligence(
                    service_name=str(open_port.get("service", "")),
                    port=str(open_port.get("port", "")),
                ),
            }
        )

    return enriched_ports


def _format_ports(open_ports: list[dict]) -> str:
    if not open_ports:
        return "none"

    return ", ".join(
        f"{open_port.get('port')}/{open_port.get('protocol')} {open_port.get('service')}" for open_port in open_ports
    )


def _format_risk_change(comparison: dict) -> str:
    if comparison.get("risk_changed"):
        return f"{str(comparison.get('previous_risk')).upper()} -> {str(comparison.get('current_risk')).upper()}"

    return "none"


async def scan_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    if update.effective_user is not None:
        clear_finding_analysis_context(update.effective_user.id)

    await update.message.reply_text(
        build_scan_text(),
        reply_markup=build_scan_type_keyboard(),
    )


async def scan_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return

    await query.answer()

    if query.data == "nav:home":
        clear_assessment_flow_state(context)
        await query.edit_message_text(build_home_text())
        if query.message is not None:
            await query.message.reply_text(
                "Main menu",
                reply_markup=build_main_menu_keyboard(),
            )
        return

    if query.data and query.data.startswith(f"{BBOT_AI_ASSESSMENT_CALLBACK_PREFIX}:"):
        user_id = update.effective_user.id if update.effective_user is not None else None
        if user_id is None:
            await query.edit_message_text("Unable to identify Telegram user.")
            return
        await _handle_bbot_ai_assessment_callback(query, user_id)
        return

    if query.data and query.data.startswith(f"{AI_SUMMARY_CALLBACK_PREFIX}:"):
        user_id = update.effective_user.id if update.effective_user is not None else None
        if user_id is None:
            await query.edit_message_text("Unable to identify Telegram user.")
            return
        await _handle_scan_ai_summary_callback(query, user_id)
        return

    if query.data is None or not query.data.startswith("scan:"):
        return

    scan_type = query.data.removeprefix("scan:")
    if scan_type not in SUPPORTED_SCAN_TYPES:
        await query.edit_message_text("Unsupported scan type.")
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is None:
        await query.edit_message_text("Unable to identify Telegram user.")
        return

    scan_request = create_scan_request(user_id=user_id, scan_type=scan_type)
    if scan_type == "nmap":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_nmap_target_prompt())
        return

    if scan_type == "nuclei":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_nuclei_target_prompt())
        return

    if scan_type == "bbot":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_bbot_target_prompt())
        return

    if scan_type == "httpx":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_httpx_target_prompt())
        return

    if scan_type == "katana":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_katana_target_prompt())
        return

    await query.edit_message_text(build_scan_created_text(scan_type))


async def scan_target_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is not None:
        finding_analysis_context = get_finding_analysis_context(user_id)
        if finding_analysis_context is not None:
            if _is_finding_analysis_exit_message(update.message.text or ""):
                clear_finding_analysis_context(user_id)
                logger.info("Finding analysis ended for user_id=%s", user_id)
                await update.message.reply_text("Exited Finding Analysis Mode.", reply_markup=build_main_menu_keyboard())
                return

            logger.info("Finding analysis question for user_id=%s", user_id)
            await update.message.reply_text("Analyzing...")
            prompt = build_finding_followup_ai_prompt(finding_analysis_context, update.message.text or "")
            try:
                logger.info("AI request started for finding analysis user_id=%s", user_id)
                ai_response = await asyncio.to_thread(ask_ai, prompt)
                logger.info("AI request completed for finding analysis user_id=%s", user_id)
            except Exception:
                logger.exception("Finding analysis AI request failed for user_id=%s", user_id)
                await update.message.reply_text("AI request failed. Check bot logs.")
                return

            await update.message.reply_text(ai_response)
            return

    if is_assessment_chat_active(context):
        handled = await assessment_chat_text_handler(update, context)
        if handled:
            return

    if user_id is not None and is_ai_waiting(user_id):
        logger.info("Ask Mongrel question received for user_id=%s", user_id)
        await update.message.reply_text("Analyzing...")
        try:
            logger.info("AI request started for user_id=%s", user_id)
            ai_response = await asyncio.to_thread(ask_ai, update.message.text or "")
            logger.info("AI request completed for user_id=%s", user_id)
        except Exception:
            logger.exception("AI request failed for user_id=%s", user_id)
            await update.message.reply_text("AI request failed. Check bot logs.")
            return

        await update.message.reply_text(ai_response)
        return

    if update.message.text in MAIN_MENU_BUTTONS:
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        clear_assessment_flow_state(context)
        return

    if is_assessment_flow_active(context):
        handled = await assessment_text_handler(update, context)
        if handled:
            return

    scan_request_id = context.user_data.get(PENDING_NMAP_REQUEST_KEY)
    if user_id is None or not isinstance(scan_request_id, str):
        return

    scan_request = get_scan_request(user_id=user_id, scan_request_id=scan_request_id)
    if scan_request is None or scan_request.status != "awaiting_target":
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    if scan_request.scan_type == "nuclei":
        await _handle_nuclei_target(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type == "bbot":
        await _handle_bbot_target(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type == "httpx":
        await _handle_httpx_target(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type == "katana":
        await _handle_katana_target(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type != "nmap":
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    target = update.message.text or ""
    try:
        normalized_target = normalize_for_nmap(target)
    except ValueError as exc:
        await update.message.reply_text(f"Invalid NMAP target: {exc}")
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    investigation = get_or_create_latest_open_investigation(user_id=user_id, target=normalized_target)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=normalized_target,
        event_type="nmap_scan_started",
        tool="nmap",
        status="started",
        summary="Nmap scan started",
    )
    progress_card = ScanProgressCard(update.message, "Nmap Scan", normalized_target)
    await progress_card.start("Launching scan...")

    try:
        result = await asyncio.to_thread(run_nmap_scan, target)
    except ValueError as exc:
        await progress_card.fail(str(exc))
        await update.message.reply_text(f"Invalid NMAP target: {exc}")
        return

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result["target"]),
        result=result,
    )
    finding = store_successful_nmap_finding(user_id=user_id, result=result)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=str(result["target"]),
        event_type="nmap_scan_completed",
        tool="nmap",
        status="completed" if result.get("success") is True else "failed",
        summary="Nmap scan completed" if result.get("success") is True else "Nmap scan failed",
        metadata={"finding_id": finding.get("id") if finding else None},
    )
    assessment_context = _pop_assessment_scan_context(context, "nmap")
    _record_assessment_scan(assessment_context, tool="nmap", result=result, finding=finding)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    if result.get("success") is True:
        await progress_card.complete()
    else:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
    await update.message.reply_text(
        append_change_summary(
            build_nmap_scan_result_text(result),
            finding.get("comparison") if finding else None,
            finding.get("impact") if finding else None,
        ),
        reply_markup=build_scan_result_actions(finding.get("id") if finding else None, "nmap"),
    )
    if result.get("success") is True and finding:
        await _send_nmap_ai_assessment(update.message, finding)
    await _send_assessment_dashboard(update.message, assessment_context)


async def _send_nmap_ai_assessment(message: object, finding: dict) -> None:
    progress_message = await message.reply_text("Generating Nmap AI assessment...")
    assessment_lines = await asyncio.to_thread(generate_nmap_ai_assessment, finding)
    if assessment_lines == NMAP_AI_FALLBACK_LINES:
        await safe_edit_text(progress_message, "Nmap AI assessment unavailable.", context="Nmap AI assessment status")
        await message.reply_text("\n".join(assessment_lines))
        return

    await safe_edit_text(progress_message, "AI assessment ready.", context="Nmap AI assessment status")
    assessment_text = render_ai_summary_card(assessment_lines, title="Nmap AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _send_nuclei_ai_assessment(message: object, finding: dict) -> None:
    progress_message = await message.reply_text("Generating Nuclei AI assessment...")
    assessment_lines = await asyncio.to_thread(generate_nuclei_ai_assessment, finding)
    if assessment_lines == NUCLEI_AI_FALLBACK_LINES:
        await safe_edit_text(progress_message, "Nuclei AI assessment unavailable.", context="Nuclei AI assessment status")
        await message.reply_text("\n".join(assessment_lines))
        return

    await safe_edit_text(progress_message, "AI assessment ready.", context="Nuclei AI assessment status")
    assessment_text = render_ai_summary_card(assessment_lines, title="Nuclei AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _send_httpx_ai_assessment(message: object, finding: dict) -> None:
    progress_message = await message.reply_text("Generating httpx AI assessment...")
    assessment_lines = await asyncio.to_thread(generate_httpx_ai_assessment, finding)
    if assessment_lines == HTTPX_AI_FALLBACK_LINES:
        await safe_edit_text(progress_message, "httpx AI assessment unavailable.", context="httpx AI assessment status")
        await message.reply_text("\n".join(assessment_lines))
        return

    await safe_edit_text(progress_message, "AI assessment ready.", context="httpx AI assessment status")
    assessment_text = render_ai_summary_card(assessment_lines, title="httpx AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _send_katana_ai_assessment(message: object, finding: dict) -> None:
    progress_message = await message.reply_text("Generating Katana AI assessment...")
    assessment_lines = await asyncio.to_thread(generate_katana_ai_assessment, finding)
    if assessment_lines == KATANA_AI_FALLBACK_LINES:
        await safe_edit_text(progress_message, "Katana AI assessment unavailable.", context="Katana AI assessment status")
        await message.reply_text("\n".join(assessment_lines))
        return

    await safe_edit_text(progress_message, "AI assessment ready.", context="Katana AI assessment status")
    assessment_text = render_ai_summary_card(assessment_lines, title="Katana AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _handle_katana_target(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    scan_request_id: str,
) -> None:
    if update.message is None:
        return

    target = update.message.text or ""
    try:
        display_target = normalize_for_katana(target)
    except ValueError as exc:
        await update.message.reply_text(f"Invalid Katana target: {exc}")
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    investigation = get_or_create_latest_open_investigation(user_id=user_id, target=display_target)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=display_target,
        event_type="katana_scan_started",
        tool="katana",
        status="started",
        summary="Katana crawl started",
    )
    progress_card = ScanProgressCard(update.message, "Katana Crawl", display_target)
    await progress_card.start("Launching crawl...")

    try:
        result = await asyncio.to_thread(run_katana_scan, target)
    except ValueError as exc:
        await progress_card.fail(str(exc))
        add_investigation_event(
            investigation_id=investigation["id"],
            user_id=user_id,
            target=display_target,
            event_type="katana_scan_failed",
            tool="katana",
            status="failed",
            summary="Katana crawl failed",
        )
        await update.message.reply_text(f"Invalid Katana target: {exc}")
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result["target"]),
        result=result,
    )
    observations = parse_katana_output(str(result.get("output") or "")) if result.get("output") else []
    finding = store_katana_scan_result(user_id=user_id, result=result, observations=observations)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=str(result["target"]),
        event_type="katana_scan_completed" if result.get("success") is True else "katana_scan_failed",
        tool="katana",
        status="completed" if result.get("success") is True else "failed",
        summary="Katana crawl completed" if result.get("success") is True else "Katana crawl failed",
        metadata={"finding_id": finding.get("id"), "url_count": len(observations)},
    )
    assessment_context = _pop_assessment_scan_context(context, "katana")
    _record_assessment_scan(assessment_context, tool="katana", result=result, finding=finding)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    if result.get("success") is True:
        await progress_card.complete()
    else:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
    await update.message.reply_text(
        build_katana_result_text(result, observations),
        reply_markup=build_scan_result_actions(finding.get("id"), "katana") if result.get("success") is True else None,
    )
    if result.get("success") is True:
        await _send_katana_ai_assessment(update.message, finding)
    await _send_assessment_dashboard(update.message, assessment_context)


async def _handle_httpx_target(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    scan_request_id: str,
) -> None:
    if update.message is None:
        return

    target = update.message.text or ""
    try:
        display_target = normalize_for_httpx(target)
    except ValueError as exc:
        await update.message.reply_text(f"Invalid httpx target: {exc}")
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    investigation = get_or_create_latest_open_investigation(user_id=user_id, target=display_target)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=display_target,
        event_type="httpx_scan_started",
        tool="httpx",
        status="started",
        summary="httpx fingerprinting started",
    )
    progress_card = ScanProgressCard(update.message, "httpx Scan", display_target)
    await progress_card.start("Launching scan...")

    try:
        result = await asyncio.to_thread(run_httpx_scan, target)
    except ValueError as exc:
        await progress_card.fail(str(exc))
        add_investigation_event(
            investigation_id=investigation["id"],
            user_id=user_id,
            target=display_target,
            event_type="httpx_scan_failed",
            tool="httpx",
            status="failed",
            summary="httpx fingerprinting failed",
        )
        await update.message.reply_text(f"Invalid httpx target: {exc}")
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result["target"]),
        result=result,
    )
    services = parse_httpx_output(str(result.get("output") or "")) if result.get("output") else []
    finding = store_httpx_scan_result(user_id=user_id, result=result, services=services)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=str(result["target"]),
        event_type="httpx_scan_completed" if result.get("success") is True else "httpx_scan_failed",
        tool="httpx",
        status="completed" if result.get("success") is True else "failed",
        summary="httpx fingerprinting completed" if result.get("success") is True else "httpx fingerprinting failed",
        metadata={"finding_id": finding.get("id"), "service_count": len(services)},
    )
    assessment_context = _pop_assessment_scan_context(context, "httpx")
    _record_assessment_scan(assessment_context, tool="httpx", result=result, finding=finding)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    if result.get("success") is True:
        await progress_card.complete()
    else:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
    await update.message.reply_text(
        build_httpx_result_text(result, services),
        reply_markup=build_scan_result_actions(finding.get("id"), "httpx") if result.get("success") is True else None,
    )
    if result.get("success") is True:
        await _send_httpx_ai_assessment(update.message, finding)
    await _send_assessment_dashboard(update.message, assessment_context)


async def _handle_bbot_target(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    scan_request_id: str,
) -> None:
    if update.message is None:
        return

    target = update.message.text or ""
    try:
        display_target = normalize_for_bbot(target)
    except ValueError as exc:
        await update.message.reply_text(f"Invalid BBOT target: {exc}")
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    if not is_bbot_available():
        await update.message.reply_text("BBOT is not installed or not available on PATH.")
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    investigation = get_or_create_latest_open_investigation(user_id=user_id, target=display_target)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=display_target,
        event_type="bbot_scan_started",
        tool="bbot",
        status="started",
        summary="BBOT recon started",
    )
    progress_card = ScanProgressCard(update.message, "BBOT Scan", display_target)
    await progress_card.start("Launching scan...")
    await progress_card.start_auto_refresh("Launching scan...", interval_seconds=5)

    try:
        result = await asyncio.to_thread(run_bbot_scan, target)
    except ValueError as exc:
        await progress_card.fail(str(exc))
        add_investigation_event(
            investigation_id=investigation["id"],
            user_id=user_id,
            target=display_target,
            event_type="bbot_scan_failed",
            tool="bbot",
            status="failed",
            summary="BBOT recon failed",
        )
        await update.message.reply_text(f"Invalid BBOT target: {exc}")
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return
    finally:
        await progress_card.stop_auto_refresh()

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result["target"]),
        result=result,
    )
    observations = []
    parser_error = None
    if result.get("output"):
        await progress_card.update("Collecting observations...")
        try:
            observations = normalize_bbot_output(
                result.get("output"),
                target=str(result.get("target") or display_target),
                user_id=user_id,
                investigation_id=investigation["id"],
            )
        except Exception as exc:
            parser_error = str(exc)
            observations = []
        if observations:
            add_observations(observations)
    observation_counts = summarize_observations(observations)
    if result.get("success") is not True and observations:
        result = {**result, "partial": True, "parser_error": parser_error}
    elif parser_error:
        result = {**result, "parser_error": parser_error}
    finding = store_bbot_scan_result(user_id=user_id, result=result, observations=observations)
    is_partial = result.get("partial") is True
    is_successful_or_partial = result.get("success") is True or is_partial
    event_type = "bbot_scan_partial" if is_partial else ("bbot_scan_completed" if result.get("success") is True else "bbot_scan_failed")
    observation_count = len(observations)
    recon_summary = None
    if is_successful_or_partial:
        recon_summary = build_bbot_recon_summary(
            user_id=user_id,
            investigation_id=investigation["id"],
            target=str(result.get("target") or display_target),
        )
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=str(result["target"]),
        event_type=event_type,
        tool="bbot",
        status="partial" if is_partial else ("completed" if result.get("success") is True else "failed"),
        summary=(
            f"BBOT scan partial - Recon Summary Generated ({observation_count} observations)."
            if is_partial
            else (
                f"BBOT scan completed - Recon Summary Generated ({observation_count} observations)."
                if result.get("success") is True
                else "BBOT recon failed"
            )
        ),
        metadata={"finding_id": finding.get("id"), "observation_count": observation_count, "partial": is_partial},
    )
    assessment_context = _pop_assessment_scan_context(context, "bbot")
    _record_assessment_scan(assessment_context, tool="bbot", result=result, finding=finding)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    if is_partial:
        await progress_card.partial()
    elif result.get("success") is True:
        await progress_card.complete()
    else:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
    chunks = split_report_text(build_bbot_result_text(result, observation_counts, recon_summary=recon_summary))
    keyboard = (
        _combine_inline_keyboards(
            build_scan_result_actions(finding.get("id"), "bbot"),
            build_bbot_ai_assessment_keyboard(investigation["id"]),
        )
        if result.get("success") is True
        or is_partial
        else None
    )
    for index, chunk in enumerate(chunks):
        kwargs = {"reply_markup": keyboard} if keyboard is not None and index == len(chunks) - 1 else {}
        await update.message.reply_text(chunk, **kwargs)
    await _send_assessment_dashboard(update.message, assessment_context)


async def _handle_bbot_ai_assessment_callback(query: object, user_id: int) -> None:
    data = str(getattr(query, "data", "") or "")
    investigation_id = data.removeprefix(f"{BBOT_AI_ASSESSMENT_CALLBACK_PREFIX}:")
    investigation = get_investigation(investigation_id, user_id)
    if investigation is None:
        await query.edit_message_text("Investigation not found for BBOT AI assessment.")
        return

    message = getattr(query, "message", None)
    progress_message = None
    stop_event: asyncio.Event | None = None
    progress_task: asyncio.Task | None = None
    progress_frames = build_spinner_frames("Generating AI Recon Assessment")
    if message is not None:
        progress_message = await message.reply_text(progress_frames[0])
        stop_event = asyncio.Event()
        progress_task = asyncio.create_task(
            run_progress_frames(
                progress_message,
                progress_frames,
                stop_event,
                start_index=1,
                context="BBOT AI assessment status",
            )
        )
    else:
        await safe_edit_text(query, progress_frames[0], context="BBOT AI assessment status")

    try:
        assessment_lines = await asyncio.to_thread(
            generate_bbot_ai_assessment,
            user_id,
            investigation_id=investigation_id,
            target=investigation.get("target"),
        )
    finally:
        if stop_event is not None and progress_task is not None:
            stop_event.set()
            await progress_task

    fallback = assessment_lines == FALLBACK_LINES
    event = add_investigation_event(
        investigation_id=investigation_id,
        user_id=user_id,
        target=investigation.get("target"),
        event_type="bbot_ai_assessment_fallback" if fallback else "bbot_ai_assessment_generated",
        tool="bbot",
        status="completed" if not fallback else "fallback",
        summary="BBOT AI Recon Assessment Generated" if not fallback else "BBOT AI Recon Assessment Fallback",
        metadata={"line_count": len(assessment_lines), "fallback": fallback},
    )
    final_status = "AI Recon Assessment unavailable." if fallback else "AI Recon Assessment ready."
    if progress_message is not None:
        await safe_edit_text(progress_message, final_status, context="BBOT AI assessment status")
    else:
        await safe_edit_text(query, final_status, context="BBOT AI assessment status")

    if message is None:
        await query.edit_message_text("\n".join(assessment_lines))
        return

    assessment_text = (
        "\n".join(assessment_lines)
        if fallback
        else render_ai_summary_card(assessment_lines, title="BBOT AI Assessment")
    )
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)

    logger.info("BBOT AI assessment event recorded: id=%s fallback=%s", event.get("id"), fallback)


async def _handle_scan_ai_summary_callback(query: object, user_id: int) -> None:
    data = str(getattr(query, "data", "") or "")
    parts = data.split(":", 2)
    if len(parts) != 3:
        await query.edit_message_text("Invalid AI summary request.")
        return

    _, tool, finding_id = parts
    finding = get_user_finding(user_id=user_id, finding_id=finding_id)
    if finding is None:
        await query.edit_message_text("Stored scan result not found.")
        return

    message = getattr(query, "message", None)
    if message is None:
        await query.edit_message_text("Generating AI summary...")
        return

    progress_message = await message.reply_text("Generating AI summary...")
    summary_lines = await asyncio.to_thread(generate_scan_ai_summary, finding)
    final_status = "AI summary unavailable." if summary_lines == FALLBACK_SUMMARY_LINES else "AI summary ready."
    await safe_edit_text(progress_message, final_status, context="Scan AI summary status")

    summary_text = render_ai_summary_card(summary_lines)
    for chunk in split_report_text(summary_text):
        await message.reply_text(chunk)

    logger.info("Scan AI summary generated for user_id=%s tool=%s finding_id=%s", user_id, tool, finding_id)


def _is_finding_analysis_exit_message(text: str) -> bool:
    return text.strip().lower() in {"home", "cancel", "/home", "/cancel"}


def _truncate_bbot_output(output: str, limit: int = 900) -> str:
    normalized_output = output.strip()
    if not normalized_output:
        return "No output returned."
    if len(normalized_output) <= limit:
        return normalized_output
    return f"{normalized_output[:limit].rstrip()}\n...[truncated]"


def _safe_truncated_text(output: str, limit: int = 3000) -> str:
    normalized_output = str(output or "").strip()
    if not normalized_output:
        return "No output returned."
    if len(normalized_output) <= limit:
        return normalized_output
    return f"{normalized_output[:limit].rstrip()}\n...[truncated]"


def _build_bbot_summary(observation_counts: dict[str, int]) -> str:
    total_observations = sum(observation_counts.values())
    if total_observations == 0:
        return "BBOT completed but no structured observations were extracted."

    return "\n".join(
        [
            "BBOT recon completed.",
            "Observations:",
            f"- Subdomains: {observation_counts.get('subdomain', 0)}",
            f"- URLs: {observation_counts.get('url', 0)}",
            f"- IP Addresses: {observation_counts.get('ip_address', 0)}",
            f"- Emails: {observation_counts.get('email', 0)}",
            f"- Technologies: {observation_counts.get('technology', 0)}",
            f"- Raw Events: {observation_counts.get('raw_event', 0)}",
        ]
    )


async def _handle_nuclei_target(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    scan_request_id: str,
) -> None:
    if update.message is None:
        return

    target = update.message.text or ""
    try:
        display_target = normalize_for_nuclei(target)
    except ValueError as exc:
        await update.message.reply_text(f"Invalid Nuclei target: {exc}")
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    investigation = get_or_create_latest_open_investigation(user_id=user_id, target=display_target)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=display_target,
        event_type="nuclei_scan_started",
        tool="nuclei",
        status="started",
        summary="Nuclei scan started",
    )
    progress_card = ScanProgressCard(update.message, "Nuclei Scan", display_target)
    status_message = await progress_card.start("Launching scan...")
    active_scan = set_active_scan(
        user_id=user_id,
        scan_type="nuclei",
        target=display_target,
        status_message=status_message,
    )
    started_at = progress_card.started_at
    assessment_context = _pop_assessment_scan_context(context, "nuclei")
    status_task = asyncio.create_task(_update_nuclei_status_card(user_id, status_message, display_target, started_at))
    task = asyncio.create_task(
        _run_nuclei_scan_background(
            user_id=user_id,
            scan_request_id=scan_request_id,
            target=target,
            message=update.message,
            progress_card=progress_card,
            display_target=display_target,
            started_at=started_at,
            investigation_id=investigation["id"],
            assessment_context=assessment_context,
        )
    )
    set_active_scan_status_task(user_id, status_task)
    set_active_scan_task(user_id, task)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    logger.info(
        "Nuclei scan started for user_id=%s target=%s started_at=%s",
        user_id,
        active_scan.target,
        active_scan.started_at.isoformat(),
    )


async def _run_nuclei_scan_background(
    user_id: int,
    scan_request_id: str,
    target: str,
    message: object,
    progress_card: ScanProgressCard,
    display_target: str,
    started_at: float,
    investigation_id: str,
    assessment_context: dict | None = None,
) -> None:
    try:
        result = await asyncio.to_thread(run_nuclei_scan, target)
    except ValueError as exc:
        _stop_nuclei_status_updates(user_id)
        clear_active_scan(user_id)
        await progress_card.fail(str(exc))
        add_investigation_event(
            investigation_id=investigation_id,
            user_id=user_id,
            target=display_target,
            event_type="nuclei_scan_completed",
            tool="nuclei",
            status="failed",
            summary="Nuclei scan failed",
        )
        await _send_scan_message(message, f"Invalid Nuclei target: {exc}")
        _record_assessment_scan(
            assessment_context,
            tool="nuclei",
            result={"success": False, "target": display_target, "error": str(exc)},
        )
        await _send_assessment_dashboard(message, assessment_context)
        return
    except asyncio.CancelledError:
        elapsed_seconds = time.monotonic() - started_at
        await progress_card.update("Cancelled")
        logger.info("Nuclei scan cancelled for user_id=%s elapsed_seconds=%.2f", user_id, elapsed_seconds)
        raise

    active_scan = get_active_scan(user_id)
    if active_scan is None or active_scan.cancelled:
        elapsed_seconds = time.monotonic() - started_at
        logger.info("Nuclei scan result discarded for user_id=%s elapsed_seconds=%.2f", user_id, elapsed_seconds)
        return

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result["target"]),
        result=result,
    )
    _stop_nuclei_status_updates(user_id)
    clear_active_scan(user_id)
    elapsed_seconds = time.monotonic() - started_at
    elapsed_label = f"{int(elapsed_seconds)}s"
    logger.info("Nuclei scan completed for user_id=%s elapsed_seconds=%.2f", user_id, elapsed_seconds)

    if result.get("success") is not True:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
        add_investigation_event(
            investigation_id=investigation_id,
            user_id=user_id,
            target=display_target,
            event_type="nuclei_scan_completed",
            tool="nuclei",
            status="failed",
            summary="Nuclei scan failed",
        )
        await _send_scan_message(message, f"Nuclei scan failed: {result.get('error') or 'Unknown error.'}")
        _record_assessment_scan(assessment_context, tool="nuclei", result=result)
        await _send_assessment_dashboard(message, assessment_context)
        return

    await progress_card.complete()
    output = str(result.get("output") or "")
    if not output.strip():
        clean_target = str(result.get("target") or target)
        finding = store_clean_nuclei_scan(user_id=user_id, target=clean_target)
        add_investigation_event(
            investigation_id=investigation_id,
            user_id=user_id,
            target=clean_target,
            event_type="nuclei_scan_completed",
            tool="nuclei",
            status="completed",
            summary="Nuclei scan completed with no findings",
            metadata={"finding_id": finding.get("id")},
        )
        await _send_scan_message(
            message,
            build_clean_nuclei_verdict_text(clean_target, elapsed=elapsed_label),
            reply_markup=build_scan_result_actions(finding.get("id"), "nuclei"),
        )
        finding.setdefault("metadata", {})
        finding["metadata"].update({"elapsed": elapsed_label, "elapsed_seconds": int(elapsed_seconds), "scan_profile": "fast"})
        _record_assessment_scan(assessment_context, tool="nuclei", result=result, finding=finding)
        await _send_nuclei_ai_assessment(message, finding)
        await _send_assessment_dashboard(message, assessment_context)
        return

    try:
        nuclei_findings = parse_nuclei_results(output)
    except NucleiParserError:
        await _send_scan_message(message, "Unable to parse Nuclei scan output.")
        _record_assessment_scan(
            assessment_context,
            tool="nuclei",
            result={**result, "success": False, "error": "Unable to parse Nuclei scan output."},
        )
        await _send_assessment_dashboard(message, assessment_context)
        return

    if not nuclei_findings:
        clean_target = str(result.get("target") or target)
        finding = store_clean_nuclei_scan(user_id=user_id, target=clean_target)
        add_investigation_event(
            investigation_id=investigation_id,
            user_id=user_id,
            target=clean_target,
            event_type="nuclei_scan_completed",
            tool="nuclei",
            status="completed",
            summary="Nuclei scan completed with no findings",
            metadata={"finding_id": finding.get("id")},
        )
        await _send_scan_message(
            message,
            build_clean_nuclei_verdict_text(clean_target, elapsed=elapsed_label),
            reply_markup=build_scan_result_actions(finding.get("id"), "nuclei"),
        )
        finding.setdefault("metadata", {})
        finding["metadata"].update({"elapsed": elapsed_label, "elapsed_seconds": int(elapsed_seconds), "scan_profile": "fast"})
        _record_assessment_scan(assessment_context, tool="nuclei", result=result, finding=finding)
        await _send_nuclei_ai_assessment(message, finding)
        await _send_assessment_dashboard(message, assessment_context)
        return

    from app.bot.handlers.upload import build_nuclei_import_success_text, store_nuclei_finding

    finding = store_nuclei_finding(user_id=user_id, nuclei_findings=nuclei_findings)
    finding.setdefault("metadata", {})
    finding["metadata"].update({"elapsed": elapsed_label, "elapsed_seconds": int(elapsed_seconds), "scan_profile": "fast"})
    add_investigation_event(
        investigation_id=investigation_id,
        user_id=user_id,
        target=str(finding.get("target") or display_target),
        event_type="nuclei_scan_completed",
        tool="nuclei",
        status="completed",
        summary="Nuclei scan completed",
        metadata={"finding_id": finding.get("id"), "finding_count": finding.get("finding_count")},
    )
    await _send_scan_message(
        message,
        build_nuclei_import_success_text(finding, elapsed=elapsed_label),
        reply_markup=build_scan_result_actions(finding.get("id"), "nuclei"),
    )
    _record_assessment_scan(assessment_context, tool="nuclei", result=result, finding=finding)
    await _send_nuclei_ai_assessment(message, finding)
    await _send_assessment_dashboard(message, assessment_context)


async def _update_nuclei_status_card(user_id: int, status_message: object, target: str, started_at: float) -> None:
    progress_card = ScanProgressCard.from_status_message(status_message, "Nuclei Scan", target, started_at)
    try:
        while True:
            await asyncio.sleep(NUCLEI_STATUS_UPDATE_INTERVAL_SECONDS)
            active_scan = get_active_scan(user_id)
            if active_scan is None or active_scan.cancelled:
                return

            await progress_card.update("Running")
    except asyncio.CancelledError:
        return


def _stop_nuclei_status_updates(user_id: int) -> None:
    active_scan = get_active_scan(user_id)
    if active_scan is not None and active_scan.status_task is not None and not active_scan.status_task.done():
        active_scan.status_task.cancel()


async def _finalize_nuclei_status(
    status_message: object,
    target: str,
    status: str,
    started_at: float,
    reason: str | None = None,
) -> None:
    progress_card = ScanProgressCard.from_status_message(status_message, "Nuclei Scan", target, started_at)
    if status == "Complete":
        await progress_card.complete()
    elif status == "Failed":
        await progress_card.fail(reason or "Unknown error.")
    else:
        await progress_card.update(status)


async def _edit_status_message(status_message: object, text: str) -> None:
    await safe_edit_text(status_message, text, context="Scan progress")


async def _send_scan_message(message: object, text: str, reply_markup: InlineKeyboardMarkup | None = None) -> None:
    reply_text = getattr(message, "reply_text", None)
    if reply_text is None:
        return

    try:
        kwargs = {"reply_markup": reply_markup} if reply_markup is not None else {}
        await reply_text(text, **kwargs)
    except Exception:
        logger.exception("Failed to send Nuclei scan result message.")
