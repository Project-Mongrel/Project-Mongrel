import asyncio
import base64
import html
import json
import logging
import secrets
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup, Update
from telegram.error import BadRequest
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.bot.keyboards.tool_mode_actions import build_tool_mode_post_scan_keyboard
from app.core.config import get_settings
from app.ui.scan_actions import build_scan_result_actions
from app.ui.result_cards import render_scan_result_card
from app.bot.handlers.scan import store_parsed_nmap_finding
from app.bot.handlers.reports import split_report_text
from app.parsers.nmap_xml_parser import parse_nmap_xml
from app.parsers.nuclei_parser import NucleiParserError, parse_nuclei_results
from app.parsers.metasploit_parser import parse_metasploit_validation_result
from app.parsers.tshark_parser import normalize_tshark_result
from app.services.ai_client import ask_ai
from app.services.assessment_store import (
    add_assessment_artifact,
    finalize_assessment_scan,
    get_assessment,
    list_assessment_scans,
    list_assessment_targets,
    record_assessment_scan,
    start_assessment_scan,
)
from app.services.assessment_map_ingestion import AssessmentMapIngestionError, ingest_assessment_scan
from app.services.assessment_map_store import AssessmentMapScopeError
from app.services.chat_state import clear_finding_analysis_context
from app.services.findings_store import add_finding
from app.services.icon_helper import icon_label, section_label
from app.services.metasploit_approval import (
    MetasploitApprovalError,
    approve_metasploit_proposal,
    get_metasploit_proposal,
    list_metasploit_proposals,
    propose_metasploit_action,
    record_metasploit_result_reference,
)
from app.services.target_normalizer import normalize_target_key
from app.services.scan_status import scan_status_from_result
from app.services.tshark_approval import TSharkApprovalError, approve_tshark_capture, get_tshark_capture_proposal, propose_tshark_capture, reject_tshark_capture
from app.services.tshark_metasploit_correlation import (
    build_tshark_metasploit_correlation_record,
    generate_tshark_metasploit_correlated_assessment,
)
from app.services.tshark_ai_assessment import FALLBACK_LINES as TSHARK_AI_FALLBACK_LINES, generate_tshark_ai_assessment
from app.services.tshark_policy import build_tshark_capture_request
from app.services.tshark_validation_capture import DEFAULT_POST_VALIDATION_TAIL_SECONDS, run_tshark_capture_during_validation
from app.services.verdict_engine import generate_mongrel_verdict
from app.tools.tshark_live_runner import check_tshark_live_readiness, run_tshark_live_capture
from app.tools.tshark_runner import check_tshark_readiness, run_tshark_offline_analysis
from app.ui.ai_summary import render_ai_summary_card

UPLOAD_STATE_AWAITING_NMAP_XML = "awaiting_nmap_xml"
UPLOAD_STATE_AWAITING_TSHARK_PCAP = "awaiting_tshark_pcap"
UPLOAD_EXPLAIN_CALLBACK = "upload:explain_ai"
MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024
MAX_TSHARK_UPLOAD_SIZE_BYTES = 25 * 1024 * 1024
MAX_OPEN_SERVICES_IN_UPLOAD_SUMMARY = 10
MAX_NUCLEI_FINDINGS_IN_REPORT = 10
MAX_UPLOAD_REPORT_LENGTH = 3800
MAX_TSHARK_CARD_LENGTH = 3800
NUCLEI_SEVERITIES = ("critical", "high", "medium", "low", "info")
_upload_states: dict[int, str] = {}
_tshark_assessment_upload_contexts: dict[int, dict] = {}
_tshark_live_contexts: dict[str, dict] = {}
_tshark_capture_validation_tokens: dict[str, dict] = {}
_latest_upload_scan_summaries: dict[int, dict] = {}
logger = logging.getLogger(__name__)
TSHARK_RUNNING_SCAN_GUARD_KEY = "tshark_running_scan_guard"


def build_upload_text() -> str:
    return (
        f"{section_label('upload', 'Supported Uploads')}\n\n"
        "- Nmap XML (supported)\n"
        "- Nuclei JSON (supported)\n"
        "- Nuclei JSONL (supported)\n"
        "- TShark PCAP/PCAPNG (supported via Scan > TShark PCAP)\n"
        "- BBOT (coming soon)\n"
        "- Logs (coming soon)\n\n"
        "Send an Nmap XML or Nuclei results file to begin analysis."
    )


def build_tshark_upload_prompt() -> str:
    return (
        f"{section_label('scan', 'TShark PCAP Upload')}\n\n"
        "Upload a local .pcap or .pcapng file for offline metadata analysis.\n\n"
        "This uses TShark with -r only. Live capture, interfaces, and arbitrary filters are not supported."
    )


def build_tshark_upload_controls() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup([[KeyboardButton("Cancel")]], resize_keyboard=True)


def build_tshark_mode_text() -> str:
    return (
        f"{section_label('scan', 'TShark')}\n\n"
        "Choose how to analyze packet metadata.\n\n"
        "Capture During Validation prepares a bounded capture around an approved validation. Analyze PCAP uses an existing .pcap or .pcapng file. Standalone Live Capture requires explicit approval and uses only configured allowlisted interfaces."
    )


def build_tshark_mode_keyboard(assessment_id: int | None = None) -> InlineKeyboardMarkup:
    suffix = f":{int(assessment_id)}" if assessment_id is not None else ""
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Capture During Validation", callback_data=f"tshark:capture{suffix}")],
            [InlineKeyboardButton("Analyze PCAP", callback_data=f"tshark:upload{suffix}")],
            [InlineKeyboardButton("Standalone Live Capture", callback_data=f"tshark:live{suffix}")],
            [InlineKeyboardButton("Back", callback_data="nav:home" if assessment_id is None else f"assessment:dashboard:{int(assessment_id)}")],
        ]
    )


def build_tshark_interface_keyboard(interfaces: list[str], assessment_id: int | None = None) -> InlineKeyboardMarkup:
    action = "iface" if assessment_id is None else f"iface_assessment:{int(assessment_id)}"
    rows = [[InlineKeyboardButton(interface, callback_data=f"tshark:{action}:{_encode_callback_value(interface)}")] for interface in interfaces[:12]]
    rows.append([InlineKeyboardButton("Back", callback_data="tshark:choose" if assessment_id is None else f"tshark:choose:{int(assessment_id)}")])
    return InlineKeyboardMarkup(rows)


def build_tshark_live_proposal_text(proposal: object, *, details: bool = False) -> str:
    request = getattr(proposal, "request", {}) or {}
    lines = [
        f"{section_label('scan', 'TShark Live Capture Proposal')}",
        "",
        "Controlled live capture for authorized environments only.",
        "",
        "Interface:",
        _escape(request.get("interface") or "unknown"),
        "",
        "Duration:",
        f"{int(request.get('duration_seconds') or 0)} seconds",
        "",
        "Packet Limit:",
        str(int(request.get("packet_count") or 0)),
        "",
        "File Size Limit:",
        f"{int(request.get('file_size_kb') or 0)} KB",
        "",
        "Risk Tier:",
        _escape(request.get("risk_tier") or "medium"),
        "",
        "Expected Effect:",
        _escape(request.get("expected_effect") or "Bounded packet metadata capture for offline analysis."),
        "",
        "Expires:",
        _escape(getattr(proposal, "expires_at", "")),
        "",
        "Approval is required before capture starts. No filters, raw commands, indefinite capture, or background capture are accepted.",
    ]
    if details:
        lines.extend(
            [
                "",
                "Proposal ID:",
                _escape(getattr(proposal, "id", "")),
                "",
                "Status:",
                _escape(getattr(proposal, "status", "")),
                "",
                "Request Fingerprint:",
                _escape(str(getattr(proposal, "fingerprint", ""))[:16]),
            ]
        )
    return "\n".join(lines)


def build_tshark_live_approval_keyboard(proposal_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Approve", callback_data=f"tshark:approve:{proposal_id}"),
                InlineKeyboardButton("Reject", callback_data=f"tshark:reject:{proposal_id}"),
            ],
            [InlineKeyboardButton("Details", callback_data=f"tshark:details:{proposal_id}")],
        ]
    )


def build_tshark_capture_validation_text(eligible: list[object]) -> str:
    if not eligible:
        return (
            f"{section_label('scan', 'TShark Capture During Validation')}\n\n"
            "No eligible approved or completed Metasploit HTTP service fingerprint validation was found for this user.\n\n"
            "Create the guided HTTP service fingerprint validation first, then return here before or after it runs."
        )
    return (
        f"{section_label('scan', 'TShark Capture During Validation')}\n\n"
        "Choose an approved validation to run while TShark captures bounded packet metadata.\n\n"
        "Only the allowlisted Metasploit HTTP service fingerprint validation is eligible in this foundation. Completed validations are used as exact re-run templates because past traffic cannot be captured retroactively."
    )


def build_tshark_capture_validation_keyboard(user_id: int, eligible: list[object], assessment_id: int | None = None) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for proposal in eligible[:10]:
        request = getattr(proposal, "request", {}) or {}
        token = _register_tshark_capture_validation_token(
            user_id,
            assessment_id=assessment_id,
            metasploit_proposal_id=str(getattr(proposal, "id", "")),
            validation_fingerprint=str(getattr(proposal, "fingerprint", "")),
        )
        rows.append(
            [
                InlineKeyboardButton(
                    f"HTTP Service Fingerprint - {request.get('target')}:{request.get('port')} ({_metasploit_capture_status_label(proposal)})",
                    callback_data=f"tshark:cv:{token}",
                )
            ]
        )
    rows.append([InlineKeyboardButton("Back", callback_data="tshark:choose" if assessment_id is None else f"tshark:choose:{int(assessment_id)}")])
    return InlineKeyboardMarkup(rows)


async def _show_tshark_capture_validation_menu(query: object, user_id: int, eligible: list[object], assessment_id: int | None) -> None:
    try:
        await query.edit_message_text(
            build_tshark_capture_validation_text(eligible),
            reply_markup=build_tshark_capture_validation_keyboard(user_id, eligible, assessment_id) if eligible else build_tshark_mode_keyboard(assessment_id),
        )
    except BadRequest as exc:
        if "message is not modified" not in str(exc).lower():
            raise
        if eligible:
            await query.answer("Eligible capture validations are already shown.", show_alert=True)
        else:
            await query.answer(
                "No fresh eligible validation. Create and approve a new HTTP service fingerprint validation first.",
                show_alert=True,
            )


def build_tshark_capture_interface_keyboard(token_payload: dict, interfaces: list[str]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for interface in interfaces[:12]:
        token = _register_tshark_capture_validation_token(
            int(token_payload["user_id"]),
            assessment_id=_parse_optional_int(token_payload.get("assessment_id")),
            metasploit_proposal_id=str(token_payload["metasploit_proposal_id"]),
            validation_fingerprint=str(token_payload["validation_fingerprint"]),
            interface=interface,
        )
        rows.append([InlineKeyboardButton(interface, callback_data=f"tshark:cvi:{token}")])
    rows.append([InlineKeyboardButton("Back", callback_data="tshark:capture" if token_payload.get("assessment_id") is None else f"tshark:capture:{int(token_payload['assessment_id'])}")])
    return InlineKeyboardMarkup(rows)


def build_tshark_capture_interface_text(proposal: object, interfaces: list[str]) -> str:
    request = getattr(proposal, "request", {}) or {}
    return "\n".join(
        [
            f"{section_label('scan', 'TShark Capture Interface')}",
            "",
            "Choose an allowlisted capture interface.",
            "",
            f"Validation: HTTP Service Fingerprint",
            f"Target: {_escape(request.get('target') or 'unknown')}",
            f"Expected Port: {_escape(request.get('port') or 'unknown')}",
            "",
            "Interfaces:",
            *[f"- {_escape(interface)}" for interface in interfaces[:12]],
        ]
    )


def build_tshark_capture_review_text(proposal: object, validation_proposal: object, *, assessment_id: int | None, post_tail_seconds: int = DEFAULT_POST_VALIDATION_TAIL_SECONDS, details: bool = False) -> str:
    capture_request = getattr(proposal, "request", {}) or {}
    validation_request = getattr(validation_proposal, "request", {}) or {}
    lines = [
        "TShark Capture Review",
        "",
        "Assessment:",
        str(assessment_id if assessment_id is not None else "Standalone validation"),
        "",
        "Validation:",
        "HTTP Service Fingerprint",
        "",
        "Target:",
        _escape(validation_request.get("target") or "unknown"),
        "",
        "Expected Port:",
        str(validation_request.get("port") or "unknown"),
        "",
        "Interface:",
        _escape(capture_request.get("interface") or "unknown"),
        "",
        "Capture Duration:",
        f"{int(capture_request.get('duration_seconds') or 0)} seconds",
        "",
        "Capture Purpose:",
        "Observe network traffic generated during the approved validation.",
        "",
        "This action WILL:",
        "- Start a bounded TShark capture",
        "- Execute the exact reviewed Metasploit validation",
        f"- Stop capture after validation and bounded tail ({post_tail_seconds} seconds)",
        "- Store packet metadata and provenance",
        "",
        "This action WILL NOT:",
        "- Modify the target beyond the approved validation",
        "- Run additional tools",
        "- Continue capturing indefinitely",
        "- Start sessions, post-exploitation, lateral movement, or brute force",
        "",
        "Approval is required before capture or validation starts.",
    ]
    if getattr(validation_proposal, "status", "") == "executed":
        lines.extend(
            [
                "",
                "Completed Validation Handling:",
                "The selected validation already ran. Approval will create a fresh exact Metasploit re-run approval for capture correlation; past traffic cannot be captured retroactively.",
            ]
        )
    if details:
        lines.extend(
            [
                "",
                "Capture Proposal ID:",
                _escape(getattr(proposal, "id", "")),
                "",
                "Validation Proposal ID:",
                _escape(getattr(validation_proposal, "id", "")),
                "",
                "Module:",
                _escape(validation_request.get("module") or "unknown"),
                "",
                "Action:",
                _escape(validation_request.get("action_type") or "unknown"),
                "",
                "Approved Options:",
                _escape(_format_options(validation_request.get("options") or {})),
                "",
                "Capture Fingerprint:",
                _escape(str(getattr(proposal, "fingerprint", ""))[:16]),
                "",
                "Validation Fingerprint:",
                _escape(str(getattr(validation_proposal, "fingerprint", ""))[:16]),
            ]
        )
    return "\n".join(lines)


def build_tshark_capture_review_keyboard(proposal_id: str) -> InlineKeyboardMarkup:
    return build_tshark_live_approval_keyboard(proposal_id)


def set_upload_state(user_id: int, state: str) -> None:
    _upload_states[user_id] = state


def set_tshark_assessment_upload_context(user_id: int, assessment_context: dict) -> None:
    context = dict(assessment_context)
    context.setdefault("user_id", int(user_id))
    _tshark_assessment_upload_contexts[user_id] = context


def get_tshark_assessment_upload_context(user_id: int) -> dict | None:
    context = _tshark_assessment_upload_contexts.get(user_id)
    return dict(context) if isinstance(context, dict) else None


def get_upload_state(user_id: int) -> str | None:
    return _upload_states.get(user_id)


def clear_upload_state(user_id: int) -> None:
    _upload_states.pop(user_id, None)
    _tshark_assessment_upload_contexts.pop(user_id, None)


def clear_tshark_live_context(proposal_id: str) -> None:
    _tshark_live_contexts.pop(str(proposal_id), None)


def _register_tshark_capture_validation_token(user_id: int, **payload: object) -> str:
    token = secrets.token_urlsafe(9)
    while token in _tshark_capture_validation_tokens:
        token = secrets.token_urlsafe(9)
    _tshark_capture_validation_tokens[token] = {"user_id": int(user_id), **payload}
    return token


def _get_tshark_capture_validation_token(token: str, user_id: int) -> dict | None:
    payload = _tshark_capture_validation_tokens.get(str(token))
    if not isinstance(payload, dict) or payload.get("user_id") != int(user_id):
        return None
    return dict(payload)


def _eligible_metasploit_capture_validations(user_id: int, assessment_id: int | None = None) -> list[object]:
    eligible: list[object] = []
    for proposal in list_metasploit_proposals(user_id=user_id):
        request = getattr(proposal, "request", {}) or {}
        if request.get("module") != "auxiliary/scanner/http/http_version":
            continue
        if request.get("action_type") != "auxiliary_validation":
            continue
        if not _is_capture_validation_selectable(proposal):
            continue
        if assessment_id is not None:
            proposal_assessment = getattr(proposal, "assessment_context", None) or {}
            if _parse_optional_int(proposal_assessment.get("assessment_id")) != assessment_id:
                continue
        eligible.append(proposal)
    return eligible


def _is_capture_validation_selectable(proposal: object) -> bool:
    status = str(getattr(proposal, "status", "") or "").lower()
    if status == "approved":
        return True
    return status == "executed" and str(getattr(proposal, "execution_state", "") or "").lower() == "executed" and getattr(proposal, "approved_at", None) is not None


def _metasploit_capture_status_label(proposal: object) -> str:
    status = str(getattr(proposal, "status", "") or "").lower()
    if status == "executed":
        return "completed"
    if status == "approved":
        return "approved"
    return status or "unknown"


def _prepare_metasploit_proposal_for_capture_execution(validation_proposal: object, *, user_id: int) -> object:
    if str(getattr(validation_proposal, "status", "") or "").lower() == "approved":
        return validation_proposal
    if not _is_capture_validation_selectable(validation_proposal):
        raise MetasploitApprovalError("Metasploit validation proposal is not eligible for capture.")
    source_refs = list(getattr(validation_proposal, "source_evidence_refs", None) or [])
    result_ref = getattr(validation_proposal, "result_artifact_ref", None)
    if result_ref:
        source_refs.append(str(result_ref))
    proposal = propose_metasploit_action(
        user_id,
        dict(getattr(validation_proposal, "request", {}) or {}),
        assessment_context=getattr(validation_proposal, "assessment_context", None),
        source_evidence_refs=source_refs,
        reason=f"TShark capture re-run from completed validation {getattr(validation_proposal, 'id', '')}",
    )
    return approve_metasploit_proposal(proposal.id, user_id=user_id, actor="human")


def _format_options(options: dict) -> str:
    if not options:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in sorted(options.items()))


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
        section_label("mongrel_ai", "Mongrel Verdict"),
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


def store_nuclei_finding(user_id: int, nuclei_findings: list[dict], metadata: dict | None = None) -> dict:
    severity_summary = _summarize_nuclei_severities(nuclei_findings)
    target = _extract_nuclei_target(nuclei_findings)
    risk_level = _score_nuclei_risk(severity_summary)
    finding_metadata = dict(metadata or {})
    return add_finding(
        user_id=user_id,
        finding={
            "source": "nuclei",
            "target": target,
            "target_key": normalize_target_key(target),
            "risk_level": risk_level.lower(),
            "nuclei_findings": nuclei_findings,
            "finding_count": len(nuclei_findings),
            "severity_summary": severity_summary,
            "metadata": finding_metadata,
        },
    )


def build_nuclei_import_success_text(finding: dict, elapsed: str | None = None) -> str:
    nuclei_findings = finding.get("nuclei_findings") or []
    severity_summary = finding.get("severity_summary") or _summarize_nuclei_severities(nuclei_findings)
    risk_level = str(finding.get("risk_level") or _score_nuclei_risk(severity_summary)).upper()
    metadata = finding.get("metadata") or {}
    status = "Partial" if metadata.get("partial") is True else "Complete"
    summary = "\n".join(
        [
            *(["Reason: Execution time limit reached", "Findings collected before timeout: retained", "Scan completed: No", ""] if status == "Partial" else []),
            f"Findings detected: {finding.get('finding_count') or len(nuclei_findings)}",
            "Severity Summary:",
            *_format_nuclei_severity_summary(severity_summary),
            "",
            "Recommended Actions:",
            "- Prioritize critical and high findings first.",
            "- Validate findings manually before remediation.",
            "- Apply configuration or code changes only after confirming the scanner-reported observation.",
            "",
            "Technical Details:",
            *_format_nuclei_technical_details(nuclei_findings),
        ]
    )
    return _truncate_message(
        render_scan_result_card(
            tool_name="Nuclei",
            target=str(finding.get("target") or "unknown"),
            status=status,
            elapsed=elapsed,
            risk=risk_level,
            summary=summary,
            findings=_format_nuclei_top_findings(nuclei_findings),
            assets=_nuclei_observed_assets(nuclei_findings),
        )
    )


def build_tshark_result_text(normalized: dict, result: dict | None = None) -> str:
    result = result or {}
    source_file = normalized.get("source_file") or {}
    truncation = normalized.get("truncation") or {}
    status = "Complete" if normalized.get("success") else "Failed"
    live_capture = _is_tshark_live_result(result)
    offline_upload = not live_capture
    polished_result = offline_upload or _is_tshark_standalone_live_result(result)
    source_label = "Live Capture" if live_capture else _escape(result.get("uploaded_filename") or source_file.get("name") or "uploaded capture")
    lines = [
        section_label("scan", "TShark PCAP Analysis"),
        "",
        "Status:",
        _escape(status),
        "",
        "Source File:",
        source_label,
        "",
        "Packet / Byte Counts:",
        f"Packets: {int(normalized.get('packet_count') or 0)}",
        f"Bytes: {int(normalized.get('byte_count') or 0)}",
        "",
        "Time Range:",
        f"Start: {_format_tshark_timestamp(normalized.get('capture_start'))}",
        f"End: {_format_tshark_timestamp(normalized.get('capture_end'))}",
        *_format_tshark_duration(result, normalized, live_capture=live_capture),
        "",
        *(
            [
                "Capture Summary:",
                *_format_tshark_capture_summary(normalized, result, live_capture=live_capture),
                "",
            ]
            if polished_result
            else []
        ),
        "Protocols:",
        *(
            _format_tshark_protocol_groups(normalized.get("observed_protocols") or [])
            if polished_result
            else _format_tshark_protocols(normalized.get("observed_protocols") or [], sort_by_count=offline_upload)
        ),
        "",
        *(
            [
                "Top Talkers:",
                *_format_tshark_top_talkers(normalized.get("observed_endpoints") or []),
                "",
            ]
            if polished_result
            else []
        ),
        "",
        "Endpoints:",
        *_format_tshark_endpoints(normalized.get("observed_endpoints") or [], sort_by_count=offline_upload),
        "",
        "Conversations:",
        *_format_tshark_conversations(normalized.get("observed_conversations") or [], sort_by_count=offline_upload, compact=polished_result),
        "",
        "DNS Metadata:",
        *_format_tshark_dns(normalized.get("dns_observations") or [], arrow=polished_result),
        "",
        "HTTP Metadata:",
        *_format_tshark_http(normalized.get("http_observations") or []),
        "",
        "TLS Metadata:",
        *_format_tshark_tls(normalized.get("tls_observations") or [], suppress_duplicate_na_sni=polished_result),
        "",
        "Warnings:",
        *_format_tshark_warnings(normalized.get("parser_warnings") or [], result),
        "",
        "Truncation:",
        *_format_tshark_truncation(truncation),
        "",
        "Capture Limitations:",
        "- Packet activity is not automatically malicious.",
        "- A connection is not compromise.",
        "- A DNS query is not exfiltration.",
        "- DNS associations are capture-window observations, not permanent ownership proof.",
        "- TCP conversations do not by themselves prove completed connections, application success, exploitation, or compromise.",
        "- TLS SNI/version metadata does not prove a successful TLS handshake.",
        "- HTTP requests without response codes are not completed HTTP transactions.",
        "- Encrypted traffic limits visibility.",
        "- Capture scope/time limits conclusions.",
        "- Absence from the capture does not prove absence from the network.",
    ]
    return _truncate_tshark_card("\n".join(lines))


def _summarize_nuclei_severities(nuclei_findings: list[dict]) -> dict[str, int]:
    summary = {severity: 0 for severity in NUCLEI_SEVERITIES}
    for finding in nuclei_findings:
        severity = str(finding.get("severity") or "info").lower()
        if severity not in summary:
            severity = "info"
        summary[severity] += 1

    return summary


def _score_nuclei_risk(severity_summary: dict[str, int]) -> str:
    if severity_summary.get("critical", 0) > 0 or severity_summary.get("high", 0) > 0:
        return "high"
    if severity_summary.get("medium", 0) > 0:
        return "medium"
    if severity_summary.get("low", 0) > 0:
        return "low"
    return "info"


def _extract_nuclei_target(nuclei_findings: list[dict]) -> str | None:
    for finding in nuclei_findings:
        target = finding.get("host") or finding.get("matched_at")
        if target:
            return str(target)

    return None


def _sort_nuclei_findings(nuclei_findings: list[dict]) -> list[dict]:
    severity_rank = {severity: index for index, severity in enumerate(NUCLEI_SEVERITIES)}
    return sorted(
        nuclei_findings,
        key=lambda finding: severity_rank.get(str(finding.get("severity") or "info").lower(), severity_rank["info"]),
    )


def _format_nuclei_severity_summary(severity_summary: dict[str, int]) -> list[str]:
    return [f"{severity.title()}: {severity_summary.get(severity, 0)}" for severity in NUCLEI_SEVERITIES]


def _format_nuclei_top_findings(nuclei_findings: list[dict]) -> list[str]:
    if not nuclei_findings:
        return ["- No findings detected."]

    return [
        f"- {finding.get('name') or finding.get('template_id') or 'Unnamed finding'} ({str(finding.get('severity') or 'info').lower()})"
        for finding in _sort_nuclei_findings(nuclei_findings)[:MAX_NUCLEI_FINDINGS_IN_REPORT]
    ]


def _nuclei_observed_assets(nuclei_findings: list[dict]) -> list[str]:
    assets = []
    seen = set()
    for finding in nuclei_findings:
        asset = str(finding.get("host") or finding.get("matched_at") or "").strip()
        if not asset or asset.lower() in seen:
            continue
        seen.add(asset.lower())
        assets.append(asset)
    return assets


def _format_nuclei_technical_details(nuclei_findings: list[dict]) -> list[str]:
    if not nuclei_findings:
        return ["No findings detected."]

    lines = []
    for index, finding in enumerate(_sort_nuclei_findings(nuclei_findings)[:MAX_NUCLEI_FINDINGS_IN_REPORT], start=1):
        lines.extend(
            [
                f"{index}. {finding.get('name') or finding.get('template_id') or 'Unnamed finding'}",
                f"   Severity: {str(finding.get('severity') or 'info').title()}",
                f"   Template: {finding.get('template_id') or 'unknown'}",
                f"   Host: {finding.get('host') or 'unknown'}",
            ]
        )
        tags = finding.get("tags") or []
        if tags:
            lines.append(f"   Tags: {', '.join(str(tag) for tag in tags)}")

        remediation = _truncate_nuclei_remediation(finding.get("remediation"))
        if remediation:
            lines.append(f"   Remediation: {remediation}")

        lines.append("")

    remaining_count = len(nuclei_findings) - MAX_NUCLEI_FINDINGS_IN_REPORT
    if remaining_count > 0:
        lines.append(f"...and {remaining_count} more findings.")

    return lines


def _truncate_nuclei_remediation(remediation: object) -> str | None:
    if not remediation:
        return None

    text = str(remediation).strip()
    if len(text) <= 180:
        return text

    return f"{text[:177]}..."


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


def _get_upload_extension(file_name: str) -> str:
    normalized_file_name = file_name.strip().lower()
    if "." not in normalized_file_name:
        return ""

    return f".{normalized_file_name.rsplit('.', 1)[1]}"


def build_upload_success_keyboard(finding_id: str | None = None, tool: str = "nmap_xml") -> InlineKeyboardMarkup:
    buttons = [[InlineKeyboardButton("Open Findings", callback_data="finding:list")]]
    summary_actions = build_scan_result_actions(finding_id, tool)
    if summary_actions is not None:
        buttons.extend(summary_actions.inline_keyboard)
    buttons.append([InlineKeyboardButton("Explain with Mongrel AI", callback_data=UPLOAD_EXPLAIN_CALLBACK)])
    return InlineKeyboardMarkup(buttons)


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
        clear_finding_analysis_context(user_id)
        set_upload_state(user_id, UPLOAD_STATE_AWAITING_NMAP_XML)

    await update.message.reply_text(
        build_upload_text(),
        reply_markup=build_main_menu_keyboard(),
    )


async def upload_document_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None or update.message.document is None:
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is None:
        return

    upload_state = get_upload_state(user_id)
    if upload_state == UPLOAD_STATE_AWAITING_TSHARK_PCAP:
        await _handle_tshark_document_upload(update, user_id)
        return

    if upload_state != UPLOAD_STATE_AWAITING_NMAP_XML:
        return

    document = update.message.document
    file_name = str(document.file_name or "")
    extension = _get_upload_extension(file_name)
    logger.info("Upload detected: extension=%s", extension or "<none>")
    if extension not in {".xml", ".json", ".jsonl"}:
        await update.message.reply_text("Please upload an Nmap XML or Nuclei JSON/JSONL file.")
        return

    if document.file_size is not None and document.file_size > MAX_UPLOAD_SIZE_BYTES:
        await update.message.reply_text("File exceeds maximum size.")
        return

    telegram_file = await document.get_file()
    file_bytes = await telegram_file.download_as_bytearray()
    try:
        file_text = bytes(file_bytes).decode("utf-8")
    except UnicodeDecodeError:
        if extension == ".xml":
            await update.message.reply_text("Unable to parse Nmap XML file.")
        else:
            await update.message.reply_text("Unable to parse Nuclei results file.")
        return

    if extension in {".json", ".jsonl"}:
        logger.info("Routing to nuclei parser")
        try:
            nuclei_findings = parse_nuclei_results(file_text)
        except NucleiParserError:
            await update.message.reply_text("Unable to parse Nuclei results file.")
            return

        finding = store_nuclei_finding(user_id=user_id, nuclei_findings=nuclei_findings)
        clear_upload_state(user_id)
        await update.message.reply_text(
            build_nuclei_import_success_text(finding),
            reply_markup=build_scan_result_actions(finding.get("id"), "nuclei"),
        )
        return

    logger.info("Routing to nmap parser")
    try:
        parsed_output = parse_nmap_xml(file_text)
    except ValueError:
        await update.message.reply_text("Unable to parse Nmap XML file.")
        return

    finding = store_parsed_nmap_finding(user_id=user_id, parsed_output=parsed_output, source="nmap_xml")
    store_latest_upload_scan_summary(user_id, finding)
    clear_upload_state(user_id)
    await update.message.reply_text(
        build_nmap_xml_import_success_text(finding),
        reply_markup=build_upload_success_keyboard(finding.get("id"), "nmap_xml"),
    )


async def _handle_tshark_document_upload(update: Update, user_id: int) -> None:
    if update.message is None or update.message.document is None:
        return

    document = update.message.document
    assessment_context = get_tshark_assessment_upload_context(user_id)
    if assessment_context and int(assessment_context.get("user_id") or user_id) != user_id:
        clear_upload_state(user_id)
        await update.message.reply_text("TShark assessment upload is not authorized for this Telegram user.")
        return
    if assessment_context and get_assessment(int(assessment_context.get("assessment_id") or 0)) is None:
        clear_upload_state(user_id)
        await update.message.reply_text("TShark assessment upload context is no longer valid.")
        return

    file_name = str(document.file_name or "").strip()
    if not file_name:
        clear_upload_state(user_id)
        await update.message.reply_text("TShark upload requires a .pcap or .pcapng filename.")
        return

    extension = _get_upload_extension(file_name)
    if extension not in {".pcap", ".pcapng"}:
        clear_upload_state(user_id)
        await update.message.reply_text("Please upload a .pcap or .pcapng file for TShark analysis.")
        return

    if document.file_size is not None and document.file_size > MAX_TSHARK_UPLOAD_SIZE_BYTES:
        clear_upload_state(user_id)
        await update.message.reply_text("TShark capture file exceeds maximum size.")
        return

    readiness = await asyncio.to_thread(check_tshark_readiness, run_version_check=False)
    if readiness.get("ready") is not True:
        clear_upload_state(user_id)
        await update.message.reply_text(_escape(str(readiness.get("error") or "TShark is not ready.")))
        return

    temp_path: Path | None = None
    fallback_status = "failed"
    try:
        telegram_file = await document.get_file()
        file_bytes = bytes(await telegram_file.download_as_bytearray())
        if not file_bytes:
            clear_upload_state(user_id)
            await update.message.reply_text("TShark capture file is empty.")
            return
        if len(file_bytes) > MAX_TSHARK_UPLOAD_SIZE_BYTES:
            clear_upload_state(user_id)
            await update.message.reply_text("TShark capture file exceeds maximum size.")
            return

        handle = tempfile.NamedTemporaryFile(prefix="mongrel-tshark-", suffix=extension, delete=False)
        try:
            temp_path = Path(handle.name)
            handle.write(file_bytes)
        finally:
            handle.close()

        if assessment_context:
            _start_tshark_assessment_scan(assessment_context)
        result = await asyncio.to_thread(run_tshark_offline_analysis, temp_path)
        normalized = await asyncio.to_thread(normalize_tshark_result, result)
        if assessment_context:
            await asyncio.to_thread(_persist_tshark_assessment_evidence, assessment_context, result, normalized)
        display_result = {**result, "uploaded_filename": _safe_uploaded_filename(file_name)}
        await update.message.reply_text(build_tshark_result_text(normalized, display_result))
        await _send_tshark_ai_assessment(update.message, normalized=normalized, tool_mode=assessment_context is None)
        if assessment_context:
            await _send_tshark_assessment_dashboard(update.message, int(assessment_context["assessment_id"]))
    except asyncio.CancelledError:
        fallback_status = "cancelled"
        raise
    finally:
        _finalize_tshark_assessment_scan_if_running(assessment_context, status=fallback_status)
        clear_upload_state(user_id)
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Unable to remove temporary TShark upload file: %s", temp_path)


def _persist_tshark_assessment_evidence(
    assessment_context: dict,
    result: dict,
    normalized: dict,
    *,
    ingest_map: bool = True,
) -> dict:
    assessment_id = int(assessment_context["assessment_id"])
    status = scan_status_from_result(result)
    scan_id = assessment_context.get("assessment_scan_id")
    if scan_id is not None:
        scan = finalize_assessment_scan(
            assessment_id=assessment_id,
            scan_id=int(scan_id),
            status=status,
            elapsed_seconds=_parse_elapsed_seconds(result.get("elapsed_seconds")),
            raw_reference="assessment_artifact:tshark_normalized_evidence",
        )
    else:
        scan = record_assessment_scan(
            assessment_id=assessment_id,
            tool="tshark",
            status=status,
            elapsed_seconds=_parse_elapsed_seconds(result.get("elapsed_seconds")),
            raw_reference="assessment_artifact:tshark_normalized_evidence",
        )
    add_assessment_artifact(
        assessment_id=assessment_id,
        scan_id=scan["id"],
        artifact_type="tshark_normalized_evidence",
        title="TShark normalized PCAP evidence",
        content=json.dumps(_bounded_tshark_artifact_payload(normalized), sort_keys=True),
        file_path=None,
    )
    if ingest_map:
        _ingest_tshark_assessment_map(assessment_context, scan)
    return scan


def _ingest_tshark_assessment_map(assessment_context: dict | None, scan: dict | None) -> None:
    if not isinstance(assessment_context, dict) or not scan:
        return
    user_id = _parse_optional_int(assessment_context.get("user_id"))
    assessment_id = _parse_optional_int(assessment_context.get("assessment_id"))
    scan_id = _parse_optional_int(scan.get("id"))
    if user_id is None or assessment_id is None or scan_id is None:
        return
    try:
        ingest_assessment_scan(user_id=user_id, assessment_id=assessment_id, scan_id=scan_id)
    except (AssessmentMapIngestionError, AssessmentMapScopeError, ValueError) as exc:
        logger.warning(
            "Assessment map ingestion skipped for tshark scan_id=%s assessment_id=%s: %s",
            scan_id,
            assessment_id,
            exc,
        )


def _start_tshark_assessment_scan(assessment_context: dict) -> None:
    if assessment_context.get("assessment_scan_id") is not None:
        return
    scan = start_assessment_scan(
        assessment_id=int(assessment_context["assessment_id"]),
        target_id=_parse_optional_int(assessment_context.get("target_id")),
        tool="tshark",
    )
    assessment_context["assessment_scan_id"] = int(scan["id"])


def _finalize_tshark_assessment_scan_if_running(
    assessment_context: dict | None,
    *,
    status: str = "failed",
) -> dict | None:
    if not isinstance(assessment_context, dict):
        return None
    assessment_id = _parse_optional_int(assessment_context.get("assessment_id"))
    scan_id = _parse_optional_int(assessment_context.get("assessment_scan_id"))
    if assessment_id is None or scan_id is None:
        return None
    return finalize_assessment_scan(assessment_id=assessment_id, scan_id=scan_id, status=status)


def _persist_tshark_capture_validation_provenance(assessment_id: int, result: dict, *, scan_id: int | None = None) -> str | None:
    provenance = result.get("provenance") if isinstance(result, dict) else {}
    if not isinstance(provenance, dict) or not provenance:
        return None
    artifact = add_assessment_artifact(
        assessment_id=int(assessment_id),
        scan_id=scan_id,
        artifact_type="tshark_validation_capture_provenance",
        title="TShark capture during validation provenance",
        content=json.dumps(
            {
                "source": "tshark_capture_during_validation",
                "user_id": provenance.get("user_id"),
                "assessment_id": int(assessment_id),
                "validation_proposal_id": provenance.get("validation_proposal_id"),
                "capture_proposal_id": provenance.get("capture_proposal_id"),
                "target": provenance.get("target"),
                "module": provenance.get("module"),
                "action": provenance.get("action"),
                "port": provenance.get("port"),
                "interface": provenance.get("interface"),
                "capture_started_at": provenance.get("capture_started_at"),
                "capture_ended_at": provenance.get("capture_ended_at"),
                "validation_started_at": provenance.get("validation_started_at"),
                "validation_ended_at": provenance.get("validation_ended_at"),
                "pcap_artifact_path": provenance.get("pcap_artifact_path"),
                "post_validation_tail_seconds": result.get("post_validation_tail_seconds"),
            },
            sort_keys=True,
        ),
        file_path=None,
    )
    return f"assessment_artifact:{artifact.get('id')}"


def _persist_tshark_metasploit_correlation(
    user_id: int,
    assessment_id: int | None,
    validation_proposal_id: str,
    capture_provenance_ref: str | None,
    result: dict,
    normalized_tshark: dict,
    scan_id: int | None = None,
) -> dict:
    logger.info(
        "Start TShark/Metasploit correlation persistence: user_id=%s assessment_id=%s validation_proposal_id=%s capture_provenance_ref=%s",
        user_id,
        assessment_id,
        validation_proposal_id,
        capture_provenance_ref,
    )
    provenance = result.get("provenance") if isinstance(result, dict) else {}
    if not isinstance(provenance, dict):
        provenance = {}
    validation_result = result.get("validation_result") if isinstance(result, dict) else {}
    if not isinstance(validation_result, dict):
        validation_result = {"success": False, "error": "Metasploit validation result was not available.", "error_type": "missing_validation_result"}
    normalized_metasploit = parse_metasploit_validation_result(validation_result)
    validation_ref = "current_run.validation_result"
    if assessment_id is not None:
        validation_ref = _persist_metasploit_capture_validation_artifact(
            assessment_id, validation_result, normalized_metasploit, validation_proposal_id, scan_id=scan_id
        )
        record_metasploit_result_reference(validation_proposal_id, validation_ref)
    correlation = build_tshark_metasploit_correlation_record(
        user_id=user_id,
        assessment_id=int(assessment_id or 0),
        validation_result_id=validation_ref,
        capture_provenance_id=capture_provenance_ref,
        provenance=provenance,
        metasploit_evidence=normalized_metasploit,
        tshark_evidence=normalized_tshark,
    )
    correlation_artifact_ref = "current_run.correlation_record"
    if assessment_id is not None:
        correlation_artifact = add_assessment_artifact(
            assessment_id=int(assessment_id),
            scan_id=scan_id,
            artifact_type="tshark_metasploit_correlation_record",
            title="TShark and Metasploit correlation record",
            content=json.dumps(correlation, sort_keys=True),
            file_path=None,
        )
        correlation_artifact_ref = f"assessment_artifact:{correlation_artifact.get('id')}"
    logger.info(
        "TShark/Metasploit correlation record created: artifact_ref=%s validation_proposal_id=%s capture_provenance_ref=%s outcome=%s",
        correlation_artifact_ref,
        validation_proposal_id,
        capture_provenance_ref,
        correlation.get("correlation_outcome"),
    )
    logger.info("TShark/Metasploit correlated AI generation invoked: correlation_artifact_ref=%s", correlation_artifact_ref)
    ai_lines = generate_tshark_metasploit_correlated_assessment(correlation)
    ai_text = "\n".join(ai_lines)
    logger.info(
        "TShark/Metasploit correlated AI generation completed: correlation_artifact_ref=%s text_length=%s",
        correlation_artifact_ref,
        len(ai_text),
    )
    if assessment_id is not None:
        add_assessment_artifact(
            assessment_id=int(assessment_id),
            artifact_type="tshark_metasploit_correlated_ai_assessment",
            title="Correlated TShark and Metasploit AI assessment",
            content=ai_text,
            file_path=correlation_artifact_ref,
        )
    logger.info(
        "TShark/Metasploit correlation helper returning: artifact_ref=%s has_record=%s ai_line_count=%s",
        correlation_artifact_ref,
        bool(correlation),
        len(ai_lines),
    )
    return {
        "correlation": correlation,
        "ai_lines": ai_lines,
        "correlation_artifact_ref": correlation_artifact_ref,
    }


def build_tshark_metasploit_correlated_assessment_text(ai_lines: list[str]) -> str:
    body = "\n".join(str(line) for line in ai_lines).strip()
    return "\n".join(
        [
            f"{icon_label('mongrel_ai', 'TShark + Metasploit Correlated Assessment')}",
            "",
            body or "Correlated assessment was unavailable.",
        ]
    )


async def _send_tshark_metasploit_correlated_assessment(
    message: object,
    correlation_result: dict,
    assessment_id: int | None,
) -> None:
    correlated_message = build_tshark_metasploit_correlated_assessment_text(
        list(correlation_result.get("ai_lines") or [])
    )
    logger.info(
        "About to send Telegram message: type=tshark_metasploit_correlated_assessment correlation_artifact_ref=%s text_length=%s",
        correlation_result.get("correlation_artifact_ref"),
        len(correlated_message),
    )
    chunks = split_report_text(correlated_message)
    for index, chunk in enumerate(chunks):
        markup = build_tool_mode_post_scan_keyboard("tshark") if assessment_id is None and index == len(chunks) - 1 else None
        await message.reply_text(chunk, **({"reply_markup": markup} if markup else {}))
    logger.info(
        "Telegram send completed: type=tshark_metasploit_correlated_assessment correlation_artifact_ref=%s",
        correlation_result.get("correlation_artifact_ref"),
    )
    if assessment_id is not None:
        await _send_tshark_assessment_dashboard(message, assessment_id)
        logger.info("Capture During Validation dashboard sent: assessment_id=%s", assessment_id)


async def _send_tshark_ai_assessment(message: object, *, normalized: dict, tool_mode: bool) -> None:
    try:
        assessment_lines = await asyncio.to_thread(generate_tshark_ai_assessment, normalized)
        if not assessment_lines or assessment_lines == TSHARK_AI_FALLBACK_LINES:
            return
        assessment_text = render_ai_summary_card(assessment_lines, title="TShark AI Assessment")
        chunks = split_report_text(assessment_text)
        for index, chunk in enumerate(chunks):
            markup = build_tool_mode_post_scan_keyboard("tshark") if tool_mode and index == len(chunks) - 1 else None
            await message.reply_text(chunk, **({"reply_markup": markup} if markup else {}))
    except Exception:
        logger.info("TShark specialist AI unavailable; deterministic result remains authoritative.", exc_info=True)


def _persist_metasploit_capture_validation_artifact(
    assessment_id: int,
    result: dict,
    normalized: dict,
    proposal_id: str,
    *,
    scan_id: int | None = None,
) -> str:
    artifact = add_assessment_artifact(
        assessment_id=int(assessment_id),
        scan_id=scan_id,
        artifact_type="metasploit_validation_normalized_evidence",
        title=f"Metasploit validation evidence {normalized.get('target') or result.get('target') or 'target'}",
        content=json.dumps(
            {
                "source": "metasploit",
                "proposal_id": str(proposal_id),
                "module": normalized.get("module"),
                "action_type": normalized.get("action_type"),
                "target": normalized.get("target"),
                "port": normalized.get("port"),
                "validation_state": normalized.get("validation_state"),
                "summary": normalized.get("summary"),
                "evidence_confidence": normalized.get("evidence_confidence"),
                "limitations": normalized.get("limitations") or [],
                "raw_evidence_excerpt": normalized.get("raw_evidence_excerpt"),
            },
            sort_keys=True,
        ),
        file_path=None,
    )
    return f"assessment_artifact:{artifact.get('id')}"


def _bounded_tshark_artifact_payload(normalized: dict) -> dict:
    return {
        "source": "tshark",
        "execution_status": normalized.get("execution_status"),
        "success": normalized.get("success"),
        "source_file": normalized.get("source_file"),
        "packet_count": normalized.get("packet_count"),
        "byte_count": normalized.get("byte_count"),
        "capture_start": normalized.get("capture_start"),
        "capture_end": normalized.get("capture_end"),
        "observed_protocols": (normalized.get("observed_protocols") or [])[:20],
        "observed_endpoints": (normalized.get("observed_endpoints") or [])[:50],
        "observed_conversations": (normalized.get("observed_conversations") or [])[:50],
        "dns_observations": (normalized.get("dns_observations") or [])[:50],
        "http_observations": (normalized.get("http_observations") or [])[:50],
        "tls_observations": (normalized.get("tls_observations") or [])[:50],
        "parser_warnings": (normalized.get("parser_warnings") or [])[:20],
        "truncation": normalized.get("truncation") or {},
        "evidence_limitations": normalized.get("evidence_limitations") or [],
        "error_type": normalized.get("error_type"),
    }


async def _send_tshark_assessment_dashboard(message: object, assessment_id: int) -> None:
    assessment = get_assessment(assessment_id)
    if assessment is None:
        return
    from app.bot.handlers.assessment import build_assessment_dashboard_keyboard, build_assessment_dashboard_text

    await message.reply_text(
        build_assessment_dashboard_text(assessment, list_assessment_targets(assessment_id), list_assessment_scans(assessment_id)),
        reply_markup=build_assessment_dashboard_keyboard(assessment_id),
    )


def _parse_elapsed_seconds(value: object) -> int | None:
    try:
        return max(0, int(float(str(value).strip())))
    except (TypeError, ValueError):
        return None


def build_tshark_live_interface_text(interfaces: list[str]) -> str:
    rendered = "\n".join(f"- {_escape(interface)}" for interface in interfaces[:12]) or "- none configured"
    return (
        f"{section_label('scan', 'TShark Live Capture')}\n\n"
        "Choose an allowlisted interface for bounded live capture.\n\n"
        "Allowlisted interfaces:\n"
        f"{rendered}\n\n"
        "No arbitrary capture filters or raw TShark commands are accepted."
    )


def _build_default_live_request(interface: str) -> dict:
    settings = get_settings()
    return build_tshark_capture_request(
        interface=interface,
        duration_seconds=int(settings.tshark_live_max_duration_seconds),
        packet_count=int(settings.tshark_live_max_packet_count),
        file_size_kb=int(settings.tshark_live_max_file_size_kb),
    )


def _normalized_tshark_live_evidence(result: dict) -> dict:
    normalized = result.get("normalized_evidence") if isinstance(result, dict) else None
    if isinstance(normalized, dict) and normalized:
        return normalized
    error = str((result or {}).get("error") or "TShark live capture did not produce normalized evidence.")
    return {
        "source": "tshark",
        "execution_status": "failed",
        "success": False,
        "source_file": {"name": "live capture", "extension": ".pcapng", "size_bytes": 0},
        "packet_count": 0,
        "byte_count": 0,
        "capture_start": None,
        "capture_end": None,
        "observed_protocols": [],
        "observed_endpoints": [],
        "observed_conversations": [],
        "dns_observations": [],
        "http_observations": [],
        "tls_observations": [],
        "parser_warnings": [_escape(error)],
        "truncation": {},
        "evidence_limitations": [
            "Packet activity is not automatically malicious.",
            "A connection is not compromise.",
            "A DNS query is not exfiltration.",
            "Encrypted traffic limits visibility.",
            "Capture scope/time limits conclusions.",
            "Absence from the capture does not prove absence from the network.",
        ],
        "error_type": (result or {}).get("error_type"),
    }


def _parse_optional_int(value: object) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _encode_callback_value(value: str) -> str:
    encoded = base64.urlsafe_b64encode(str(value).encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _decode_callback_value(value: str) -> str:
    padded = str(value or "") + ("=" * (-len(str(value or "")) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")


async def tshark_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    fallback_status = "failed"
    try:
        await _tshark_callback_handler_impl(update, context)
    except asyncio.CancelledError:
        fallback_status = "cancelled"
        raise
    finally:
        user_data = getattr(context, "user_data", None)
        assessment_context = user_data.pop(TSHARK_RUNNING_SCAN_GUARD_KEY, None) if isinstance(user_data, dict) else None
        _finalize_tshark_assessment_scan_if_running(assessment_context, status=fallback_status)


async def _tshark_callback_handler_impl(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return

    await query.answer()
    data = str(query.data or "")
    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is None:
        await query.edit_message_text("Unable to identify Telegram user.")
        return

    parts = data.split(":")
    action = parts[1] if len(parts) > 1 else ""
    if action == "choose":
        assessment_id = _parse_optional_int(parts[2] if len(parts) > 2 else None)
        await query.edit_message_text(build_tshark_mode_text(), reply_markup=build_tshark_mode_keyboard(assessment_id))
        return

    if action == "upload":
        assessment_id = _parse_optional_int(parts[2] if len(parts) > 2 else None)
        clear_upload_state(user_id)
        set_upload_state(user_id, UPLOAD_STATE_AWAITING_TSHARK_PCAP)
        prompt = build_tshark_upload_prompt() + (
            "\n\nThis TShark assessment action requires an uploaded .pcap or .pcapng artifact. The assessment target is not used as a capture file."
            if assessment_id is not None
            else ""
        )
        if assessment_id is not None:
            set_tshark_assessment_upload_context(user_id, {"assessment_id": assessment_id, "user_id": user_id})
            if query.message is not None:
                await query.message.reply_text(prompt, reply_markup=build_tshark_upload_controls())
            await query.edit_message_text("TShark PCAP upload prompt sent. The assessment dashboard remains available above.")
        else:
            await query.edit_message_text(prompt)
        return

    if action == "capture":
        assessment_id = _parse_optional_int(parts[2] if len(parts) > 2 else None)
        eligible = _eligible_metasploit_capture_validations(user_id, assessment_id)
        await _show_tshark_capture_validation_menu(query, user_id, eligible, assessment_id)
        return

    if action == "cv":
        token_payload = _get_tshark_capture_validation_token(parts[2] if len(parts) > 2 else "", user_id)
        if token_payload is None:
            await query.edit_message_text("TShark capture validation selection was not found or has expired.")
            return
        validation_proposal = get_metasploit_proposal(str(token_payload.get("metasploit_proposal_id") or ""))
        if validation_proposal is None or validation_proposal.user_id != user_id:
            await query.edit_message_text("Metasploit validation proposal is not available for this user.")
            return
        readiness = await asyncio.to_thread(check_tshark_live_readiness)
        if readiness.get("ready") is not True:
            await query.edit_message_text(_escape(str(readiness.get("error") or "TShark live capture is not ready.")))
            return
        interfaces = [str(interface) for interface in readiness.get("allowed_interfaces") or []]
        await query.edit_message_text(
            build_tshark_capture_interface_text(validation_proposal, interfaces),
            reply_markup=build_tshark_capture_interface_keyboard(token_payload, interfaces),
        )
        return

    if action == "cvi":
        token_payload = _get_tshark_capture_validation_token(parts[2] if len(parts) > 2 else "", user_id)
        if token_payload is None:
            await query.edit_message_text("TShark capture validation interface selection was not found or has expired.")
            return
        validation_proposal = get_metasploit_proposal(str(token_payload.get("metasploit_proposal_id") or ""))
        if validation_proposal is None or validation_proposal.user_id != user_id:
            await query.edit_message_text("Metasploit validation proposal is not available for this user.")
            return
        if not _is_capture_validation_selectable(validation_proposal):
            await query.edit_message_text("Metasploit validation proposal is not eligible for capture.")
            return
        if str(validation_proposal.fingerprint) != str(token_payload.get("validation_fingerprint") or ""):
            await query.edit_message_text("Metasploit validation details changed.")
            return
        try:
            request = _build_default_live_request(str(token_payload.get("interface") or ""))
            proposal = propose_tshark_capture(user_id, request)
        except (ValueError, TSharkApprovalError) as exc:
            await query.edit_message_text(_escape(str(exc)))
            return
        assessment_id = _parse_optional_int(token_payload.get("assessment_id"))
        _tshark_live_contexts[proposal.id] = {
            "request": request,
            "user_id": user_id,
            "assessment_id": assessment_id,
            "mode": "capture_validation",
            "metasploit_proposal_id": validation_proposal.id,
            "metasploit_proposal_status": validation_proposal.status,
            "metasploit_request": dict(validation_proposal.request),
            "validation_fingerprint": validation_proposal.fingerprint,
            "post_validation_tail_seconds": DEFAULT_POST_VALIDATION_TAIL_SECONDS,
        }
        await query.edit_message_text(
            build_tshark_capture_review_text(
                proposal,
                validation_proposal,
                assessment_id=assessment_id,
                post_tail_seconds=DEFAULT_POST_VALIDATION_TAIL_SECONDS,
            ),
            reply_markup=build_tshark_capture_review_keyboard(proposal.id),
        )
        return

    if action == "live":
        assessment_id = _parse_optional_int(parts[2] if len(parts) > 2 else None)
        readiness = await asyncio.to_thread(check_tshark_live_readiness)
        if readiness.get("ready") is not True:
            await query.edit_message_text(_escape(str(readiness.get("error") or "TShark live capture is not ready.")))
            return
        interfaces = [str(interface) for interface in readiness.get("allowed_interfaces") or []]
        await query.edit_message_text(
            build_tshark_live_interface_text(interfaces),
            reply_markup=build_tshark_interface_keyboard(interfaces, assessment_id),
        )
        return

    if action in {"iface", "iface_assessment"}:
        assessment_id = _parse_optional_int(parts[2] if action == "iface_assessment" and len(parts) > 3 else None)
        encoded_interface = parts[3] if action == "iface_assessment" and len(parts) > 3 else (parts[2] if len(parts) > 2 else "")
        try:
            interface = _decode_callback_value(encoded_interface)
            request = _build_default_live_request(interface)
            proposal = propose_tshark_capture(user_id, request)
        except (ValueError, TSharkApprovalError) as exc:
            await query.edit_message_text(_escape(str(exc)))
            return
        _tshark_live_contexts[proposal.id] = {"request": request, "user_id": user_id, "assessment_id": assessment_id}
        await query.edit_message_text(
            build_tshark_live_proposal_text(proposal),
            reply_markup=build_tshark_live_approval_keyboard(proposal.id),
        )
        return

    if action == "details":
        proposal_id = parts[2] if len(parts) > 2 else ""
        proposal = get_tshark_capture_proposal(proposal_id)
        if proposal is None:
            clear_tshark_live_context(proposal_id)
            await query.edit_message_text("TShark live capture proposal was not found or has expired.")
            return
        if proposal.user_id != user_id:
            await query.edit_message_text("TShark live capture proposal is not available for this user.")
            return
        live_context = _tshark_live_contexts.get(proposal_id) or {}
        if live_context.get("mode") == "capture_validation":
            validation_proposal = get_metasploit_proposal(str(live_context.get("metasploit_proposal_id") or ""))
            if validation_proposal is None:
                await query.edit_message_text("Metasploit validation proposal is not available for this user.")
                return
            await query.edit_message_text(
                build_tshark_capture_review_text(
                    proposal,
                    validation_proposal,
                    assessment_id=_parse_optional_int(live_context.get("assessment_id")),
                    post_tail_seconds=int(live_context.get("post_validation_tail_seconds") or DEFAULT_POST_VALIDATION_TAIL_SECONDS),
                    details=True,
                ),
                reply_markup=build_tshark_capture_review_keyboard(proposal.id),
            )
            return
        await query.edit_message_text(
            build_tshark_live_proposal_text(proposal, details=True),
            reply_markup=build_tshark_live_approval_keyboard(proposal.id),
        )
        return

    if action == "reject":
        proposal_id = parts[2] if len(parts) > 2 else ""
        try:
            reject_tshark_capture(proposal_id, user_id=user_id)
        except TSharkApprovalError as exc:
            await query.edit_message_text(_escape(str(exc)))
            return
        clear_tshark_live_context(proposal_id)
        clear_upload_state(user_id)
        await query.edit_message_text("TShark live capture proposal rejected. No capture was run.")
        return

    if action == "approve":
        proposal_id = parts[2] if len(parts) > 2 else ""
        live_context = _tshark_live_contexts.get(proposal_id) or {}
        request = dict(live_context.get("request") or {})
        try:
            approve_tshark_capture(proposal_id, user_id=user_id)
        except TSharkApprovalError as exc:
            clear_tshark_live_context(proposal_id)
            clear_upload_state(user_id)
            await query.edit_message_text(_escape(str(exc)))
            return
        if not request:
            clear_tshark_live_context(proposal_id)
            clear_upload_state(user_id)
            await query.edit_message_text("TShark live capture context is no longer available.")
            return

        if live_context.get("mode") == "capture_validation":
            validation_proposal_id = str(live_context.get("metasploit_proposal_id") or "")
            validation_proposal = get_metasploit_proposal(validation_proposal_id)
            metasploit_request = dict(live_context.get("metasploit_request") or {})
            if (
                validation_proposal is None
                or validation_proposal.user_id != user_id
                or not _is_capture_validation_selectable(validation_proposal)
                or validation_proposal.fingerprint != str(live_context.get("validation_fingerprint") or "")
            ):
                clear_tshark_live_context(proposal_id)
                clear_upload_state(user_id)
                await query.edit_message_text("Metasploit validation proposal is no longer available or has changed.")
                return
            try:
                executable_validation = _prepare_metasploit_proposal_for_capture_execution(validation_proposal, user_id=user_id)
            except (MetasploitApprovalError, ValueError) as exc:
                clear_tshark_live_context(proposal_id)
                clear_upload_state(user_id)
                await query.edit_message_text(_escape(str(exc)))
                return
            validation_proposal_id = str(executable_validation.id)
            metasploit_request = dict(executable_validation.request)
            if _parse_optional_int(live_context.get("assessment_id")) is not None:
                _start_tshark_assessment_scan(live_context)
                context.user_data[TSHARK_RUNNING_SCAN_GUARD_KEY] = live_context
            await query.edit_message_text("TShark capture approved. Running bounded capture during validation...")
            result = await asyncio.to_thread(
                run_tshark_capture_during_validation,
                user_id=user_id,
                capture_proposal_id=proposal_id,
                capture_request=request,
                metasploit_proposal_id=validation_proposal_id,
                metasploit_request=metasploit_request,
                post_validation_tail_seconds=int(live_context.get("post_validation_tail_seconds") or DEFAULT_POST_VALIDATION_TAIL_SECONDS),
            )
            normalized = _normalized_tshark_live_evidence(result)
            assessment_id = _parse_optional_int(live_context.get("assessment_id"))
            logger.info(
                "Entered Capture During Validation post-capture branch: user_id=%s assessment_id=%s validation_proposal_id=%s capture_proposal_id=%s success=%s packet_count=%s",
                user_id,
                assessment_id,
                validation_proposal_id,
                proposal_id,
                result.get("success") if isinstance(result, dict) else None,
                normalized.get("packet_count") if isinstance(normalized, dict) else None,
            )
            provenance_ref = None
            tshark_scan = None
            if assessment_id is not None:
                tshark_scan = _persist_tshark_assessment_evidence(
                    live_context,
                    result,
                    normalized,
                    ingest_map=False,
                )
                provenance_ref = _persist_tshark_capture_validation_provenance(
                    assessment_id, result, scan_id=int(tshark_scan["id"])
                )
            correlation_result = await asyncio.to_thread(
                _persist_tshark_metasploit_correlation,
                user_id,
                assessment_id,
                validation_proposal_id,
                provenance_ref,
                result,
                normalized,
                int(tshark_scan["id"]) if isinstance(tshark_scan, dict) else None,
            )
            if assessment_id is not None and isinstance(tshark_scan, dict):
                _ingest_tshark_assessment_map(live_context, tshark_scan)
            logger.info(
                "Capture During Validation caller received correlation result: has_record=%s has_ai_lines=%s ai_line_count=%s artifact_ref=%s",
                isinstance(correlation_result, dict) and bool(correlation_result.get("correlation")),
                isinstance(correlation_result, dict) and bool(correlation_result.get("ai_lines")),
                len(correlation_result.get("ai_lines") or []) if isinstance(correlation_result, dict) else 0,
                correlation_result.get("correlation_artifact_ref") if isinstance(correlation_result, dict) else None,
            )
            if query.message is not None:
                await query.message.reply_text(build_tshark_result_text(normalized, result.get("offline_result") or result))
                if isinstance(correlation_result, dict):
                    await _send_tshark_metasploit_correlated_assessment(
                        query.message, correlation_result, assessment_id
                    )
            clear_tshark_live_context(proposal_id)
            clear_upload_state(user_id)
            logger.info("Capture During Validation handler exits normally: user_id=%s capture_proposal_id=%s", user_id, proposal_id)
            return

        if _parse_optional_int(live_context.get("assessment_id")) is not None:
            _start_tshark_assessment_scan(live_context)
            context.user_data[TSHARK_RUNNING_SCAN_GUARD_KEY] = live_context
        await query.edit_message_text("TShark live capture approved. Running bounded capture...")
        result = await asyncio.to_thread(run_tshark_live_capture, user_id=user_id, proposal_id=proposal_id, request=request)
        normalized = _normalized_tshark_live_evidence(result)
        assessment_id = _parse_optional_int(live_context.get("assessment_id"))
        if assessment_id is not None:
            _persist_tshark_assessment_evidence(live_context, result, normalized)
        if query.message is not None:
            await query.message.reply_text(build_tshark_result_text(normalized, result.get("offline_result") or result))
            await _send_tshark_ai_assessment(query.message, normalized=normalized, tool_mode=assessment_id is None)
            if assessment_id is not None:
                await _send_tshark_assessment_dashboard(query.message, assessment_id)
        clear_tshark_live_context(proposal_id)
        clear_upload_state(user_id)
        return


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
        ai_response = await asyncio.to_thread(ask_ai, prompt, path="upload_explanation")
        logger.info("Upload findings AI explanation completed for user_id=%s", user_id)
    except Exception:
        logger.exception("Upload findings AI explanation failed for user_id=%s", user_id)
        await query.message.reply_text("AI explanation failed. Check bot logs.")
        return

    await query.message.reply_text(ai_response)


def _format_tshark_protocols(protocols: list[dict], *, sort_by_count: bool = False) -> list[str]:
    if not protocols:
        return ["- none observed"]
    protocols = [item for item in protocols if not _is_redundant_tshark_protocol(item.get("protocol"))]
    if not protocols:
        return ["- none observed"]
    if sort_by_count:
        ordered = sorted(enumerate(protocols), key=lambda indexed: (-int(indexed[1].get("packet_count") or 0), indexed[0]))
    else:
        ordered = sorted(enumerate(protocols), key=lambda indexed: (_tshark_protocol_rank(indexed[1].get("protocol")), indexed[0]))
    return [f"- {_escape(item.get('protocol'))}: {int(item.get('packet_count') or 0)}" for _, item in ordered[:8]]


def _format_tshark_protocol_groups(protocols: list[dict]) -> list[str]:
    if not protocols:
        return ["- none observed"]
    ordered = sorted(
        enumerate(item for item in protocols if not _is_redundant_tshark_protocol(item.get("protocol"))),
        key=lambda indexed: (-int(indexed[1].get("packet_count") or 0), indexed[0]),
    )
    groups = {
        "Application": [],
        "Transport": [],
        "Network": [],
        "Link": [],
    }
    for _, item in ordered:
        groups[_tshark_protocol_group(item.get("protocol"))].append(f"- {_escape(item.get('protocol'))}: {int(item.get('packet_count') or 0)}")
    lines: list[str] = []
    for group_name in ("Application", "Transport", "Network", "Link"):
        lines.append(f"{group_name}:")
        lines.extend(groups[group_name][:5] or ["- none observed"])
    return lines


def _format_tshark_capture_summary(normalized: dict, result: dict, *, live_capture: bool) -> list[str]:
    duration = _format_tshark_duration(result, normalized, live_capture=live_capture)
    return [
        duration[0] if duration else "Duration: not available",
        f"Packet Count: {int(normalized.get('packet_count') or 0)}",
        f"Main Protocols: {_format_tshark_main_protocols(normalized.get('observed_protocols') or [])}",
        f"Top Talker: {_format_tshark_top_talker(normalized.get('observed_endpoints') or [])}",
    ]


def _format_tshark_main_protocols(protocols: list[dict]) -> str:
    ordered = sorted(
        enumerate(item for item in protocols if not _is_redundant_tshark_protocol(item.get("protocol"))),
        key=lambda indexed: (-int(indexed[1].get("packet_count") or 0), indexed[0]),
    )
    names = [_escape(item.get("protocol")) for _, item in ordered[:3] if item.get("protocol")]
    return ", ".join(names) if names else "none observed"


def _format_tshark_top_talker(endpoints: list[dict]) -> str:
    ordered = _ordered_tshark_endpoints(endpoints)
    if not ordered:
        return "none observed"
    item = ordered[0]
    return f"{_escape(item.get('address'))} ({int(item.get('packet_count') or 0)} packets)"


def _format_tshark_top_talkers(endpoints: list[dict]) -> list[str]:
    ordered = _ordered_tshark_endpoints(endpoints)
    if not ordered:
        return ["- none observed"]
    return [f"- {_escape(item.get('address'))} ({int(item.get('packet_count') or 0)} packets)" for item in ordered[:5]]


def _format_tshark_endpoints(endpoints: list[dict], *, sort_by_count: bool = False) -> list[str]:
    if not endpoints:
        return ["- none observed"]
    ordered = sorted(enumerate(endpoints), key=lambda indexed: (-int(indexed[1].get("packet_count") or 0), indexed[0])) if sort_by_count else list(enumerate(endpoints))
    return [f"- {_escape(item.get('address'))} packets={int(item.get('packet_count') or 0)}" for _, item in ordered[:8]]


def _format_tshark_conversations(conversations: list[dict], *, sort_by_count: bool = False, compact: bool = False) -> list[str]:
    if not conversations:
        return ["- none observed"]
    lines = []
    ordered = sorted(enumerate(conversations), key=lambda indexed: (-int(indexed[1].get("packet_count") or 0), indexed[0])) if sort_by_count else list(enumerate(conversations))
    for _, item in ordered[:6]:
        src = _escape(item.get("src"))
        dst = _escape(item.get("dst"))
        packet_count = int(item.get("packet_count") or 0)
        if compact:
            lines.append(f"- {src} ↔ {dst} ({packet_count} packets)")
            continue
        src_port = _escape(item.get("src_port") or "")
        dst_port = _escape(item.get("dst_port") or "")
        transport = _escape(item.get("transport") or "unknown")
        src_label = f"{src}:{src_port}" if src_port else src
        dst_label = f"{dst}:{dst_port}" if dst_port else dst
        lines.append(f"- {src_label} -> {dst_label} {transport} packets={packet_count}")
    return lines


def _format_tshark_dns(observations: list[dict], *, arrow: bool = False) -> list[str]:
    if not observations:
        return ["- none observed"]
    deduped = _dedupe_tshark_dns(observations)
    if not arrow:
        return [
            f"- query={_escape(item.get('query_name') or 'n/a')} response={_escape(item.get('response_name') or item.get('response_address') or 'n/a')}"
            for item in deduped[:6]
        ]
    return [f"- {_escape(item.get('query_name') or 'n/a')}\n  →\n  {_escape(item.get('response_name') or item.get('response_address') or 'n/a')}" for item in deduped[:6]]


def _format_tshark_http(observations: list[dict]) -> list[str]:
    if not observations:
        return ["- none observed"]
    return [
        f"- request={_escape(item.get('method') or 'not observed')} host={_escape(item.get('host') or 'n/a')} "
        f"uri={_escape(item.get('uri') or 'n/a')} response_status={_escape(item.get('response_code') or 'not observed')}"
        for item in observations[:6]
    ]


def _format_tshark_tls(observations: list[dict], *, suppress_duplicate_na_sni: bool = False) -> list[str]:
    if not observations:
        return ["- none observed"]
    lines = []
    seen_na_sni: set[str] = set()
    for item in observations:
        sni = str(item.get("sni") or "").strip() or "n/a"
        version = _format_tshark_tls_version(item.get("version"))
        if suppress_duplicate_na_sni and sni.lower() == "n/a":
            key = version.lower()
            if key in seen_na_sni:
                continue
            seen_na_sni.add(key)
        lines.append(f"- sni={_escape(sni)} version={_escape(version)} handshake_success=not established by stored metadata")
        if len(lines) >= 6:
            break
    return lines or ["- none observed"]


def _format_tshark_warnings(warnings: list[str], result: dict) -> list[str]:
    unique_warnings = _dedupe_tshark_warnings(warnings)
    lines = [f"- {_escape(warning)}" for warning in unique_warnings[:5]]
    if result.get("error"):
        error = str(result.get("error") or "")
        if error not in unique_warnings:
            lines.append(f"- {_escape(error)}")
    return lines or ["- none"]


def _format_tshark_truncation(truncation: dict) -> list[str]:
    active = [key for key, value in sorted(truncation.items()) if value is True]
    if not active:
        return ["- none"]
    return [f"- {_escape(key)}" for key in active]


def _escape(value: object) -> str:
    return html.escape(str(value or ""), quote=False)


def _is_tshark_live_result(result: dict) -> bool:
    return str(result.get("source") or "") == "tshark_live" or bool(result.get("interface") and result.get("duration_seconds"))


def _is_tshark_standalone_live_result(result: dict) -> bool:
    if not _is_tshark_live_result(result):
        return False
    return any(result.get(key) not in (None, "") for key in ("interface", "duration_seconds", "packet_count_limit", "file_size_kb_limit"))


def _format_tshark_timestamp(value: object) -> str:
    if value in (None, ""):
        return "not available"
    try:
        timestamp = float(str(value).strip())
    except (TypeError, ValueError):
        return _escape(value)
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_tshark_duration(result: dict, normalized: dict, *, live_capture: bool) -> list[str]:
    if live_capture:
        value = result.get("elapsed_seconds")
        if value in (None, ""):
            value = result.get("duration_seconds")
        if value in (None, ""):
            value = _capture_duration_from_timestamps(normalized.get("capture_start"), normalized.get("capture_end"))
    else:
        value = _capture_duration_from_timestamps(normalized.get("capture_start"), normalized.get("capture_end"))
    try:
        seconds = max(0.0, float(str(value).strip()))
    except (TypeError, ValueError):
        return []
    return [f"Duration: {seconds:.1f}s"]


def _tshark_protocol_rank(protocol: object) -> int:
    lowered = str(protocol or "").lower()
    application = ("http", "dns", "tls", "ssl", "quic", "ssh", "smtp", "imap", "pop", "ftp", "smb", "rdp")
    transport = ("tcp", "udp", "sctp")
    network = ("ip", "ipv6", "icmp", "arp")
    link = ("eth", "frame", "data")
    if any(item in lowered for item in application):
        return 0
    if any(item in lowered for item in transport):
        return 1
    if any(item in lowered for item in network):
        return 2
    if any(item in lowered for item in link):
        return 3
    return 4


def _tshark_protocol_group(protocol: object) -> str:
    rank = _tshark_protocol_rank(protocol)
    if rank == 0:
        return "Application"
    if rank == 1:
        return "Transport"
    if rank == 2:
        return "Network"
    return "Link"


def _is_redundant_tshark_protocol(protocol: object) -> bool:
    return "ethertype" in str(protocol or "").strip().lower()


def _ordered_tshark_endpoints(endpoints: list[dict]) -> list[dict]:
    return [
        item
        for _, item in sorted(
            enumerate(endpoints or []),
            key=lambda indexed: (-int(indexed[1].get("packet_count") or 0), indexed[0]),
        )
    ]


def _dedupe_tshark_warnings(warnings: list[str]) -> list[str]:
    seen: set[str] = set()
    unique = []
    for warning in warnings:
        text = str(warning or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        unique.append(text)
    return unique


def _dedupe_tshark_dns(observations: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    unique = []
    for item in observations:
        key = (
            str(item.get("query_name") or ""),
            str(item.get("response_name") or ""),
            str(item.get("response_address") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _format_tshark_tls_version(version: object) -> str:
    raw = str(version or "n/a").strip()
    versions = {
        "0x0301": "TLS 1.0",
        "0x0302": "TLS 1.1",
        "0x0303": "TLS 1.2",
        "0x0304": "TLS 1.3",
    }
    return versions.get(raw.lower(), raw or "n/a")


def _capture_duration_from_timestamps(start: object, end: object) -> float | None:
    try:
        return float(str(end).strip()) - float(str(start).strip())
    except (TypeError, ValueError):
        return None


def _safe_uploaded_filename(file_name: object) -> str:
    name = str(file_name or "").replace("\\", "/").split("/")[-1].strip()
    if not name:
        return "uploaded capture"
    cleaned = "".join(character for character in name if character.isprintable()).strip()
    return cleaned[:160] or "uploaded capture"


def _truncate_tshark_card(message: str) -> str:
    text = str(message or "")
    if len(text) <= MAX_TSHARK_CARD_LENGTH:
        return text
    return f"{text[:MAX_TSHARK_CARD_LENGTH]}\n\n[output truncated]"
