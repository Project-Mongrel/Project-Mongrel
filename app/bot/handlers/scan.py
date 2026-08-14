import asyncio
import ipaddress
import logging
import re
import secrets
import time
from datetime import UTC
from pathlib import Path
from urllib.parse import urlsplit

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import BadRequest
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
from app.parsers.ffuf_parser import parse_ffuf_output, summarize_ffuf_results
from app.parsers.gitleaks_parser import GitleaksParserError, extract_gitleaks_vault_payloads, normalize_gitleaks_output, summarize_gitleaks_evidence
from app.parsers.httpx_parser import parse_httpx_output, summarize_httpx_services
from app.parsers.katana_parser import parse_katana_output, summarize_katana_observations
from app.parsers.nuclei_parser import NucleiParserError, parse_nuclei_results
from app.parsers.playwright_parser import normalize_playwright_observation, summarize_playwright_observation
from app.parsers.prowler_parser import ProwlerParserError, normalize_prowler_output
from app.parsers.testssl_parser import TestsslParserError, normalize_testssl_output, summarize_testssl_evidence
from app.parsers.metasploit_parser import parse_metasploit_validation_result
from app.services.ai_client import ask_ai
from app.services.assessment_store import (
    add_assessment_artifact,
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
from app.services.bbot_summary import build_bbot_recon_summary, build_bbot_recon_summary_from_observations
from app.services.chat_state import clear_finding_analysis_context, get_finding_analysis_context, is_ai_waiting
from app.services.comparison_engine import compare_findings
from app.services.findings_store import add_finding, get_latest_user_finding_for_target
from app.services.findings_store import get_user_finding
from app.services.evidence_vault import (
    EvidenceVaultDecryptError,
    EvidenceVaultUnavailable,
    get_secret_evidence_metadata,
    record_reveal_audit_event,
    reveal_secret_evidence,
    store_secret_evidence,
)
from app.services.icon_helper import section_label
from app.services.impact_engine import assess_change_impact
from app.services.investigation_store import add_investigation_event, get_investigation, get_or_create_latest_open_investigation
from app.services.metasploit_approval import (
    MetasploitApprovalError,
    approve_metasploit_proposal,
    get_metasploit_proposal,
    propose_metasploit_action,
    record_metasploit_result_reference,
    reject_metasploit_proposal,
)
from app.services.metasploit_ai_assessment import FALLBACK_LINES as METASPLOIT_AI_FALLBACK_LINES
from app.services.metasploit_ai_assessment import generate_metasploit_ai_assessment
from app.services.metasploit_policy import MODULE_POLICIES, build_metasploit_action_request
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
from app.services.nmap_interpretation import apply_nmap_assessment_interpretation, is_nmap_assessment_inconclusive
from app.services.nuclei_ai_assessment import FALLBACK_LINES as NUCLEI_AI_FALLBACK_LINES
from app.services.nuclei_ai_assessment import generate_nuclei_ai_assessment
from app.services.ffuf_ai_assessment import FALLBACK_LINES as FFUF_AI_FALLBACK_LINES
from app.services.ffuf_ai_assessment import generate_ffuf_ai_assessment
from app.services.gitleaks_ai_assessment import FALLBACK_LINES as GITLEAKS_AI_FALLBACK_LINES
from app.services.gitleaks_ai_assessment import generate_gitleaks_ai_assessment
from app.services.httpx_ai_assessment import FALLBACK_LINES as HTTPX_AI_FALLBACK_LINES
from app.services.httpx_ai_assessment import generate_httpx_ai_assessment
from app.services.katana_ai_assessment import FALLBACK_LINES as KATANA_AI_FALLBACK_LINES
from app.services.katana_ai_assessment import generate_katana_ai_assessment
from app.services.playwright_ai_assessment import FALLBACK_LINES as PLAYWRIGHT_AI_FALLBACK_LINES
from app.services.playwright_ai_assessment import generate_playwright_ai_assessment
from app.services.prowler_ai_assessment import FALLBACK_LINES as PROWLER_AI_FALLBACK_LINES
from app.services.prowler_ai_assessment import generate_prowler_ai_assessment
from app.services.testssl_ai_assessment import FALLBACK_LINES as TESTSSL_AI_FALLBACK_LINES
from app.services.testssl_ai_assessment import generate_testssl_ai_assessment
from app.services.service_intelligence import get_service_intelligence
from app.services.target_normalizer import normalize_for_bbot, normalize_for_ffuf, normalize_for_httpx, normalize_for_katana, normalize_for_nmap, normalize_for_nuclei, normalize_for_playwright, normalize_target_key
from app.tools.nmap_parser import parse_nmap_output
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS, run_nmap_scan
from app.tools.nuclei_runner import run_nuclei_scan
from app.tools.ffuf_runner import run_ffuf_scan
from app.tools.gitleaks_runner import run_gitleaks_scan
from app.tools.httpx_runner import run_httpx_scan
from app.tools.katana_runner import run_katana_scan
from app.tools.metasploit_runner import check_metasploit_readiness, run_metasploit_validation
from app.tools.playwright_runner import run_playwright_observation
from app.tools.prowler_runner import normalize_prowler_provider, run_prowler_scan, summarize_prowler_failure
from app.tools.testssl_runner import run_testssl_scan
from app.tools.bbot_runner import is_bbot_available, run_bbot_scan
from app.core.config import get_settings
from app.ui.ai_summary import render_ai_summary_card
from app.ui.scan_progress import ScanProgressCard, render_scan_loading_card
from app.ui.scan_actions import AI_SUMMARY_CALLBACK_PREFIX, SCAN_RECOVERY_CALLBACK_PREFIX, build_scan_recovery_actions, build_scan_result_actions
from app.ui.result_cards import render_scan_result_card, render_section

PENDING_NMAP_REQUEST_KEY = "pending_nmap_scan_request_id"
NUCLEI_STATUS_UPDATE_INTERVAL_SECONDS = 15
BBOT_AI_ASSESSMENT_CALLBACK_PREFIX = "bbot_ai"
GITLEAKS_EVIDENCE_VIEW_CALLBACK_PREFIX = "glev"
GITLEAKS_EVIDENCE_REVEAL_CALLBACK_PREFIX = "glrv"
GITLEAKS_EVIDENCE_CANCEL_CALLBACK_PREFIX = "glcx"
METASPLOIT_CALLBACK_PREFIX = "msf"
GITLEAKS_EVIDENCE_TOKEN_TTL_SECONDS = 900
METASPLOIT_FLOW_MODE_KEY = "metasploit_flow_mode"
METASPLOIT_GUIDED_CONTEXT_KEY = "metasploit_guided_context"
SCAN_RECOVERY_TOKEN_TTL_SECONDS = 3600
_gitleaks_evidence_action_tokens: dict[str, dict[str, object]] = {}
_metasploit_pending_context: dict[str, dict[str, object]] = {}
_metasploit_guided_tokens: dict[str, dict[str, object]] = {}
_bbot_ai_callback_tokens: dict[str, dict[str, object]] = {}
_scan_recovery_tokens: dict[str, dict[str, object]] = {}
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
            "Uses the configured bounded Nuclei profile: selected templates/tags/severities, exclusions, redirects, rate, concurrency, timeout, retries, and result limits.",
            "Template matches are scanner evidence, not automatic exploit confirmation. Zero matches means no selected templates matched.",
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
            "Uses the configured external BBOT CLI profile with allowlisted presets/modules, scope distance, DNS/web concurrency, timeout, and output limits.",
            "Discoveries are observations only. Technology detection is not vulnerability proof, and absence of discoveries does not prove absence.",
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
            "Bounded web-service probing covers configured ports/schemes, redirects, TLS/certificate, IP/CDN/CNAME, timing, and technology metadata.",
            "No response bodies, cookies, auth headers, credentials, or secrets are collected for Telegram output.",
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
            "Bounded authorized crawling with JavaScript endpoint discovery, forms, redirects, and known files where configured.",
            "Scope remains constrained by validated target and configured Katana field scope.",
            "",
            "Examples:",
            "https://example.com",
            "example.com",
        ]
    )


def build_playwright_target_prompt() -> str:
    return "\n".join(
        [
            "Playwright observation request created. Send the authorized HTTP target URL or hostname.",
            "",
            "Passive browser observation of JavaScript-rendered content, links, forms, inputs, redirects, console, and network metadata.",
            "No clicks, form submissions, credential entry, purchases, account changes, or custom scripts are performed.",
            "",
            "Examples:",
            "https://example.com",
            "example.com",
        ]
    )


def build_ffuf_target_prompt() -> str:
    return "\n".join(
        [
            "ffuf discovery request created. Send the authorized HTTP target URL or hostname.",
            "",
            "Hidden-content discovery uses the configured wordlist and bounded ffuf settings.",
            "Optional: include FUZZ in an authorized URL to control the fuzz position.",
            "",
            "Examples:",
            "https://example.com",
            "https://example.com/api/FUZZ",
            "https://example.com/search?q=FUZZ",
            "example.com",
        ]
    )


def build_testssl_target_prompt() -> str:
    return "\n".join(
        [
            "testssl.sh TLS assessment request created. Send the authorized TLS target URL or hostname.",
            "",
            "Bounded TLS assessment using the configured testssl.sh profile: protocols, cipher categories, certificate/trust metadata, vulnerabilities, SNI/IP mode, STARTTLS where configured, and time/output limits.",
            "Scanner labels are TLS evidence, not automatic exploit confirmation. Absence of findings is not a secure verdict.",
            "",
            "Examples:",
            "https://example.com",
            "example.com",
            "example.com:443",
        ]
    )


def build_gitleaks_target_prompt() -> str:
    return "\n".join(
        [
            "Gitleaks secret scan request created.",
            "",
            "Send an authorized local directory path on the Mongrel VPS.",
            "",
            "Detection only:",
            "- Secrets are redacted in Telegram, AI, and reports.",
            "- Raw secrets are stored only in the encrypted Evidence Vault when configured.",
            "- No credential validation or use is performed.",
            "",
            "Demo smoke-test path:",
            "/home/mongrel/Project-Mongrel/data/gitleaks_smoke_fixture",
            "",
            "Assessment artifact example:",
            "/home/mongrel/Project-Mongrel/data/artifacts/<assessment-id>",
            "",
            "The demo smoke-test path contains generated fake test data only.",
        ]
    )


def build_prowler_provider_prompt() -> str:
    return "\n".join(
        [
            "Prowler cloud posture scan request created.",
            "",
            "Send the authorized provider to assess:",
            "aws",
            "azure",
            "gcp",
            "",
            "Requirements:",
            "- The Mongrel VPS must already have authorized read-only cloud credentials available for that provider.",
            "- Mongrel does not create credentials.",
            "- Mongrel does not modify cloud resources.",
            "- No remediation or validation actions are performed.",
        ]
    )


def build_metasploit_request_prompt() -> str:
    return "\n".join(
        [
            "Metasploit controlled validation request created.",
            "",
            "Send a structured request only:",
            "module=<allowlisted_module>",
            "action=<check|auxiliary_validation|exploit_validation>",
            "target=<authorized_target>",
            "port=<port>",
            "",
            "Optional policy-approved options:",
            "option.TARGETURI=/",
            "option.SSL=true",
            "",
            "Raw msfconsole commands, resource scripts, sessions, post-exploitation, lateral movement, and brute force are not accepted.",
        ]
    )


def build_metasploit_mode_text() -> str:
    return "\n".join(
        [
            "Metasploit Validation",
            "",
            "Choose how to prepare the controlled validation request.",
            "",
            "Guided Validation walks through target, service, and a compatible allowlisted validation.",
            "Advanced Manual Mode accepts the existing structured key=value request format.",
            "",
            "No msfconsole commands, raw resource scripts, sessions, post-exploitation, lateral movement, or brute force are accepted.",
        ]
    )


def build_metasploit_mode_keyboard(scan_request_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Guided Validation", callback_data=f"{METASPLOIT_CALLBACK_PREFIX}:guided:{scan_request_id}")],
            [InlineKeyboardButton("Advanced Manual Mode", callback_data=f"{METASPLOIT_CALLBACK_PREFIX}:manual:{scan_request_id}")],
            [InlineKeyboardButton("Back", callback_data="scan:metasploit")],
        ]
    )


def build_metasploit_guided_target_prompt() -> str:
    return "\n".join(
        [
            "Metasploit guided validation.",
            "",
            "Send the authorized hostname or IP address.",
            "",
            "URLs are normalized to hostnames when safe.",
            "No validation runs until you review and approve the exact action.",
        ]
    )


def build_metasploit_service_keyboard(user_id: int, scan_request_id: str, target: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "HTTP - 80",
                    callback_data=f"{METASPLOIT_CALLBACK_PREFIX}:svc:{_register_metasploit_guided_token(user_id, scan_request_id, target=target, service='HTTP', port=80)}",
                ),
                InlineKeyboardButton(
                    "HTTPS - 443",
                    callback_data=f"{METASPLOIT_CALLBACK_PREFIX}:svc:{_register_metasploit_guided_token(user_id, scan_request_id, target=target, service='HTTPS', port=443)}",
                ),
            ],
            [
                InlineKeyboardButton(
                    "Custom Port",
                    callback_data=f"{METASPLOIT_CALLBACK_PREFIX}:custom:{_register_metasploit_guided_token(user_id, scan_request_id, target=target)}",
                )
            ],
        ]
    )


def build_metasploit_service_prompt(target: str) -> str:
    return "\n".join(
        [
            "Choose the service/port to validate.",
            "",
            f"Target: {target}",
            "",
            "Only compatible allowlisted Metasploit validations will be shown next.",
        ]
    )


def build_metasploit_validation_keyboard(user_id: int, scan_request_id: str, target: str, service: str, port: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "HTTP service fingerprint check",
                    callback_data=f"{METASPLOIT_CALLBACK_PREFIX}:val:{_register_metasploit_guided_token(user_id, scan_request_id, target=target, service=service, port=port, validation='http_version')}",
                )
            ]
        ]
    )


def build_metasploit_validation_prompt(target: str, service: str, port: int) -> str:
    return "\n".join(
        [
            "Choose an allowlisted validation.",
            "",
            f"Target: {target}",
            f"Service: {service} - {port}",
            "",
            "Available:",
            "HTTP service fingerprint check",
        ]
    )


def _register_metasploit_guided_token(user_id: int, scan_request_id: str, **payload: object) -> str:
    token = secrets.token_urlsafe(9)
    while token in _metasploit_guided_tokens:
        token = secrets.token_urlsafe(9)
    _metasploit_guided_tokens[token] = {"user_id": int(user_id), "scan_request_id": scan_request_id, **payload}
    return token


def build_metasploit_readiness_failure_text(readiness: dict[str, object] | None = None) -> str:
    readiness = readiness or {}
    configured = str(readiness.get("configured_binary") or "msfconsole")
    return "\n".join(
        [
            "Metasploit Validation is not ready.",
            "",
            "Metasploit/msfconsole is not installed or configured.",
            f"Configured binary: {configured}",
            "",
            "Set METASPLOIT_BINARY to the msfconsole path on the Mongrel VPS, then try again.",
            "No validation proposal was created and no target was touched.",
        ]
    )


def build_metasploit_proposal_text(proposal: object) -> str:
    request = getattr(proposal, "request", {}) or {}
    options = request.get("options") or {}
    service = _metasploit_service_label(int(request.get("port") or 0))
    validation = _metasploit_validation_name(str(request.get("module") or ""))
    risk = str(request.get("risk_tier") or "unknown").upper()
    expected_effect = str(request.get("expected_effect") or "Perform the selected controlled validation against the authorized target.")
    return "\n".join(
        [
            "Metasploit Validation Review",
            "",
            "Controlled offensive validation for explicitly authorized targets only.",
            "",
            "Target:",
            str(request.get("target") or "unknown"),
            "",
            "Service:",
            f"{service} ({request.get('port') or 'unknown'})",
            "",
            "Validation:",
            validation,
            "",
            "Module:",
            str(request.get("module") or "unknown"),
            "",
            "Action:",
            str(request.get("action_type") or "unknown"),
            "",
            "Risk:",
            risk,
            "",
            "This action WILL:",
            f"- {expected_effect}",
            "",
            "This action WILL NOT:",
            "- Create a session",
            "- Upload a payload",
            "- Perform post-exploitation",
            "- Move laterally",
            "- Execute brute force",
            "",
            "Metasploit Validation Proposal",
            f"Proposal ID: {getattr(proposal, 'id', 'unknown')}",
            f"Target: {request.get('target') or 'unknown'}",
            f"Port: {request.get('port') or 'unknown'}",
            f"Risk tier: {risk}",
            f"Expected effect: {expected_effect}",
            f"Timeout: {request.get('timeout_seconds') or 'unknown'}s",
            f"Expires: {_format_metasploit_timestamp(getattr(proposal, 'expires_at', None))}",
            "Approved options: " + (_format_metasploit_options(options) if options else "none"),
            "",
            "Approve only if this exact action is authorized.",
        ]
    )


def build_metasploit_proposal_details_text(proposal: object) -> str:
    base_lines = build_metasploit_proposal_text(proposal).splitlines()
    return "\n".join(
        [
            "Metasploit Validation Proposal Details",
            "",
            *base_lines[2:],
            "",
            f"Approval status: {getattr(proposal, 'status', 'unknown')}",
            f"Execution state: {getattr(proposal, 'execution_state', 'unknown')}",
        ]
    )


def build_metasploit_proposal_keyboard(proposal_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Approve", callback_data=f"{METASPLOIT_CALLBACK_PREFIX}:approve:{proposal_id}"),
                InlineKeyboardButton("Reject", callback_data=f"{METASPLOIT_CALLBACK_PREFIX}:reject:{proposal_id}"),
            ],
            [InlineKeyboardButton("Details", callback_data=f"{METASPLOIT_CALLBACK_PREFIX}:details:{proposal_id}")],
        ]
    )


def build_metasploit_result_text(finding: dict) -> str:
    evidence = finding.get("metasploit_evidence") or {}
    return "\n".join(
        [
            "Metasploit Validation",
            "",
            "Target:",
            str(finding.get("target") or evidence.get("target") or "unknown"),
            "",
            "Module:",
            str(evidence.get("module") or "unknown"),
            "",
            "Action:",
            str(evidence.get("action_type") or "unknown"),
            "",
            "Status:",
            str(finding.get("status") or "unknown").title(),
            "",
            "Validation State:",
            str(evidence.get("validation_state") or "INCONCLUSIVE"),
            "",
            "Evidence:",
            str(evidence.get("summary") or "No conclusive validation evidence recorded."),
            "",
            "Artifact/ref:",
            str((finding.get("metadata") or {}).get("artifact_ref") or "not captured"),
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


def build_bbot_ai_assessment_keyboard(
    investigation_id: str | None,
    finding_id: str | None = None,
    user_id: int | None = None,
) -> InlineKeyboardMarkup | None:
    if not investigation_id:
        return None

    token = _register_bbot_ai_callback(user_id=user_id, investigation_id=investigation_id, finding_id=finding_id)
    callback_data = f"{BBOT_AI_ASSESSMENT_CALLBACK_PREFIX}:{token}"
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("Generate AI Recon Assessment", callback_data=callback_data)]]
    )


def _register_bbot_ai_callback(user_id: int | None, investigation_id: str, finding_id: str | None = None) -> str:
    token = secrets.token_urlsafe(9)
    while token in _bbot_ai_callback_tokens:
        token = secrets.token_urlsafe(9)
    _bbot_ai_callback_tokens[token] = {
        "user_id": user_id,
        "investigation_id": investigation_id,
        "finding_id": finding_id,
    }
    return token


def _combine_inline_keyboards(*keyboards: InlineKeyboardMarkup | None) -> InlineKeyboardMarkup | None:
    rows = []
    for keyboard in keyboards:
        if keyboard is not None:
            rows.extend(keyboard.inline_keyboard)

    return InlineKeyboardMarkup(rows) if rows else None


def _assessment_id_from_context(assessment_context: dict | None) -> int | None:
    if not isinstance(assessment_context, dict) or assessment_context.get("assessment_id") is None:
        return None
    try:
        return int(assessment_context["assessment_id"])
    except (TypeError, ValueError):
        return None


def _register_scan_recovery_context(
    *,
    user_id: int,
    tool: str,
    target: str,
    assessment_context: dict | None = None,
) -> str:
    token = secrets.token_urlsafe(9)
    while token in _scan_recovery_tokens:
        token = secrets.token_urlsafe(9)
    _scan_recovery_tokens[token] = {
        "user_id": user_id,
        "tool": str(tool or "").strip().lower(),
        "target": str(target or ""),
        "assessment_context": dict(assessment_context) if isinstance(assessment_context, dict) else None,
        "created_at": time.time(),
    }
    return token


def _get_scan_recovery_context(token: str, user_id: int) -> dict[str, object] | None:
    now = time.time()
    for stored_token, payload in list(_scan_recovery_tokens.items()):
        if now - float(payload.get("created_at") or 0) > SCAN_RECOVERY_TOKEN_TTL_SECONDS:
            _scan_recovery_tokens.pop(stored_token, None)

    payload = _scan_recovery_tokens.get(token)
    if not payload or payload.get("user_id") != user_id:
        return None
    return payload


def _build_scan_outcome_actions(
    *,
    user_id: int,
    tool: str,
    target: str,
    outcome: str,
    finding_id: str | None = None,
    assessment_context: dict | None = None,
) -> InlineKeyboardMarkup | None:
    token = _register_scan_recovery_context(
        user_id=user_id,
        tool=tool,
        target=target,
        assessment_context=assessment_context,
    )
    assessment_id = _assessment_id_from_context(assessment_context)
    if finding_id:
        return build_scan_result_actions(
            finding_id,
            tool,
            recovery_token=token,
            outcome=outcome,
            assessment_id=assessment_id,
        )
    return build_scan_recovery_actions(token, outcome, assessment_id=assessment_id)


def _restore_recovery_scan_request(user_id: int, context: ContextTypes.DEFAULT_TYPE, payload: dict[str, object]) -> str:
    tool = str(payload.get("tool") or "").strip().lower()
    scan_request = create_scan_request(user_id=user_id, scan_type=tool)
    mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
    context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
    assessment_context = payload.get("assessment_context")
    if isinstance(assessment_context, dict):
        context.user_data[ASSESSMENT_SCAN_CONTEXT_KEY] = dict(assessment_context)
    return scan_request.id


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
    content_types = [str(value) for value in summary.get("content_types") or []]
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
    metadata_details = []
    if content_types:
        metadata_details.append("Content types: " + ", ".join(content_types[:5]))
    network_metadata = [
        f"IPs: {summary.get('ip_count', 0)}",
        f"CDN observations: {summary.get('cdn_count', 0)}",
        f"CNAME observations: {summary.get('cname_count', 0)}",
        f"TLS/certificate metadata: {summary.get('tls_count', 0)}",
    ]
    metadata_details.append("Metadata: " + ", ".join(network_metadata))
    if technologies:
        findings.append("Technologies: " + ", ".join(technologies[:8]) + " | " + " | ".join(metadata_details))
    else:
        findings.append(" | ".join(metadata_details))
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
        summary=(
            f"{summary.get('service_count', 0)} HTTP service/URL observation(s) recorded. "
            "HTTP status, CDN/challenge, and technology metadata are observations only, not vulnerability findings."
        ),
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


def build_playwright_result_text(result: dict[str, object], observation: dict | None = None) -> str:
    observation = normalize_playwright_observation(observation or {})
    summary = summarize_playwright_observation(observation)
    limitations = list(observation.get("limitations") or [])
    if result.get("success") is not True:
        limitations.append(str(result.get("error") or "Playwright observation did not complete successfully."))
    if not observation:
        limitations.append("No structured Playwright browser observation was stored.")
    screenshot_status = "present" if summary.get("screenshot_present") else "not captured"
    findings = [
        f"Final URL: {summary.get('final_url') or 'unknown'}",
        f"Title: {summary.get('title') or 'not observed'}",
        f"Load status: {summary.get('load_status') or 'unknown'}",
        f"Status code: {summary.get('status_code') or 'not observed'}",
        f"Forms/inputs: {summary.get('forms_count', 0)} forms / {summary.get('inputs_count', 0)} inputs",
        f"Links: {summary.get('links_count', 0)}",
        f"Observed samples: {summary.get('form_samples_count', 0)} forms / {summary.get('input_samples_count', 0)} inputs / {summary.get('network_events_count', 0)} network events",
        f"Out-of-scope redirect: {'yes' if summary.get('redirected_out_of_scope') else 'no'}",
        f"Console/network issues: {summary.get('console_issue_count', 0)} console / {summary.get('network_issue_count', 0)} network / {summary.get('page_error_count', 0)} page errors",
        f"Screenshot/artifact: {screenshot_status}",
    ]
    if limitations:
        findings.append("Limitations: " + " ".join(str(limitation) for limitation in limitations[:3]))
    findings_text = "\n".join(f"- {finding}" for finding in findings)
    return render_scan_result_card(
        tool_name="Playwright",
        target=str(result.get("target") or observation.get("requested_url") or "unknown"),
        status="Complete" if result.get("success") is True else "Failed",
        elapsed=f"{int(float(result.get('elapsed_seconds') or 0))}s",
        risk="INFO" if result.get("success") is True else None,
        summary="Passive browser observation recorded." if result.get("success") is True else str(result.get("error") or "Playwright observation failed."),
        findings=findings_text,
        assets=[str(value) for value in [observation.get("requested_url"), observation.get("final_url"), *(observation.get("link_samples") or [])] if value],
    )


def store_playwright_scan_result(user_id: int, result: dict[str, object], observation: dict | None = None) -> dict:
    observation = normalize_playwright_observation(observation or {})
    summary = summarize_playwright_observation(observation)
    status = "completed" if result.get("success") is True else "failed"
    if result.get("success") is True:
        finding_summary = "Playwright passive browser observation completed."
    else:
        finding_summary = str(result.get("error") or "Playwright observation failed.")
    target = str(result.get("target") or observation.get("requested_url") or "")
    return add_finding(
        user_id=user_id,
        finding={
            "source": "playwright",
            "target": target,
            "target_key": normalize_target_key(target),
            "status": status,
            "summary": finding_summary,
            "risk_level": "info" if result.get("success") is True else "unknown",
            "finding_count": 1 if observation else 0,
            "raw_output": "",
            "playwright_observation": observation,
            "playwright_summary": summary,
            "metadata": {
                "elapsed_seconds": result.get("elapsed_seconds"),
                "error": result.get("error"),
                "error_type": result.get("error_type"),
                "mode": "passive_browser_observation",
                "screenshot_present": bool(summary.get("screenshot_present")),
            },
        },
    )


def build_ffuf_result_text(result: dict[str, object], observations: list[dict] | None = None) -> str:
    observations = observations or []
    summary = summarize_ffuf_results(observations)
    limitations = []
    if result.get("success") is not True:
        limitations.append(str(result.get("error") or "ffuf did not complete successfully."))
    if not observations:
        limitations.append("No structured ffuf JSON observations were stored.")
    status_codes = summary.get("status_codes") or {}
    interesting_paths = [str(value) for value in summary.get("interesting_paths") or []]
    redirects = [
        f"{observation.get('path') or observation.get('url')} -> {observation.get('redirect_location')}"
        for observation in observations
        if observation.get("redirect_location")
    ]
    findings = [
        f"Wordlist entries: {int(result.get('wordlist_count') or 0)}",
        f"Discovered paths: {summary.get('result_count', 0)}",
        "Status codes: " + (", ".join(f"{code}: {count}" for code, count in sorted(status_codes.items())) if status_codes else "none"),
        f"Forbidden/auth-gated responses: {summary.get('forbidden_count', 0)}",
        f"Server-error responses: {summary.get('server_error_count', 0)}",
    ]
    if interesting_paths:
        findings.append("Interesting paths: " + "; ".join(interesting_paths[:8]))
    if redirects:
        findings.append("Redirects: " + "; ".join(redirects[:5]))
    if result.get("wordlist_path"):
        findings.append(f"Wordlist used: {str(result.get('wordlist_path')).split('/')[-1].split(chr(92))[-1]}")
    if limitations:
        findings.append("Limitations: " + " ".join(limitations))
    findings_text = "\n".join(f"- {finding}" for finding in findings)
    return render_scan_result_card(
        tool_name="ffuf",
        target=str(result.get("target") or "unknown"),
        status="Complete" if result.get("success") is True else "Failed",
        elapsed=f"{int(float(result.get('elapsed_seconds') or 0))}s",
        risk="INFO" if result.get("success") is True else None,
        summary=f"{summary.get('result_count', 0)} hidden-content observation(s) recorded.",
        findings=findings_text,
        assets=[str(observation.get("url")) for observation in observations if observation.get("url")],
    )


def store_ffuf_scan_result(user_id: int, result: dict[str, object], observations: list[dict] | None = None) -> dict:
    observations = observations or []
    status = "completed" if result.get("success") is True else "failed"
    summary = summarize_ffuf_results(observations)
    if result.get("success") is True:
        finding_summary = f"ffuf observed {len(observations)} hidden-content path record(s)."
    else:
        finding_summary = str(result.get("error") or "ffuf hidden-content discovery failed.")
    target = str(result.get("target") or "")
    return add_finding(
        user_id=user_id,
        finding={
            "source": "ffuf",
            "target": target,
            "target_key": normalize_target_key(target),
            "status": status,
            "summary": finding_summary,
            "risk_level": "info" if result.get("success") is True else "unknown",
            "finding_count": len(observations),
            "raw_output": str(result.get("output") or ""),
            "ffuf_results": observations,
            "ffuf_summary": summary,
            "metadata": {
                "returncode": result.get("returncode"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "command": result.get("command"),
                "working_directory": result.get("working_directory"),
                "error": result.get("error"),
                "error_type": result.get("error_type"),
                "parser": "json",
                "wordlist_path": result.get("wordlist_path"),
                "wordlist_count": result.get("wordlist_count"),
                "fuzz_url": result.get("fuzz_url"),
            },
        },
    )


def build_testssl_result_text(result: dict[str, object], evidence: dict | None = None) -> str:
    evidence = evidence or {}
    summary = summarize_testssl_evidence(evidence) if evidence else {}
    limitations = list(evidence.get("limitations") or [])
    if result.get("success") is not True:
        limitations.append(str(result.get("error") or "testssl.sh did not complete successfully."))
    protocols = summary.get("supported_protocols") or [item.get("name") for item in evidence.get("protocols") or [] if item.get("name")]
    vulnerabilities = evidence.get("vulnerabilities") or []
    notable = [
        item
        for item in vulnerabilities + (evidence.get("notable_findings") or []) + (evidence.get("cipher_findings") or [])
        if _is_notable_testssl_item(item)
    ]
    findings = [
        "Certificate: " + str(summary.get("certificate_summary") or "No certificate metadata extracted."),
        "Protocols: " + (", ".join(str(value) for value in protocols[:8]) if protocols else "none extracted"),
    ]
    weak = evidence.get("weak_protocols") or []
    if weak:
        findings.append("Weak/deprecated: " + "; ".join(str(value) for value in weak[:5]))
    findings.extend(
        [
            "Notable TLS findings: " + (str(len(notable)) if notable else "none recorded"),
            "Limitation: TLS configuration evidence only; scanner labels are not automatic exploit confirmation.",
        ]
    )
    for item in notable[:5]:
        findings.append(f"{item.get('id')}: {item.get('finding') or item.get('severity') or 'reported'}")
    if limitations:
        findings.append("Limitations: " + " ".join(limitations[:3]))
    return render_scan_result_card(
        tool_name="testssl.sh",
        target=str(result.get("target") or evidence.get("target") or "unknown"),
        status="Complete" if result.get("success") is True else "Failed",
        elapsed=f"{int(float(result.get('elapsed_seconds') or 0))}s",
        risk="INFO" if result.get("success") is True else None,
        summary=(
            "TLS configuration evidence recorded. No secure/robust conclusion is made from absence of findings."
            if evidence
            else "No structured testssl.sh evidence was stored."
        ),
        findings=findings,
        assets=[str(evidence.get("host") or result.get("target") or "")],
    )


def store_testssl_scan_result(user_id: int, result: dict[str, object], evidence: dict | None = None) -> dict:
    evidence = evidence or {}
    status = "completed" if result.get("success") is True else "failed"
    summary = summarize_testssl_evidence(evidence) if evidence else {}
    notable_count = int(summary.get("notable_count") or 0) + int(summary.get("weak_protocol_count") or 0)
    target = str(result.get("target") or evidence.get("target") or "")
    return add_finding(
        user_id=user_id,
        finding={
            "source": "testssl",
            "target": target,
            "target_key": normalize_target_key(target),
            "status": status,
            "summary": (
                f"testssl.sh recorded TLS evidence for {evidence.get('host') or target}."
                if result.get("success") is True
                else str(result.get("error") or "testssl.sh TLS assessment failed.")
            ),
            "risk_level": "info" if result.get("success") is True else "unknown",
            "finding_count": notable_count,
            "raw_output": "",
            "testssl_evidence": evidence,
            "testssl_summary": summary,
            "metadata": {
                "returncode": result.get("returncode"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "command": result.get("command"),
                "working_directory": result.get("working_directory"),
                "error": result.get("error"),
                "error_type": result.get("error_type"),
                "parser": "testssl-json",
            },
        },
    )


def _is_notable_testssl_item(item: dict) -> bool:
    severity = str(item.get("severity") or "").upper()
    finding = str(item.get("finding") or "").lower()
    if severity in {"HIGH", "CRITICAL", "MEDIUM", "LOW", "WARN", "WARNING"}:
        return True
    return not any(term in finding for term in ("not vulnerable", "not offered", "not supported", "no vulnerability"))


def build_gitleaks_result_text(result: dict[str, object], evidence: dict | None = None) -> str:
    evidence = evidence or {}
    summary = summarize_gitleaks_evidence(evidence) if evidence else {}
    finding_count = int(summary.get("finding_count") or 0)
    affected_files = int(summary.get("affected_files_count") or 0)
    limitations = list(evidence.get("limitations") or [])
    if result.get("success") is not True:
        limitations.append(str(result.get("error") or "Gitleaks did not complete successfully."))
    findings = [
        f"Secret findings: {finding_count}",
        f"Affected files: {affected_files}",
    ]
    for item in (evidence.get("findings") or [])[:5]:
        findings.append(
            f"{item.get('rule_id') or 'unknown'} in {item.get('file_path') or 'unknown'}:"
            f"{item.get('line_number') or '?'} ({item.get('redacted_secret_preview') or '<REDACTED>'})"
        )
        break
    findings.extend(
        [
            "Rules: " + _format_count_summary(summary.get("rule_summary") or {}),
            "Providers: " + _format_count_summary(summary.get("provider_summary") or {}),
            "Severity: " + _format_count_summary(summary.get("severity_summary") or {}),
        ]
    )
    findings.append("Limitation: Detection only; secrets were not validated or used.")
    if limitations:
        findings.append("Limitations: " + " ".join(str(value) for value in limitations[:3]))
    return render_scan_result_card(
        tool_name="Gitleaks",
        target=str(result.get("target") or evidence.get("scan_root") or "unknown"),
        status="Complete" if result.get("success") is True else "Failed",
        elapsed=f"{int(float(result.get('elapsed_seconds') or 0))}s",
        risk="HIGH" if finding_count else ("INFO" if result.get("success") is True else None),
        summary=f"{finding_count} redacted secret-exposure finding(s) recorded.",
        findings=findings,
        assets=[str(evidence.get("scan_root") or result.get("target") or "")],
    )


def build_gitleaks_result_actions(finding: dict | None, assessment_context: dict | None, user_id: int | None = None) -> InlineKeyboardMarkup | None:
    if not finding:
        return build_scan_result_actions(finding.get("id") if finding else None, "gitleaks")
    finding_id = str(finding.get("id") or "")
    base_actions = build_scan_result_actions(finding_id, "gitleaks")
    buttons = list(base_actions.inline_keyboard) if base_actions else []
    assessment_ref = _gitleaks_assessment_reference(assessment_context)
    evidence_items = _gitleaks_vaulted_findings(finding)
    for index, evidence_item in enumerate(evidence_items, start=1):
        evidence_id = str(evidence_item.get("evidence_id") or "")
        if not evidence_id or not finding_id:
            continue
        token = _store_gitleaks_evidence_action_token(
            user_id=user_id,
            assessment_id=assessment_ref,
            finding_id=finding_id,
            evidence_id=evidence_id,
        )
        label = "View Evidence" if len(evidence_items) == 1 else f"View Evidence #{index}"
        buttons.append(
            [
                InlineKeyboardButton(
                    label,
                    callback_data=f"{GITLEAKS_EVIDENCE_VIEW_CALLBACK_PREFIX}:{token}",
                )
            ]
        )
    return InlineKeyboardMarkup(buttons) if buttons else None


def build_gitleaks_evidence_warning_text(finding: dict, evidence_id: str) -> str:
    evidence_item = _find_gitleaks_evidence_item(finding, evidence_id) or {}
    return "\n".join(
        [
            "Sensitive Evidence Warning",
            "",
            f"Evidence ID: {evidence_id}",
            f"Provider: {evidence_item.get('provider') or 'unknown'}",
            f"Rule: {evidence_item.get('rule_id') or 'unknown'}",
            f"File: {evidence_item.get('file_path') or 'unknown'}",
            f"Line: {evidence_item.get('line_number') or '?'}",
            f"Preview: {evidence_item.get('redacted_secret_preview') or '<REDACTED>'}",
            f"Fingerprint: {evidence_item.get('fingerprint') or evidence_item.get('secret_hash') or 'not available'}",
            "",
            "This action reveals sensitive evidence from the encrypted Evidence Vault.",
            "Use it only for explicitly authorized assessments.",
        ]
    )


def build_gitleaks_evidence_warning_keyboard(token: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "Reveal Full Secret",
                    callback_data=f"{GITLEAKS_EVIDENCE_REVEAL_CALLBACK_PREFIX}:{token}",
                )
            ],
            [
                InlineKeyboardButton(
                    "Cancel",
                    callback_data=f"{GITLEAKS_EVIDENCE_CANCEL_CALLBACK_PREFIX}:{token}",
                )
            ],
        ]
    )


def build_gitleaks_sensitive_secret_text(evidence_id: str, secret_value: str, ttl_seconds: int) -> str:
    return "\n".join(
        [
            "Sensitive Evidence Revealed",
            "",
            f"Evidence ID: {evidence_id}",
            "",
            secret_value,
            "",
            f"This message is intended to be short-lived and may be deleted after {ttl_seconds}s.",
            "Do not copy it into reports, AI prompts, logs, or normal evidence.",
        ]
    )


def summarize_prowler_evidence(evidence: dict) -> dict:
    findings = evidence.get("findings") or []
    failed = [finding for finding in findings if str(finding.get("status") or "").upper() == "FAIL"]
    passed = [finding for finding in findings if str(finding.get("status") or "").upper() == "PASS"]
    return {
        "finding_count": int(evidence.get("finding_count") or len(findings)),
        "failed_count": len(failed),
        "passed_count": len(passed),
        "highest_severity": _highest_prowler_severity(finding.get("severity") for finding in findings),
        "top_failed_services": _top_failed_prowler_services(failed),
    }


def build_prowler_result_text(result: dict[str, object], evidence: dict | None = None) -> str:
    evidence = evidence or {}
    summary = summarize_prowler_evidence(evidence) if evidence else {}
    provider = str(result.get("provider") or evidence.get("provider") or "unknown").upper()
    cloud_context = str(result.get("cloud_context") or evidence.get("cloud_context") or f"standalone-{provider.lower()}")
    output_files = result.get("output_files") or []
    findings = [
        f"Provider: {provider}",
        f"Context: {cloud_context}",
    ]
    finding_count = int(summary.get("finding_count") or 0)
    findings.extend(
        [
            f"Total checks/findings parsed: {finding_count}",
            f"Failed checks: {int(summary.get('failed_count') or 0)}",
            f"Passed checks: {int(summary.get('passed_count') or 0)}",
        ]
    )
    if result.get("success") is True or finding_count:
        findings.extend(
            [
                f"Highest scanner-reported severity: {summary.get('highest_severity') or 'none'}",
                "Top failed services: " + (", ".join(summary.get("top_failed_services") or []) or "none"),
            ]
        )
    if output_files:
        findings.append(f"Output artifact: {Path(str(output_files[0])).name}")
    top_failed = [
        finding
        for finding in evidence.get("findings") or []
        if str(finding.get("status") or "").upper() == "FAIL"
    ][:3]
    for finding in top_failed:
        findings.append(
            f"{finding.get('check_id') or 'check'}: {finding.get('service') or 'unknown'} "
            f"{finding.get('region') or 'unknown'} ({finding.get('severity') or 'unknown'})"
        )
    return render_scan_result_card(
        tool_name="Prowler Cloud Posture",
        target=cloud_context,
        status="Complete" if result.get("success") is True else "Failed",
        elapsed=f"{int(float(result.get('elapsed_seconds') or 0))}s",
        risk="INFO" if result.get("success") is True else None,
        summary=f"{provider} cloud posture evidence collected for {cloud_context}." if result.get("success") is True else f"Prowler scan failed. {_safe_prowler_failure_text(result, provider)}",
        findings=findings,
        assets=[f"Provider: {provider}", f"Context: {cloud_context}"],
    )


def _safe_prowler_failure_text(result: dict[str, object], provider: str) -> str:
    error = str(result.get("error") or "")
    if error:
        return summarize_prowler_failure(provider.lower(), stderr=error)
    return "Prowler scan failed."


def parse_metasploit_request_text(text: str) -> dict:
    values: dict[str, object] = {}
    options: dict[str, object] = {}
    raw_command_verbs = {"use", "set", "run", "exploit", "sessions", "jobs", "route", "shell", "background", "load"}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        first_token = line.split(maxsplit=1)[0].lower()
        if first_token in raw_command_verbs:
            raise ValueError("Raw msfconsole commands are not accepted.")
        if "=" not in line:
            raise ValueError("Metasploit request lines must use key=value format.")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        normalized_key = key.lower()
        if normalized_key in {"module", "action", "target", "port", "timeout"}:
            values[normalized_key] = value
        elif normalized_key.startswith("option."):
            option_name = key.split(".", 1)[1].strip().upper()
            options[option_name] = value
        elif key.isupper():
            options[key.upper()] = value
        else:
            raise ValueError("Unsupported Metasploit request field.")
    if "module" not in values or "action" not in values or "target" not in values:
        raise ValueError("Metasploit request requires module, action, and target.")
    port = int(values.get("port") or 0)
    if not port:
        raise ValueError("Metasploit request requires port.")
    timeout = int(values["timeout"]) if values.get("timeout") else None
    return build_metasploit_action_request(
        module=str(values["module"]),
        action_type=str(values["action"]),
        target=str(values["target"]),
        port=port,
        options=options,
        timeout_seconds=timeout,
    )


def _format_metasploit_recovery_request(request: dict | None) -> str:
    request = request or {}
    lines = [
        f"module={request.get('module') or ''}",
        f"action={request.get('action_type') or request.get('action') or ''}",
        f"target={request.get('target') or ''}",
        f"port={request.get('port') or ''}",
    ]
    if request.get("timeout_seconds"):
        lines.append(f"timeout={request.get('timeout_seconds')}")
    for key, value in sorted((request.get("options") or {}).items()):
        lines.append(f"option.{key}={value}")
    return "\n".join(lines)


def store_metasploit_scan_result(
    user_id: int,
    result: dict[str, object],
    normalized: dict,
    proposal_id: str,
    artifact_ref: str,
) -> dict:
    validation_state = str(normalized.get("validation_state") or "INCONCLUSIVE")
    status = "completed" if result.get("success") is True else "failed"
    return add_finding(
        user_id=user_id,
        finding={
            "source": "metasploit",
            "target": result.get("target"),
            "target_key": normalize_target_key(result.get("target")),
            "status": status,
            "summary": normalized.get("summary"),
            "risk_level": "high" if validation_state == "VALIDATED" else ("info" if status == "completed" else "unknown"),
            "finding_count": 1 if validation_state == "VALIDATED" else 0,
            "raw_output": str(result.get("output") or result.get("error") or ""),
            "metasploit_evidence": normalized,
            "metadata": {
                "proposal_id": proposal_id,
                "artifact_ref": artifact_ref,
                "module": result.get("module"),
                "action_type": result.get("action_type"),
                "port": result.get("port"),
                "risk_tier": result.get("risk_tier"),
                "expected_effect": result.get("expected_effect"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "returncode": result.get("returncode"),
                "error_type": result.get("error_type"),
            },
        },
    )


def _format_metasploit_options(options: dict) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(options.items())) if options else "none"


def _format_metasploit_timestamp(value: object) -> str:
    if hasattr(value, "astimezone"):
        return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    return "unknown"


def _metasploit_service_label(port: int) -> str:
    return {80: "HTTP", 443: "HTTPS"}.get(int(port or 0), "Custom service")


def _metasploit_validation_name(module: str) -> str:
    if module == "auxiliary/scanner/http/http_version":
        return "HTTP service fingerprint check"
    return module or "unknown"


def store_prowler_scan_result(user_id: int, result: dict[str, object], evidence: dict | None = None) -> dict:
    evidence = evidence or {}
    summary = summarize_prowler_evidence(evidence) if evidence else {}
    status = "completed" if result.get("success") is True else "failed"
    provider = str(result.get("provider") or evidence.get("provider") or "")
    cloud_context = str(result.get("cloud_context") or evidence.get("cloud_context") or f"standalone-{provider}") if provider else "unknown-cloud-context"
    return add_finding(
        user_id=user_id,
        finding={
            "source": "prowler",
            "target": cloud_context,
            "target_key": normalize_target_key(cloud_context),
            "provider": provider,
            "cloud_context": cloud_context,
            "status": status,
            "summary": (
                f"Prowler recorded {int(summary.get('finding_count') or 0)} scanner-reported cloud posture finding(s) for {provider.upper()} context {cloud_context}."
                if result.get("success") is True
                else _safe_prowler_failure_text(result, provider or "unknown")
            ),
            "risk_level": "info" if result.get("success") is True else "unknown",
            "finding_count": int(summary.get("finding_count") or 0),
            "raw_output": "",
            "prowler_evidence": evidence,
            "prowler_summary": summary,
            "metadata": {
                "returncode": result.get("returncode"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "command": result.get("command"),
                "working_directory": result.get("working_directory"),
                "output_dir": result.get("output_dir"),
                "output_files": result.get("output_files"),
                "provider": provider,
                "cloud_context": cloud_context,
                "error": result.get("error"),
                "error_type": result.get("error_type"),
                "parser": "prowler-json-ocsf",
            },
        },
    )


def store_gitleaks_scan_result(user_id: int, result: dict[str, object], evidence: dict | None = None) -> dict:
    evidence = evidence or {}
    summary = summarize_gitleaks_evidence(evidence) if evidence else {}
    finding_count = int(summary.get("finding_count") or 0)
    status = "completed" if result.get("success") is True else "failed"
    target = str(result.get("target") or evidence.get("scan_root") or "")
    return add_finding(
        user_id=user_id,
        finding={
            "source": "gitleaks",
            "target": target,
            "target_key": normalize_target_key(target),
            "status": status,
            "summary": (
                f"Gitleaks recorded {finding_count} redacted secret-exposure finding(s)."
                if result.get("success") is True
                else str(result.get("error") or "Gitleaks secret scan failed.")
            ),
            "risk_level": "high" if finding_count else ("info" if result.get("success") is True else "unknown"),
            "finding_count": finding_count,
            "raw_output": "",
            "gitleaks_evidence": evidence,
            "gitleaks_summary": summary,
            "metadata": {
                "returncode": result.get("returncode"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "command": result.get("command"),
                "working_directory": result.get("working_directory"),
                "error": result.get("error"),
                "error_type": result.get("error_type"),
                "parser": "gitleaks-json",
            },
        },
    )


def store_gitleaks_secret_vault_records(raw_output: str, evidence: dict, assessment_id: str | int | None = None) -> dict:
    finding_count = int(evidence.get("finding_count") or 0)
    if finding_count <= 0:
        return evidence
    payloads = extract_gitleaks_vault_payloads(raw_output, scan_root=str(evidence.get("scan_root") or ""))
    if not payloads:
        raise EvidenceVaultUnavailable("Gitleaks produced findings without vault-storable secret payloads.")

    updated_findings = [dict(finding) for finding in evidence.get("findings") or []]
    for index, payload in enumerate(payloads):
        vault_record = store_secret_evidence(
            assessment_id=str(assessment_id) if assessment_id is not None else None,
            finding_reference=payload["finding_reference"],
            secret_payload=payload["secret_payload"],
        )
        if index < len(updated_findings):
            updated_findings[index]["evidence_id"] = vault_record["evidence_id"]
    return {**evidence, "findings": updated_findings}


def redact_gitleaks_result_for_public_state(result: dict[str, object]) -> dict[str, object]:
    public_result = dict(result)
    if public_result.get("json_output"):
        public_result["json_output"] = ""
        public_result["json_redacted"] = True
    return public_result


def _gitleaks_assessment_reference(assessment_context: dict | None) -> str:
    if assessment_context and assessment_context.get("assessment_id") is not None:
        return str(assessment_context.get("assessment_id"))
    return "standalone"


def _gitleaks_vaulted_findings(finding: dict) -> list[dict]:
    return [
        item
        for item in ((finding.get("gitleaks_evidence") or {}).get("findings") or [])
        if isinstance(item, dict) and str(item.get("evidence_id") or "").strip()
    ]


def _find_gitleaks_evidence_item(finding: dict, evidence_id: str) -> dict | None:
    for item in ((finding.get("gitleaks_evidence") or {}).get("findings") or []):
        if isinstance(item, dict) and str(item.get("evidence_id") or "") == str(evidence_id):
            return item
    return None


def _format_count_summary(counts: dict) -> str:
    return ", ".join(f"{key}: {count}" for key, count in sorted(counts.items())) if counts else "none"


def _highest_prowler_severity(values: object) -> str:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "info": 1}
    highest = ""
    highest_score = -1
    for value in values:
        text = str(value or "").strip()
        score = order.get(text.lower(), 0 if text else -1)
        if score > highest_score:
            highest = text
            highest_score = score
    return highest


def _top_failed_prowler_services(failed_findings: list[dict], limit: int = 3) -> list[str]:
    counts: dict[str, int] = {}
    for finding in failed_findings:
        service = str(finding.get("service") or "unknown").strip() or "unknown"
        counts[service] = counts.get(service, 0) + 1
    return [f"{service}: {count}" for service, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def _prowler_output_directory(provider: str) -> Path:
    return Path("data") / "prowler" / f"{provider}-{int(time.time())}"


def _load_prowler_evidence(result: dict[str, object], provider: str) -> dict:
    output_files = [Path(str(path)) for path in result.get("output_files") or [] if str(path).strip()]
    if not output_files:
        raise ProwlerParserError("Prowler JSON-OCSF output artifact was not found.")
    output_file = output_files[0]
    if not output_file.exists() or not output_file.is_file():
        raise ProwlerParserError("Prowler JSON-OCSF output artifact was not found.")
    return normalize_prowler_output(output_file.read_text(encoding="utf-8"), provider=provider)


def _prowler_cloud_context(provider: str, assessment_context: dict | None = None) -> str:
    if assessment_context:
        context_label = str(assessment_context.get("cloud_context") or "").strip()
        if context_label and context_label.lower() != provider:
            return context_label
        return f"assessment-{provider}"
    return f"standalone-{provider}"


def _prowler_assessment_provider_limitation(error: object) -> str:
    return (
        f"Invalid Prowler provider: {error}\n\n"
        "Assessment-mode Prowler currently accepts only aws, azure, or gcp as the assessment target value. "
        "Use a cloud-provider assessment target for this mission; richer cloud environment labels need a later UX pass."
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
            "observations": observations,
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
    is_inconclusive = is_nmap_assessment_inconclusive(parsed_output, result)
    if not parsed_output.get("target") and not parsed_output.get("host_status") and not open_ports and not parsed_output.get("duration"):
        summary = _safe_truncated_text(fallback_output)
        return render_scan_result_card(
            tool_name="Nmap",
            target=target,
            status="Complete" if result.get("success") is True else "Failed",
            summary=summary,
        )

    if is_inconclusive:
        findings = [
            "Target status could not be established.",
            "No conclusion about exposed ports, services, vulnerabilities, or security posture can be made from this run.",
        ]
    else:
        findings = (
            [f"{open_port.get('port')}/{open_port.get('protocol')} {open_port.get('service')}" for open_port in open_ports]
            if open_ports
            else ["No open ports found."]
        )
    host_status = parsed_output.get("host_status") or "Unknown"
    notes = parsed_output.get("risk_notes") or []
    summary_lines = (
        [
            "Assessment Result: Inconclusive",
            "Target status could not be established.",
            "No conclusion about exposed ports, services, vulnerabilities, or security posture can be made from this run.",
        ]
        if is_inconclusive
        else [_format_nmap_host_status(host_status)]
    )
    if notes and not is_inconclusive:
        summary_lines.extend(_format_nmap_notes(notes))
    return render_scan_result_card(
        tool_name="Nmap",
        target=target,
        status="Inconclusive" if is_inconclusive else ("Complete" if result.get("success") is True else "Failed"),
        elapsed=str(parsed_output.get("duration") or "") or None,
        risk="UNKNOWN / INCONCLUSIVE" if is_inconclusive else (str(parsed_output.get("risk_level") or "").upper() or None),
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


def _current_assessment_scan_context(context: ContextTypes.DEFAULT_TYPE, tool: str) -> dict | None:
    user_data = getattr(context, "user_data", None)
    if not isinstance(user_data, dict):
        return None
    assessment_context = user_data.get(ASSESSMENT_SCAN_CONTEXT_KEY)
    if not isinstance(assessment_context, dict):
        return None
    if str(assessment_context.get("tool") or "").lower() != tool:
        return None
    return dict(assessment_context)


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
    return apply_nmap_assessment_interpretation(parsed_output, result)


def store_successful_nmap_finding(user_id: int, result: dict[str, object]) -> dict | None:
    if result.get("success") is not True:
        return None

    parsed_output = parse_nmap_result(result)
    return store_parsed_nmap_finding(user_id=user_id, parsed_output=parsed_output, source="nmap")


def store_parsed_nmap_finding(user_id: int, parsed_output: dict, source: str) -> dict:
    assessed_output = dict(parsed_output)
    assessed_output.update(assess_nmap_ports(assessed_output.get("open_ports", [])))
    assessed_output = apply_nmap_assessment_interpretation(assessed_output)
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
            "assessment_result": assessed_output.get("assessment_result"),
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

    if query.data and query.data.startswith(f"{SCAN_RECOVERY_CALLBACK_PREFIX}:"):
        user_id = update.effective_user.id if update.effective_user is not None else None
        if user_id is None:
            await query.edit_message_text("Unable to identify Telegram user.")
            return
        await _handle_scan_recovery_callback(query, user_id, context)
        return

    if query.data and query.data.startswith(f"{AI_SUMMARY_CALLBACK_PREFIX}:"):
        user_id = update.effective_user.id if update.effective_user is not None else None
        if user_id is None:
            await query.edit_message_text("Unable to identify Telegram user.")
            return
        await _handle_scan_ai_summary_callback(query, user_id)
        return

    if query.data and _is_gitleaks_evidence_callback(str(query.data)):
        user_id = update.effective_user.id if update.effective_user is not None else None
        if user_id is None:
            await query.edit_message_text("Unable to identify Telegram user.")
            return
        await _handle_gitleaks_evidence_vault_callback(query, user_id)
        return

    if query.data and str(query.data).startswith(f"{METASPLOIT_CALLBACK_PREFIX}:"):
        user_id = update.effective_user.id if update.effective_user is not None else None
        if user_id is None:
            await query.edit_message_text("Unable to identify Telegram user.")
            return
        await _handle_metasploit_callback(query, user_id, context)
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

    if scan_type == "tshark":
        from app.bot.handlers.upload import build_tshark_mode_keyboard, build_tshark_mode_text, clear_upload_state

        clear_upload_state(user_id)
        await query.edit_message_text(build_tshark_mode_text(), reply_markup=build_tshark_mode_keyboard())
        return

    if scan_type == "metasploit":
        readiness = await asyncio.to_thread(check_metasploit_readiness, run_version_check=False)
        if readiness.get("ready") is not True:
            await query.edit_message_text(build_metasploit_readiness_failure_text(readiness))
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

    if scan_type == "playwright":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_playwright_target_prompt())
        return

    if scan_type == "ffuf":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_ffuf_target_prompt())
        return

    if scan_type == "testssl":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_testssl_target_prompt())
        return

    if scan_type == "metasploit":
        await query.edit_message_text(
            build_metasploit_mode_text(),
            reply_markup=build_metasploit_mode_keyboard(scan_request.id),
        )
        return

    if scan_type == "gitleaks":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_gitleaks_target_prompt())
        return

    if scan_type == "prowler":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_prowler_provider_prompt())
        return

    if scan_type == "metasploit":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_metasploit_request_prompt())
        return

    await query.edit_message_text(build_scan_created_text(scan_type))


async def _handle_scan_recovery_callback(query: object, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    data = str(getattr(query, "data", "") or "")
    parts = data.split(":", 2)
    if len(parts) != 3:
        await query.edit_message_text("Unsupported scan recovery action.")
        return

    action, token = parts[1], parts[2]
    payload = _get_scan_recovery_context(token, user_id)
    if payload is None:
        await query.edit_message_text("Scan recovery action was not found or has expired.")
        return

    tool = str(payload.get("tool") or "").strip().lower()
    if tool not in SUPPORTED_SCAN_TYPES:
        await query.edit_message_text("Unsupported scan type.")
        return

    if action == "menu":
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        await query.edit_message_text(build_scan_text(), reply_markup=build_scan_type_keyboard())
        return

    if action in {"edit_target", "edit_input"}:
        _restore_recovery_scan_request(user_id, context, payload)
        target = str(payload.get("target") or "").strip()
        prompt = "Send corrected input." if action == "edit_input" else f"Current target:\n\n{target or 'unknown'}\n\nSend a replacement target."
        await query.edit_message_text(prompt)
        return

    if action != "rerun":
        await query.edit_message_text("Unsupported scan recovery action.")
        return

    message = getattr(query, "message", None)
    reply_text = getattr(message, "reply_text", None)
    if reply_text is None:
        await query.edit_message_text("Unable to re-run scan from this message.")
        return

    _restore_recovery_scan_request(user_id, context, payload)
    target = str(payload.get("target") or "")
    await query.edit_message_text(f"Re-running {tool.upper()} scan...")
    synthetic_update = type(
        "ScanRecoveryUpdate",
        (),
        {
            "message": type(
                "ScanRecoveryMessage",
                (),
                {"text": target, "reply_text": reply_text},
            )(),
            "effective_user": type("ScanRecoveryUser", (), {"id": user_id})(),
        },
    )()
    await scan_target_handler(synthetic_update, context)


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

    if scan_request.scan_type == "playwright":
        await _handle_playwright_target(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type == "ffuf":
        await _handle_ffuf_target(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type == "testssl":
        await _handle_testssl_target(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type == "gitleaks":
        await _handle_gitleaks_target(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type == "prowler":
        await _handle_prowler_provider(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type == "metasploit":
        await _handle_metasploit_request(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type != "nmap":
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    target = update.message.text or ""
    try:
        normalized_target = normalize_for_nmap(target)
    except ValueError as exc:
        await update.message.reply_text(
            f"Invalid NMAP target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="nmap",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "nmap"),
            ),
        )
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
        await update.message.reply_text(
            f"Invalid NMAP target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="nmap",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "nmap"),
            ),
        )
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
        reply_markup=_build_scan_outcome_actions(
            user_id=user_id,
            tool="nmap",
            target=target,
            outcome=(
                "failed"
                if (finding and is_nmap_assessment_inconclusive(finding, result))
                else ("success" if result.get("success") is True else "failed")
            ),
            finding_id=finding.get("id") if finding else None,
            assessment_context=assessment_context,
        ),
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


async def _send_playwright_ai_assessment(message: object, finding: dict) -> None:
    progress_message = await message.reply_text("Generating Playwright AI assessment...")
    assessment_lines = await asyncio.to_thread(generate_playwright_ai_assessment, finding)
    if assessment_lines == PLAYWRIGHT_AI_FALLBACK_LINES:
        await safe_edit_text(progress_message, "Playwright AI assessment unavailable.", context="Playwright AI assessment status")
        await message.reply_text("\n".join(assessment_lines))
        return

    await safe_edit_text(progress_message, "AI assessment ready.", context="Playwright AI assessment status")
    assessment_text = render_ai_summary_card(assessment_lines, title="Playwright AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _send_ffuf_ai_assessment(message: object, finding: dict) -> None:
    progress_message = await message.reply_text("Generating ffuf AI assessment...")
    assessment_lines = await asyncio.to_thread(generate_ffuf_ai_assessment, finding)
    if assessment_lines == FFUF_AI_FALLBACK_LINES:
        await safe_edit_text(progress_message, "ffuf AI assessment unavailable.", context="ffuf AI assessment status")
        await message.reply_text("\n".join(assessment_lines))
        return

    await safe_edit_text(progress_message, "AI assessment ready.", context="ffuf AI assessment status")
    assessment_text = render_ai_summary_card(assessment_lines, title="ffuf AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _send_testssl_ai_assessment(message: object, finding: dict) -> None:
    progress_message = await message.reply_text("Generating testssl.sh AI assessment...")
    assessment_lines = await asyncio.to_thread(generate_testssl_ai_assessment, finding)
    if assessment_lines == TESTSSL_AI_FALLBACK_LINES:
        await safe_edit_text(progress_message, "testssl.sh AI assessment unavailable.", context="testssl.sh AI assessment status")
        await message.reply_text("\n".join(assessment_lines))
        return

    await safe_edit_text(progress_message, "AI assessment ready.", context="testssl.sh AI assessment status")
    assessment_text = render_ai_summary_card(assessment_lines, title="testssl.sh AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _send_gitleaks_ai_assessment(message: object, finding: dict) -> None:
    progress_message = await message.reply_text("Generating Gitleaks AI assessment...")
    assessment_lines = await asyncio.to_thread(generate_gitleaks_ai_assessment, finding)
    if assessment_lines == GITLEAKS_AI_FALLBACK_LINES:
        await safe_edit_text(progress_message, "Gitleaks AI assessment unavailable.", context="Gitleaks AI assessment status")
        await message.reply_text("\n".join(assessment_lines))
        return

    await safe_edit_text(progress_message, "AI assessment ready.", context="Gitleaks AI assessment status")
    assessment_text = render_ai_summary_card(assessment_lines, title="Gitleaks AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _send_prowler_ai_assessment(message: object, finding: dict) -> None:
    evidence = finding.get("prowler_evidence") or {}
    if not evidence.get("findings"):
        await message.reply_text("No parsed Prowler checks were available from this run.")
        return

    progress_message = await message.reply_text("Generating Prowler AI assessment...")
    assessment_lines = await asyncio.to_thread(generate_prowler_ai_assessment, finding)
    if assessment_lines == PROWLER_AI_FALLBACK_LINES:
        await safe_edit_text(progress_message, "Prowler AI assessment unavailable.", context="Prowler AI assessment status")
        await message.reply_text("\n".join(assessment_lines))
        return

    await safe_edit_text(progress_message, "AI assessment ready.", context="Prowler AI assessment status")
    assessment_text = render_ai_summary_card(assessment_lines, title="Prowler AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _send_metasploit_ai_assessment(message: object, finding: dict) -> None:
    evidence = finding.get("metasploit_evidence") or {}
    if not evidence:
        await message.reply_text("No normalized Metasploit validation evidence was available from this run.")
        return

    progress_message = await message.reply_text("Generating Metasploit AI assessment...")
    assessment_lines = await asyncio.to_thread(generate_metasploit_ai_assessment, finding)
    if assessment_lines == METASPLOIT_AI_FALLBACK_LINES:
        await safe_edit_text(progress_message, "Metasploit AI assessment unavailable.", context="Metasploit AI assessment status")
        await message.reply_text("\n".join(assessment_lines))
        return

    await safe_edit_text(progress_message, "AI assessment ready.", context="Metasploit AI assessment status")
    assessment_text = render_ai_summary_card(assessment_lines, title="Metasploit AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _handle_ffuf_target(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    scan_request_id: str,
) -> None:
    if update.message is None:
        return

    target = update.message.text or ""
    try:
        display_target = normalize_for_ffuf(target)
    except ValueError as exc:
        await update.message.reply_text(
            f"Invalid ffuf target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="ffuf",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "ffuf"),
            ),
        )
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    investigation = get_or_create_latest_open_investigation(user_id=user_id, target=display_target)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=display_target,
        event_type="ffuf_scan_started",
        tool="ffuf",
        status="started",
        summary="ffuf hidden-content discovery started",
    )
    progress_card = ScanProgressCard(update.message, "ffuf Discovery", display_target)
    await progress_card.start("Launching discovery...")

    try:
        result = await asyncio.to_thread(run_ffuf_scan, target)
    except ValueError as exc:
        await progress_card.fail(str(exc))
        add_investigation_event(
            investigation_id=investigation["id"],
            user_id=user_id,
            target=display_target,
            event_type="ffuf_scan_failed",
            tool="ffuf",
            status="failed",
            summary="ffuf hidden-content discovery failed",
        )
        await update.message.reply_text(
            f"Invalid ffuf target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="ffuf",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "ffuf"),
            ),
        )
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result["target"]),
        result=result,
    )
    observations = parse_ffuf_output(str(result.get("output") or "")) if result.get("output") else []
    finding = store_ffuf_scan_result(user_id=user_id, result=result, observations=observations)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=str(result["target"]),
        event_type="ffuf_scan_completed" if result.get("success") is True else "ffuf_scan_failed",
        tool="ffuf",
        status="completed" if result.get("success") is True else "failed",
        summary="ffuf hidden-content discovery completed" if result.get("success") is True else "ffuf hidden-content discovery failed",
        metadata={"finding_id": finding.get("id"), "result_count": len(observations)},
    )
    assessment_context = _pop_assessment_scan_context(context, "ffuf")
    _record_assessment_scan(assessment_context, tool="ffuf", result=result, finding=finding)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    if result.get("success") is True:
        await progress_card.complete()
    else:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
    await update.message.reply_text(
        build_ffuf_result_text(result, observations),
        reply_markup=_build_scan_outcome_actions(
            user_id=user_id,
            tool="ffuf",
            target=target,
            outcome="success" if result.get("success") is True else "failed",
            finding_id=finding.get("id") if result.get("success") is True else None,
            assessment_context=assessment_context,
        ),
    )
    if result.get("success") is True:
        await _send_ffuf_ai_assessment(update.message, finding)
    await _send_assessment_dashboard(update.message, assessment_context)


async def _handle_testssl_target(
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
        await update.message.reply_text(
            f"Invalid testssl.sh target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="testssl",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "testssl"),
            ),
        )
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    investigation = get_or_create_latest_open_investigation(user_id=user_id, target=display_target)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=display_target,
        event_type="testssl_scan_started",
        tool="testssl",
        status="started",
        summary="testssl.sh TLS assessment started",
    )
    progress_card = ScanProgressCard(update.message, "testssl.sh TLS", display_target)
    await progress_card.start("Launching scan...")
    await progress_card.start_auto_refresh("Running scan...", interval_seconds=5)
    assessment_context = _pop_assessment_scan_context(context, "testssl")

    try:
        result = await asyncio.to_thread(run_testssl_scan, target)
    except ValueError as exc:
        await progress_card.fail(str(exc))
        await update.message.reply_text(
            f"Invalid testssl.sh target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="testssl",
                target=target,
                outcome="invalid",
                assessment_context=assessment_context,
            ),
        )
        _record_assessment_scan(
            assessment_context,
            tool="testssl",
            result={"success": False, "target": display_target, "error": str(exc)},
        )
        await _send_assessment_dashboard(update.message, assessment_context)
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return
    finally:
        await progress_card.stop_auto_refresh()

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result.get("target") or display_target),
        result=result,
    )
    evidence = {}
    parser_error = None
    if result.get("success") is True:
        try:
            evidence = normalize_testssl_output(str(result.get("json_output") or ""), target=str(result.get("target") or display_target))
        except TestsslParserError as exc:
            parser_error = str(exc)
            result = {**result, "success": False, "error": parser_error, "error_type": "parser_error"}

    finding = store_testssl_scan_result(user_id=user_id, result=result, evidence=evidence)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=str(result.get("target") or display_target),
        event_type="testssl_scan_completed" if result.get("success") is True else "testssl_scan_failed",
        tool="testssl",
        status="completed" if result.get("success") is True else "failed",
        summary="testssl.sh TLS assessment completed" if result.get("success") is True else "testssl.sh TLS assessment failed",
        metadata={"finding_id": finding.get("id"), "parser_error": parser_error},
    )
    _record_assessment_scan(assessment_context, tool="testssl", result=result, finding=finding)
    if result.get("success") is True:
        await progress_card.complete()
    else:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
    await update.message.reply_text(
        build_testssl_result_text(result, evidence),
        reply_markup=_build_scan_outcome_actions(
            user_id=user_id,
            tool="testssl",
            target=target,
            outcome="success" if result.get("success") is True else "failed",
            finding_id=finding.get("id") if result.get("success") is True else None,
            assessment_context=assessment_context,
        ),
    )
    if result.get("success") is True:
        await _send_testssl_ai_assessment(update.message, finding)
    await _send_assessment_dashboard(update.message, assessment_context)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)


async def _handle_gitleaks_target(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    scan_request_id: str,
) -> None:
    if update.message is None:
        return

    scope = update.message.text or ""
    investigation = get_or_create_latest_open_investigation(user_id=user_id, target=scope)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=scope,
        event_type="gitleaks_scan_started",
        tool="gitleaks",
        status="started",
        summary="Gitleaks secret scan started",
    )
    progress_card = ScanProgressCard(update.message, "Gitleaks Secrets", scope)
    await progress_card.start("Launching scan...")
    await progress_card.start_auto_refresh("Running scan...", interval_seconds=5)
    assessment_context = _pop_assessment_scan_context(context, "gitleaks")

    try:
        result = await asyncio.to_thread(run_gitleaks_scan, scope)
    except ValueError as exc:
        await progress_card.fail(str(exc))
        add_investigation_event(
            investigation_id=investigation["id"],
            user_id=user_id,
            target=scope,
            event_type="gitleaks_scan_failed",
            tool="gitleaks",
            status="failed",
            summary="Gitleaks secret scan failed",
        )
        await update.message.reply_text(
            f"Invalid Gitleaks scope: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="gitleaks",
                target=scope,
                outcome="invalid",
                assessment_context=assessment_context,
            ),
        )
        _record_assessment_scan(
            assessment_context,
            tool="gitleaks",
            result={"success": False, "target": scope, "error": str(exc)},
        )
        await _send_assessment_dashboard(update.message, assessment_context)
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return
    finally:
        await progress_card.stop_auto_refresh()

    evidence = {}
    parser_error = None
    if result.get("success") is True:
        try:
            evidence = normalize_gitleaks_output(str(result.get("json_output") or "[]"), scan_root=str(result.get("target") or scope))
            evidence = store_gitleaks_secret_vault_records(
                str(result.get("json_output") or "[]"),
                evidence,
                assessment_id=assessment_context.get("assessment_id") if assessment_context else None,
            )
        except GitleaksParserError as exc:
            parser_error = str(exc)
            result = {**result, "success": False, "error": parser_error, "error_type": "parser_error"}
            evidence = {}
        except EvidenceVaultUnavailable as exc:
            parser_error = str(exc)
            result = {**result, "success": False, "error": parser_error, "error_type": "evidence_vault_unavailable"}
            evidence = {}

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result.get("target") or scope),
        result=redact_gitleaks_result_for_public_state(result),
    )

    finding = store_gitleaks_scan_result(user_id=user_id, result=result, evidence=evidence)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=str(result.get("target") or scope),
        event_type="gitleaks_scan_completed" if result.get("success") is True else "gitleaks_scan_failed",
        tool="gitleaks",
        status="completed" if result.get("success") is True else "failed",
        summary="Gitleaks secret scan completed" if result.get("success") is True else "Gitleaks secret scan failed",
        metadata={"finding_id": finding.get("id"), "finding_count": finding.get("finding_count"), "parser_error": parser_error},
    )
    _record_assessment_scan(assessment_context, tool="gitleaks", result=result, finding=finding)
    if result.get("success") is True:
        await progress_card.complete()
    else:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
    await update.message.reply_text(
        build_gitleaks_result_text(result, evidence),
        reply_markup=(
            _combine_inline_keyboards(
                build_gitleaks_result_actions(finding, assessment_context, user_id=user_id),
                _build_scan_outcome_actions(
                    user_id=user_id,
                    tool="gitleaks",
                    target=scope,
                    outcome="success",
                    assessment_context=assessment_context,
                ),
            )
            if result.get("success") is True
            else _build_scan_outcome_actions(
                user_id=user_id,
                tool="gitleaks",
                target=scope,
                outcome="failed",
                assessment_context=assessment_context,
            )
        ),
    )
    if result.get("success") is True:
        await _send_gitleaks_ai_assessment(update.message, finding)
    await _send_assessment_dashboard(update.message, assessment_context)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)


async def _handle_prowler_provider(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    scan_request_id: str,
) -> None:
    if update.message is None:
        return

    provider_input = update.message.text or ""
    try:
        provider = normalize_prowler_provider(provider_input)
    except ValueError as exc:
        assessment_context = _pop_assessment_scan_context(context, "prowler")
        error_text = _prowler_assessment_provider_limitation(exc) if assessment_context else f"Invalid Prowler provider: {exc}"
        await update.message.reply_text(
            error_text,
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="prowler",
                target=provider_input,
                outcome="invalid",
                assessment_context=assessment_context,
            ),
        )
        _record_assessment_scan(
            assessment_context,
            tool="prowler",
            result={"success": False, "target": provider_input, "provider": provider_input, "error": str(exc)},
        )
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    assessment_context = _pop_assessment_scan_context(context, "prowler")
    cloud_context = _prowler_cloud_context(provider, assessment_context)
    investigation = get_or_create_latest_open_investigation(user_id=user_id, target=cloud_context)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=cloud_context,
        event_type="prowler_scan_started",
        tool="prowler",
        status="started",
        summary=f"Prowler cloud posture scan started for {provider.upper()} context {cloud_context}",
        metadata={"provider": provider, "cloud_context": cloud_context},
    )
    progress_card = ScanProgressCard(update.message, "Prowler Cloud Posture", cloud_context)
    await progress_card.start("Launching scan...")
    await progress_card.start_auto_refresh("Running scan...", interval_seconds=10)

    output_dir = _prowler_output_directory(provider)
    output_filename = f"mongrel-prowler-{provider}"
    try:
        result = await asyncio.to_thread(run_prowler_scan, provider, output_dir, output_filename)
        result = {**result, "provider": provider, "cloud_context": cloud_context}
    finally:
        await progress_card.stop_auto_refresh()

    evidence = {}
    parser_error = None
    if result.get("success") is True:
        try:
            evidence = _load_prowler_evidence(result, provider)
            evidence["cloud_context"] = cloud_context
        except ProwlerParserError as exc:
            parser_error = str(exc)
            result = {**result, "success": False, "error": parser_error, "error_type": "parser_error"}

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=cloud_context,
        result=result,
    )
    finding = store_prowler_scan_result(user_id=user_id, result=result, evidence=evidence)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=cloud_context,
        event_type="prowler_scan_completed" if result.get("success") is True else "prowler_scan_failed",
        tool="prowler",
        status="completed" if result.get("success") is True else "failed",
        summary=f"Prowler cloud posture scan completed for {provider.upper()} context {cloud_context}" if result.get("success") is True else "Prowler cloud posture scan failed",
        metadata={"finding_id": finding.get("id"), "finding_count": finding.get("finding_count"), "parser_error": parser_error, "provider": provider, "cloud_context": cloud_context},
    )
    _record_assessment_scan(assessment_context, tool="prowler", result=result, finding=finding)
    if result.get("success") is True:
        await progress_card.complete()
    else:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
    await update.message.reply_text(
        build_prowler_result_text(result, evidence),
        reply_markup=_build_scan_outcome_actions(
            user_id=user_id,
            tool="prowler",
            target=provider_input,
            outcome="success" if result.get("success") is True else "failed",
            finding_id=finding.get("id") if result.get("success") is True else None,
            assessment_context=assessment_context,
        ),
    )
    if result.get("success") is True:
        await _send_prowler_ai_assessment(update.message, finding)
    await _send_assessment_dashboard(update.message, assessment_context)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)


async def _handle_metasploit_request(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    scan_request_id: str,
) -> None:
    if update.message is None:
        return
    mode = str(context.user_data.get(METASPLOIT_FLOW_MODE_KEY) or "manual")
    if mode == "guided_target":
        try:
            target = _normalize_metasploit_guided_target(update.message.text or "")
        except ValueError as exc:
            await update.message.reply_text(
                f"Invalid Metasploit target: {exc}",
                reply_markup=_build_scan_outcome_actions(
                    user_id=user_id,
                    tool="metasploit",
                    target=update.message.text or "",
                    outcome="invalid",
                    assessment_context=_current_assessment_scan_context(context, "metasploit"),
                ),
            )
            context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
            context.user_data.pop(METASPLOIT_FLOW_MODE_KEY, None)
            context.user_data.pop(METASPLOIT_GUIDED_CONTEXT_KEY, None)
            return
        context.user_data[METASPLOIT_GUIDED_CONTEXT_KEY] = {"target": target}
        context.user_data[METASPLOIT_FLOW_MODE_KEY] = "guided_service"
        await update.message.reply_text(
            build_metasploit_service_prompt(target),
            reply_markup=build_metasploit_service_keyboard(user_id, scan_request_id, target),
        )
        return
    if mode == "guided_custom_port":
        guided = context.user_data.get(METASPLOIT_GUIDED_CONTEXT_KEY) or {}
        target = str(guided.get("target") or "")
        try:
            port = _normalize_metasploit_guided_port(update.message.text or "")
        except ValueError as exc:
            await update.message.reply_text(
                f"Invalid Metasploit port: {exc}",
                reply_markup=_build_scan_outcome_actions(
                    user_id=user_id,
                    tool="metasploit",
                    target=update.message.text or "",
                    outcome="invalid",
                    assessment_context=_current_assessment_scan_context(context, "metasploit"),
                ),
            )
            return
        service = _metasploit_service_label(port)
        if not _metasploit_guided_supports_http_version(port):
            await update.message.reply_text("No allowlisted Metasploit validations are compatible with that service/port in guided mode.")
            return
        await update.message.reply_text(
            build_metasploit_validation_prompt(target, service, port),
            reply_markup=build_metasploit_validation_keyboard(user_id, scan_request_id, target, service, port),
        )
        return
    try:
        request = parse_metasploit_request_text(update.message.text or "")
    except (ValueError, TypeError) as exc:
        await update.message.reply_text(
            f"Invalid Metasploit validation request: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="metasploit",
                target=update.message.text or "",
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "metasploit"),
            ),
        )
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    assessment_context = _pop_assessment_scan_context(context, "metasploit")
    if assessment_context and not _metasploit_target_belongs_to_assessment(
        str(request.get("target") or ""),
        assessment_context,
    ):
        await update.message.reply_text(
            "Metasploit target is not part of this assessment's known target/assets. "
            "Add it explicitly or run standalone."
        )
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return
    await _create_and_send_metasploit_proposal(
        update.message,
        context,
        user_id,
        request,
        scan_request_id,
        assessment_context=assessment_context if isinstance(assessment_context, dict) else None,
    )


async def _create_and_send_metasploit_proposal(
    message: object,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    request: dict,
    scan_request_id: str,
    *,
    assessment_context: dict | None = None,
) -> None:
    proposal = propose_metasploit_action(
        user_id,
        request,
        assessment_context=assessment_context,
        reason="guided validation" if context.user_data.get(METASPLOIT_FLOW_MODE_KEY, "").startswith("guided") else None,
    )
    _metasploit_pending_context[proposal.id] = {
        "scan_request_id": scan_request_id,
        "assessment_context": assessment_context,
    }
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    context.user_data.pop(METASPLOIT_FLOW_MODE_KEY, None)
    context.user_data.pop(METASPLOIT_GUIDED_CONTEXT_KEY, None)
    await message.reply_text(
        build_metasploit_proposal_text(proposal),
        reply_markup=build_metasploit_proposal_keyboard(proposal.id),
    )


def _metasploit_target_belongs_to_assessment(target: str, assessment_context: dict) -> bool:
    requested = _comparison_host(target)
    if not requested:
        return False
    candidates = [
        str(assessment_context.get("primary_target") or ""),
        *(str(value or "") for value in assessment_context.get("known_assets") or []),
    ]
    assessment_id = assessment_context.get("assessment_id")
    if assessment_id is not None:
        candidates.extend(str(item.get("address") or "") for item in list_assessment_targets(int(assessment_id)))
    known_hosts = {_comparison_host(value) for value in candidates}
    return requested in known_hosts


def _comparison_host(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    parsed = urlsplit(text if "://" in text else f"//{text}")
    host = parsed.hostname or text.split("/", 1)[0].split(":", 1)[0]
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return host.rstrip(".")


def _normalize_metasploit_guided_target(value: str) -> str:
    raw = str(value or "").strip()
    if any(character in raw for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("target contains unsupported shell characters.")
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
    host = str(host or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("target must be a hostname or IP address.")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", host) or ".." in host or host.startswith("-") or host.endswith("-"):
            raise ValueError("target must be a valid hostname or IP address.")
        return host


def _normalize_metasploit_guided_port(value: object) -> int:
    try:
        port = int(str(value or "").strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("port must be an integer.") from exc
    if port < 1 or port > 65535:
        raise ValueError("port is outside the valid range.")
    return port


def _metasploit_guided_supports_http_version(port: int) -> bool:
    return (
        "auxiliary/scanner/http/http_version" in MODULE_POLICIES
        and int(port or 0) in {80, 443, 8080, 8443}
    )


def _build_guided_metasploit_request(*, target: str, service: str, port: int) -> dict:
    options = {"SSL": "true"} if int(port) in {443, 8443} or str(service).upper() == "HTTPS" else {}
    return build_metasploit_action_request(
        module="auxiliary/scanner/http/http_version",
        action_type="auxiliary_validation",
        target=target,
        port=port,
        options=options,
    )


async def _handle_metasploit_callback(query: object, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    data = str(getattr(query, "data", "") or "")
    parts = data.split(":")
    if len(parts) != 3:
        await query.edit_message_text("Unsupported Metasploit action.")
        return
    action, proposal_id = parts[1], parts[2]
    if action in {"guided", "manual"}:
        scan_request_id = proposal_id
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request_id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request_id
        context.user_data[METASPLOIT_FLOW_MODE_KEY] = "guided_target" if action == "guided" else "manual"
        prompt = build_metasploit_guided_target_prompt() if action == "guided" else build_metasploit_request_prompt()
        await query.edit_message_text(prompt)
        return
    if action in {"svc", "custom", "val"}:
        token_payload = _metasploit_guided_tokens.get(proposal_id)
        if not token_payload or token_payload.get("user_id") != user_id:
            await query.edit_message_text("Metasploit guided selection was not found or has expired.")
            return
        scan_request_id = str(token_payload.get("scan_request_id") or "")
        target = str(token_payload.get("target") or "")
        if action == "custom":
            mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request_id)
            context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request_id
            context.user_data[METASPLOIT_FLOW_MODE_KEY] = "guided_custom_port"
            context.user_data[METASPLOIT_GUIDED_CONTEXT_KEY] = {"target": target}
            await query.edit_message_text(f"Send the authorized service port for {target}.")
            return
        port = int(token_payload.get("port") or 0)
        service = str(token_payload.get("service") or _metasploit_service_label(port))
        if action == "svc":
            if not _metasploit_guided_supports_http_version(port):
                await query.edit_message_text("No allowlisted Metasploit validations are compatible with that service/port in guided mode.")
                return
            await query.edit_message_text(
                build_metasploit_validation_prompt(target, service, port),
                reply_markup=build_metasploit_validation_keyboard(user_id, scan_request_id, target, service, port),
            )
            return
        request = _build_guided_metasploit_request(target=target, service=service, port=port)
        assessment_context = _pop_assessment_scan_context(context, "metasploit")
        if assessment_context and not _metasploit_target_belongs_to_assessment(target, assessment_context):
            await query.edit_message_text(
                "Metasploit target is not part of this assessment's known target/assets. "
                "Add it explicitly or run standalone."
            )
            context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
            context.user_data.pop(METASPLOIT_FLOW_MODE_KEY, None)
            context.user_data.pop(METASPLOIT_GUIDED_CONTEXT_KEY, None)
            return
        message = getattr(query, "message", None)
        if message is None:
            await query.edit_message_text("Unable to create Metasploit proposal.")
            return
        await _create_and_send_metasploit_proposal(
            message,
            context,
            user_id,
            request,
            scan_request_id,
            assessment_context=assessment_context if isinstance(assessment_context, dict) else None,
        )
        return
    proposal = get_metasploit_proposal(proposal_id)
    if proposal is None:
        await query.edit_message_text("Metasploit proposal not found.")
        return
    if action == "details":
        try:
            await query.edit_message_text(
                build_metasploit_proposal_details_text(proposal),
                reply_markup=build_metasploit_proposal_keyboard(proposal.id),
            )
        except BadRequest as exc:
            if "message is not modified" in str(exc).lower():
                await query.answer("Proposal details are already shown.")
                return
            raise
        return
    if action == "reject":
        try:
            reject_metasploit_proposal(proposal_id, user_id=user_id)
        except MetasploitApprovalError as exc:
            await query.edit_message_text(f"Metasploit proposal rejection denied: {exc}")
            return
        pending = _metasploit_pending_context.pop(proposal_id, {})
        scan_request_id = pending.get("scan_request_id") if isinstance(pending, dict) else None
        if isinstance(scan_request_id, str):
            complete_scan_request(
                user_id=user_id,
                scan_request_id=scan_request_id,
                target=str((proposal.request or {}).get("target") or ""),
                result={"success": False, "error": "Metasploit validation proposal rejected.", "error_type": "rejected"},
            )
        await query.edit_message_text("Metasploit validation proposal rejected. No execution was performed.")
        return
    if action != "approve":
        await query.edit_message_text("Unsupported Metasploit action.")
        return
    try:
        approved = approve_metasploit_proposal(proposal_id, user_id=user_id, actor="human")
    except MetasploitApprovalError as exc:
        await query.edit_message_text(f"Metasploit approval denied: {exc}")
        return

    await query.edit_message_text("Metasploit proposal approved. Executing bounded validation...")
    result = await asyncio.to_thread(run_metasploit_validation, user_id=user_id, proposal_id=approved.id, request=approved.request)
    normalized = parse_metasploit_validation_result(result)
    pending = _metasploit_pending_context.pop(approved.id, {})
    assessment_context = pending.get("assessment_context") if isinstance(pending, dict) else None
    artifact_ref = _store_metasploit_artifact(assessment_context, result, normalized, approved.id)
    record_metasploit_result_reference(approved.id, artifact_ref)
    finding = store_metasploit_scan_result(user_id, result, normalized, approved.id, artifact_ref)

    scan_request_id = pending.get("scan_request_id") if isinstance(pending, dict) else None
    if isinstance(scan_request_id, str):
        complete_scan_request(user_id=user_id, scan_request_id=scan_request_id, target=str(result.get("target") or ""), result=result)
    _record_assessment_scan(assessment_context if isinstance(assessment_context, dict) else None, tool="metasploit", result=result, finding=finding)

    message = getattr(query, "message", None)
    reply_text = getattr(message, "reply_text", None)
    if reply_text is not None:
        await reply_text(
            build_metasploit_result_text(finding),
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="metasploit",
                target=_format_metasploit_recovery_request(approved.request),
                outcome="success" if result.get("success") is True else "failed",
                finding_id=finding.get("id") if result.get("success") is True else None,
                assessment_context=assessment_context if isinstance(assessment_context, dict) else None,
            ),
        )
        if normalized:
            await _send_metasploit_ai_assessment(message, finding)
        else:
            await reply_text("No normalized Metasploit validation evidence was available from this run.")
    else:
        await query.edit_message_text(build_metasploit_result_text(finding))


def _store_metasploit_artifact(assessment_context: object, result: dict[str, object], normalized: dict, proposal_id: str) -> str:
    content = "\n".join(
        [
            "Metasploit raw validation output",
            f"Proposal: {proposal_id}",
            f"Module: {result.get('module')}",
            f"Action: {result.get('action_type')}",
            f"Target: {result.get('target')}:{result.get('port')}",
            f"Validation state: {normalized.get('validation_state')}",
            "",
            str(result.get("output") or result.get("error") or ""),
        ]
    )
    if isinstance(assessment_context, dict) and assessment_context.get("assessment_id") is not None:
        artifact = add_assessment_artifact(
            int(assessment_context["assessment_id"]),
            artifact_type="metasploit_raw_output",
            title=f"Metasploit {result.get('module')} {result.get('target')}",
            content=content,
        )
        return f"assessment_artifact:{artifact.get('id')}"
    return "finding.raw_output"


async def _handle_playwright_target(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    scan_request_id: str,
) -> None:
    if update.message is None:
        return

    target = update.message.text or ""
    try:
        display_target = normalize_for_playwright(target)
    except ValueError as exc:
        await update.message.reply_text(
            f"Invalid Playwright target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="playwright",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "playwright"),
            ),
        )
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    investigation = get_or_create_latest_open_investigation(user_id=user_id, target=display_target)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=display_target,
        event_type="playwright_observation_started",
        tool="playwright",
        status="started",
        summary="Playwright passive browser observation started",
    )
    progress_card = ScanProgressCard(update.message, "Playwright Observation", display_target)
    await progress_card.start("Launching browser observation...")

    try:
        result = await asyncio.to_thread(run_playwright_observation, target)
    except ValueError as exc:
        await progress_card.fail(str(exc))
        add_investigation_event(
            investigation_id=investigation["id"],
            user_id=user_id,
            target=display_target,
            event_type="playwright_observation_failed",
            tool="playwright",
            status="failed",
            summary="Playwright passive browser observation failed",
        )
        await update.message.reply_text(
            f"Invalid Playwright target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="playwright",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "playwright"),
            ),
        )
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result["target"]),
        result=result,
    )
    observation = normalize_playwright_observation(result.get("output") or {}) if result.get("output") else {}
    finding = store_playwright_scan_result(user_id=user_id, result=result, observation=observation)
    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=str(result["target"]),
        event_type="playwright_observation_completed" if result.get("success") is True else "playwright_observation_failed",
        tool="playwright",
        status="completed" if result.get("success") is True else "failed",
        summary="Playwright passive browser observation completed" if result.get("success") is True else "Playwright passive browser observation failed",
        metadata={"finding_id": finding.get("id"), "final_url": observation.get("final_url")},
    )
    assessment_context = _pop_assessment_scan_context(context, "playwright")
    _record_assessment_scan(assessment_context, tool="playwright", result=result, finding=finding)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    if result.get("success") is True:
        await progress_card.complete()
    else:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
    await update.message.reply_text(
        build_playwright_result_text(result, observation),
        reply_markup=_build_scan_outcome_actions(
            user_id=user_id,
            tool="playwright",
            target=target,
            outcome="success" if result.get("success") is True else "failed",
            finding_id=finding.get("id") if result.get("success") is True else None,
            assessment_context=assessment_context,
        ),
    )
    if result.get("success") is True:
        await _send_playwright_ai_assessment(update.message, finding)
    await _send_assessment_dashboard(update.message, assessment_context)


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
        await update.message.reply_text(
            f"Invalid Katana target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="katana",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "katana"),
            ),
        )
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
        await update.message.reply_text(
            f"Invalid Katana target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="katana",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "katana"),
            ),
        )
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
        reply_markup=_build_scan_outcome_actions(
            user_id=user_id,
            tool="katana",
            target=target,
            outcome="success" if result.get("success") is True else "failed",
            finding_id=finding.get("id") if result.get("success") is True else None,
            assessment_context=assessment_context,
        ),
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
        await update.message.reply_text(
            f"Invalid httpx target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="httpx",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "httpx"),
            ),
        )
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
    await progress_card.start_auto_refresh("Running scan...", interval_seconds=5)

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
        await update.message.reply_text(
            f"Invalid httpx target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="httpx",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "httpx"),
            ),
        )
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
    elapsed_seconds = _parse_elapsed_seconds(result.get("elapsed_seconds"))
    if elapsed_seconds is not None:
        progress_card.started_at = time.monotonic() - elapsed_seconds
    if result.get("success") is True:
        await progress_card.complete()
    else:
        await progress_card.fail(str(result.get("error") or "Unknown error."))
    await update.message.reply_text(
        build_httpx_result_text(result, services),
        reply_markup=_build_scan_outcome_actions(
            user_id=user_id,
            tool="httpx",
            target=target,
            outcome="success" if result.get("success") is True else "failed",
            finding_id=finding.get("id") if result.get("success") is True else None,
            assessment_context=assessment_context,
        ),
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
        await update.message.reply_text(
            f"Invalid BBOT target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="bbot",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "bbot"),
            ),
        )
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    if not is_bbot_available():
        await update.message.reply_text(
            "BBOT is not installed or not available on PATH.",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="bbot",
                target=target,
                outcome="failed",
                assessment_context=_current_assessment_scan_context(context, "bbot"),
            ),
        )
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
        await update.message.reply_text(
            f"Invalid BBOT target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="bbot",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "bbot"),
            ),
        )
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
    if result.get("success") is True and not observations:
        sanitized_error = str(result.get("error") or "").strip()
        result = {
            **result,
            "success": False,
            "error": sanitized_error or "BBOT completed but produced no fresh normalized evidence for this run.",
            "error_type": "no_fresh_evidence",
        }
    elif result.get("success") is not True and observations:
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
        recon_summary = build_bbot_recon_summary_from_observations(
            observations,
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
    elapsed_seconds = _parse_elapsed_seconds(result.get("elapsed_seconds"))
    if elapsed_seconds is not None:
        progress_card.started_at = time.monotonic() - elapsed_seconds
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
            build_bbot_ai_assessment_keyboard(investigation["id"], finding.get("id"), user_id=user_id),
            _build_scan_outcome_actions(
                user_id=user_id,
                tool="bbot",
                target=target,
                outcome="success" if result.get("success") is True else "failed",
                assessment_context=assessment_context,
            ),
        )
        if result.get("success") is True
        or is_partial
        else _build_scan_outcome_actions(
            user_id=user_id,
            tool="bbot",
            target=target,
            outcome="failed",
            assessment_context=assessment_context,
        )
    )
    for index, chunk in enumerate(chunks):
        kwargs = {"reply_markup": keyboard} if keyboard is not None and index == len(chunks) - 1 else {}
        await update.message.reply_text(chunk, **kwargs)
    if is_successful_or_partial and observations:
        await _send_bbot_ai_assessment(
            update.message,
            user_id=user_id,
            investigation_id=investigation["id"],
            target=str(result.get("target") or display_target),
            observations=observations,
            recon_summary=recon_summary,
        )
    await _send_assessment_dashboard(update.message, assessment_context)


async def _send_bbot_ai_assessment(
    message: object,
    *,
    user_id: int,
    investigation_id: str,
    target: str,
    observations: list[dict] | None = None,
    recon_summary: str | None = None,
) -> None:
    progress_message = await message.reply_text("Generating BBOT AI assessment...")
    assessment_lines = await asyncio.to_thread(
        generate_bbot_ai_assessment,
        user_id,
        investigation_id=investigation_id,
        target=target,
        observations=observations,
        recon_summary=recon_summary,
    )
    fallback = assessment_lines == FALLBACK_LINES
    add_investigation_event(
        investigation_id=investigation_id,
        user_id=user_id,
        target=target,
        event_type="bbot_ai_assessment_fallback" if fallback else "bbot_ai_assessment_generated",
        tool="bbot",
        status="completed" if not fallback else "fallback",
        summary="BBOT AI Recon Assessment Generated" if not fallback else "BBOT AI Recon Assessment Fallback",
        metadata={"line_count": len(assessment_lines), "fallback": fallback, "automatic": True},
    )
    await safe_edit_text(
        progress_message,
        "BBOT AI assessment unavailable." if fallback else "AI assessment ready.",
        context="BBOT AI assessment status",
    )
    assessment_text = "\n".join(assessment_lines) if fallback else render_ai_summary_card(assessment_lines, title="BBOT AI Assessment")
    for chunk in split_report_text(assessment_text):
        await message.reply_text(chunk)


async def _handle_bbot_ai_assessment_callback(query: object, user_id: int) -> None:
    data = str(getattr(query, "data", "") or "")
    token = data.removeprefix(f"{BBOT_AI_ASSESSMENT_CALLBACK_PREFIX}:")
    token_payload = _bbot_ai_callback_tokens.get(token)
    if not token_payload or token_payload.get("user_id") != user_id:
        await query.edit_message_text("Stored BBOT AI request was not found or has expired.")
        return

    investigation_id = str(token_payload.get("investigation_id") or "")
    finding_id = str(token_payload.get("finding_id") or "") or None
    investigation = get_investigation(investigation_id, user_id)
    if investigation is None:
        await query.edit_message_text("Investigation not found for BBOT AI assessment.")
        return
    finding = get_user_finding(user_id, finding_id) if finding_id else None
    if finding_id and finding is None:
        await query.edit_message_text("Stored BBOT scan result not found for AI assessment.")
        return
    finding_observations = list(finding.get("observations") or []) if finding else None
    finding_target = str((finding or {}).get("target") or investigation.get("target") or "")
    finding_summary = (
        build_bbot_recon_summary_from_observations(finding_observations, target=finding_target)
        if finding_observations is not None
        else None
    )

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
            target=finding_target or investigation.get("target"),
            observations=finding_observations,
            recon_summary=finding_summary,
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


async def _handle_gitleaks_evidence_vault_callback(query: object, user_id: int) -> None:
    parsed = _parse_evidence_vault_callback(str(getattr(query, "data", "") or ""), user_id=user_id)
    if parsed is None:
        token = _callback_token_from_data(str(getattr(query, "data", "") or ""))
        if token:
            payload = _gitleaks_evidence_action_tokens.get(token) or {}
            reason = "wrong_user_or_missing_finding" if payload.get("user_id") is not None and int(payload.get("user_id")) != int(user_id) else "token_invalid"
            _record_reveal_attempt(
                evidence_id=str(payload.get("evidence_id") or f"token:{token}"),
                user_id=user_id,
                assessment_id=str(payload.get("assessment_id") or ""),
                outcome="denied",
                reason=reason,
            )
        await query.edit_message_text("Evidence access denied.")
        return

    action, token, assessment_id, finding_id, evidence_id = parsed
    if action == "cancel":
        _record_reveal_attempt(evidence_id=evidence_id, user_id=user_id, assessment_id=assessment_id, outcome="cancelled")
        await query.edit_message_text("Evidence reveal cancelled.")
        return

    _record_reveal_attempt(evidence_id=evidence_id, user_id=user_id, assessment_id=assessment_id, outcome="attempted")
    finding, denial_reason = _authorize_gitleaks_evidence_access(
        user_id=user_id,
        assessment_id=assessment_id,
        finding_id=finding_id,
        evidence_id=evidence_id,
    )
    if finding is None:
        _record_reveal_attempt(
            evidence_id=evidence_id,
            user_id=user_id,
            assessment_id=assessment_id,
            outcome="denied",
            reason=denial_reason,
        )
        await query.edit_message_text("Evidence access denied.")
        return

    if action == "view":
        await query.edit_message_text(
            build_gitleaks_evidence_warning_text(finding, evidence_id),
            reply_markup=build_gitleaks_evidence_warning_keyboard(token),
        )
        return

    if action != "reveal":
        await query.edit_message_text("Invalid evidence vault action.")
        return

    try:
        revealed = reveal_secret_evidence(
            evidence_id,
            reveal_metadata={"user_id": user_id, "assessment_id": assessment_id, "finding_id": finding_id},
        )
    except KeyError:
        _record_reveal_attempt(evidence_id=evidence_id, user_id=user_id, assessment_id=assessment_id, outcome="failed", reason="missing_evidence")
        await query.edit_message_text("Evidence access denied.")
        return
    except EvidenceVaultUnavailable:
        _record_reveal_attempt(evidence_id=evidence_id, user_id=user_id, assessment_id=assessment_id, outcome="failed", reason="vault_unavailable")
        await query.edit_message_text("Evidence vault is unavailable.")
        return
    except EvidenceVaultDecryptError:
        _record_reveal_attempt(evidence_id=evidence_id, user_id=user_id, assessment_id=assessment_id, outcome="failed", reason="decrypt_failed")
        await query.edit_message_text("Evidence vault decrypt failed.")
        return

    secret_value = str((revealed.get("secret_payload") or {}).get("secret") or "")
    if not secret_value:
        _record_reveal_attempt(evidence_id=evidence_id, user_id=user_id, assessment_id=assessment_id, outcome="failed", reason="empty_payload")
        await query.edit_message_text("Evidence vault payload was empty.")
        return

    _record_reveal_attempt(evidence_id=evidence_id, user_id=user_id, assessment_id=assessment_id, outcome="success")
    settings = get_settings()
    ttl_seconds = max(1, int(settings.evidence_reveal_ttl_seconds or 60))
    message = getattr(query, "message", None)
    if message is None:
        await query.edit_message_text("Evidence vault reveal is unavailable in this chat context.")
        return
    await query.edit_message_text("Sensitive evidence revealed in a short-lived message.")
    reveal_message = await message.reply_text(build_gitleaks_sensitive_secret_text(evidence_id, secret_value, ttl_seconds))
    _schedule_sensitive_message_delete(reveal_message, ttl_seconds)


def _parse_evidence_vault_callback(data: str, *, user_id: int) -> tuple[str, str, str, str, str] | None:
    parts = data.split(":", 1)
    if len(parts) != 2:
        return None
    prefix, token = parts
    actions = {
        GITLEAKS_EVIDENCE_VIEW_CALLBACK_PREFIX: "view",
        GITLEAKS_EVIDENCE_REVEAL_CALLBACK_PREFIX: "reveal",
        GITLEAKS_EVIDENCE_CANCEL_CALLBACK_PREFIX: "cancel",
    }
    action = actions.get(prefix)
    if action is None or not token:
        return None
    payload = _resolve_gitleaks_evidence_action_token(token, user_id=user_id)
    if payload is None:
        return None
    assessment_id = str(payload.get("assessment_id") or "")
    finding_id = str(payload.get("finding_id") or "")
    evidence_id = str(payload.get("evidence_id") or "")
    if not assessment_id or not finding_id or not evidence_id:
        return None
    return action, token, assessment_id, finding_id, evidence_id


def _is_gitleaks_evidence_callback(data: str) -> bool:
    return data.startswith(
        (
            f"{GITLEAKS_EVIDENCE_VIEW_CALLBACK_PREFIX}:",
            f"{GITLEAKS_EVIDENCE_REVEAL_CALLBACK_PREFIX}:",
            f"{GITLEAKS_EVIDENCE_CANCEL_CALLBACK_PREFIX}:",
        )
    )


def _callback_token_from_data(data: str) -> str:
    parts = data.split(":", 1)
    return parts[1] if len(parts) == 2 else ""


def _store_gitleaks_evidence_action_token(
    *,
    user_id: int | None,
    assessment_id: str,
    finding_id: str,
    evidence_id: str,
) -> str:
    _purge_expired_gitleaks_evidence_action_tokens()
    token = secrets.token_urlsafe(9)
    _gitleaks_evidence_action_tokens[token] = {
        "user_id": user_id,
        "assessment_id": assessment_id,
        "finding_id": finding_id,
        "evidence_id": evidence_id,
        "expires_at": time.monotonic() + GITLEAKS_EVIDENCE_TOKEN_TTL_SECONDS,
    }
    return token


def _resolve_gitleaks_evidence_action_token(token: str, *, user_id: int) -> dict[str, object] | None:
    payload = _gitleaks_evidence_action_tokens.get(token)
    if not payload:
        return None
    if float(payload.get("expires_at") or 0) < time.monotonic():
        _gitleaks_evidence_action_tokens.pop(token, None)
        return None
    token_user_id = payload.get("user_id")
    if token_user_id is not None and int(token_user_id) != int(user_id):
        return None
    return dict(payload)


def _purge_expired_gitleaks_evidence_action_tokens() -> None:
    now = time.monotonic()
    expired = [token for token, payload in _gitleaks_evidence_action_tokens.items() if float(payload.get("expires_at") or 0) < now]
    for token in expired:
        _gitleaks_evidence_action_tokens.pop(token, None)


def _authorize_gitleaks_evidence_access(
    *,
    user_id: int,
    assessment_id: str,
    finding_id: str,
    evidence_id: str,
) -> tuple[dict | None, str]:
    finding = get_user_finding(user_id=user_id, finding_id=finding_id)
    if finding is None:
        return None, "wrong_user_or_missing_finding"
    if finding.get("source") != "gitleaks":
        return None, "wrong_tool"
    if _find_gitleaks_evidence_item(finding, evidence_id) is None:
        return None, "evidence_not_in_finding"
    metadata = get_secret_evidence_metadata(evidence_id)
    if metadata is None:
        return None, "missing_evidence"
    if assessment_id == "standalone":
        if str(metadata.get("assessment_id") or "") != "":
            return None, "vault_assessment_mismatch"
        return finding, ""
    try:
        scan_assessment_id = int(assessment_id)
    except ValueError:
        return None, "invalid_assessment"
    if not any(
        str(scan.get("finding_id") or "") == finding_id and str(scan.get("tool") or "") == "gitleaks"
        for scan in list_assessment_scans(scan_assessment_id)
    ):
        return None, "wrong_assessment"
    if str(metadata.get("assessment_id") or "") != str(assessment_id):
        return None, "vault_assessment_mismatch"
    return finding, ""


def _record_reveal_attempt(*, evidence_id: str, user_id: int, assessment_id: str, outcome: str, reason: str = "") -> None:
    try:
        record_reveal_audit_event(
            evidence_id=evidence_id,
            user_id=user_id,
            assessment_id=assessment_id,
            outcome=outcome,
            reason=reason,
        )
    except Exception:
        logger.exception("Evidence reveal audit write failed: evidence_id=%s outcome=%s", evidence_id, outcome)


def _schedule_sensitive_message_delete(message: object, ttl_seconds: int) -> None:
    if not hasattr(message, "delete"):
        return
    try:
        asyncio.create_task(_delete_sensitive_message_later(message, ttl_seconds))
    except RuntimeError:
        logger.info("Sensitive evidence auto-delete could not be scheduled.")


async def _delete_sensitive_message_later(message: object, ttl_seconds: int) -> None:
    await asyncio.sleep(ttl_seconds)
    try:
        await message.delete()
    except Exception:
        logger.info("Sensitive evidence auto-delete failed.")


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
        await update.message.reply_text(
            f"Invalid Nuclei target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="nuclei",
                target=target,
                outcome="invalid",
                assessment_context=_current_assessment_scan_context(context, "nuclei"),
            ),
        )
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
        await _send_scan_message(
            message,
            f"Invalid Nuclei target: {exc}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="nuclei",
                target=target,
                outcome="invalid",
                assessment_context=assessment_context,
            ),
        )
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

    output = str(result.get("output") or "")
    is_partial_timeout = result.get("error_type") == "timeout" and bool(output.strip())

    if result.get("success") is not True and not is_partial_timeout:
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
        await _send_scan_message(
            message,
            f"Nuclei scan failed: {result.get('error') or 'Unknown error.'}",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="nuclei",
                target=target,
                outcome="failed",
                assessment_context=assessment_context,
            ),
        )
        _record_assessment_scan(assessment_context, tool="nuclei", result=result)
        await _send_assessment_dashboard(message, assessment_context)
        return

    if is_partial_timeout:
        await progress_card.update("Partial")
    else:
        await progress_card.complete()
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
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="nuclei",
                target=target,
                outcome="success",
                finding_id=finding.get("id"),
                assessment_context=assessment_context,
            ),
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
        await _send_scan_message(
            message,
            "Unable to parse Nuclei scan output.",
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="nuclei",
                target=target,
                outcome="failed",
                assessment_context=assessment_context,
            ),
        )
        _record_assessment_scan(
            assessment_context,
            tool="nuclei",
            result={**result, "success": False, "error": "Unable to parse Nuclei scan output."},
        )
        await _send_assessment_dashboard(message, assessment_context)
        return

    if not nuclei_findings:
        if is_partial_timeout:
            await _send_scan_message(
                message,
                "Nuclei scan partial: execution time limit reached before any parseable findings were collected.",
                reply_markup=_build_scan_outcome_actions(
                    user_id=user_id,
                    tool="nuclei",
                    target=target,
                    outcome="failed",
                    assessment_context=assessment_context,
                ),
            )
            _record_assessment_scan(assessment_context, tool="nuclei", result=result)
            await _send_assessment_dashboard(message, assessment_context)
            return
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
            reply_markup=_build_scan_outcome_actions(
                user_id=user_id,
                tool="nuclei",
                target=target,
                outcome="success",
                finding_id=finding.get("id"),
                assessment_context=assessment_context,
            ),
        )
        finding.setdefault("metadata", {})
        finding["metadata"].update({"elapsed": elapsed_label, "elapsed_seconds": int(elapsed_seconds), "scan_profile": "fast"})
        _record_assessment_scan(assessment_context, tool="nuclei", result=result, finding=finding)
        await _send_nuclei_ai_assessment(message, finding)
        await _send_assessment_dashboard(message, assessment_context)
        return

    from app.bot.handlers.upload import build_nuclei_import_success_text, store_nuclei_finding

    nuclei_metadata = {
        "elapsed": elapsed_label,
        "elapsed_seconds": int(elapsed_seconds),
        "scan_profile": "fast",
        "partial": is_partial_timeout,
        "timed_out": is_partial_timeout,
        "timeout_reason": result.get("timeout_reason") if is_partial_timeout else None,
    }
    finding = store_nuclei_finding(user_id=user_id, nuclei_findings=nuclei_findings, metadata=nuclei_metadata)
    add_investigation_event(
        investigation_id=investigation_id,
        user_id=user_id,
        target=str(finding.get("target") or display_target),
        event_type="nuclei_scan_completed",
        tool="nuclei",
        status="partial" if is_partial_timeout else "completed",
        summary="Nuclei scan partial - findings retained before timeout" if is_partial_timeout else "Nuclei scan completed",
        metadata={"finding_id": finding.get("id"), "finding_count": finding.get("finding_count")},
    )
    await _send_scan_message(
        message,
        build_nuclei_import_success_text(finding, elapsed=elapsed_label),
        reply_markup=_build_scan_outcome_actions(
            user_id=user_id,
            tool="nuclei",
            target=target,
            outcome="success",
            finding_id=finding.get("id"),
            assessment_context=assessment_context,
        ),
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
