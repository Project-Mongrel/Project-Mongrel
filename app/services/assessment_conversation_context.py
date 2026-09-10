import hashlib
import json
import re
from datetime import datetime
from typing import Any

from app.services.assessment_context import build_assessment_context
from app.services.assessment_conversation_store import (
    get_latest_assessment_conversation,
    get_user_conversation,
    list_recent_messages,
)
from app.services.assessment_guard import build_assessment_guard, build_guard_prompt_section
from app.services.assessment_store import get_user_assessment
from app.services.mongrel_self_knowledge import build_mongrel_self_knowledge_profile

CONTEXT_SCHEMA_VERSION = "assessment_conversation_context.v1"
DEFAULT_RECENT_MESSAGE_LIMIT = 8
MAX_FINDINGS_PER_TOOL = 5
MAX_ITEMS_PER_LIST = 10
MAX_ARTIFACTS = 8
MAX_TEXT_LENGTH = 1200
RAW_FIELD_NAMES = {
    "raw",
    "raw_output",
    "output",
    "stdout",
    "stderr",
    "console_output",
    "pcap",
    "pcap_data",
    "raw_pcap",
    "raw_packets",
    "packet_rows",
    "decrypted_secret",
    "raw_secret",
    "secret_payload",
}
SECRET_FIELD_ALLOWLIST = {"redacted_secret_preview", "secret_hash"}
TOOL_ALIASES = {
    "nmap": ("nmap", "port scan", "open port", "open ports"),
    "bbot": ("bbot",),
    "nuclei": ("nuclei",),
    "httpx": ("httpx", "http fingerprint"),
    "katana": ("katana", "crawl", "crawler"),
    "playwright": ("playwright", "browser", "dom"),
    "ffuf": ("ffuf", "fuzz", "fuzzing"),
    "testssl": ("testssl", "testssl.sh", "tls", "ssl"),
    "gitleaks": ("gitleaks", "secret", "secrets"),
    "prowler": ("prowler", "cloud", "aws", "azure", "gcp"),
    "metasploit": ("metasploit", "msfconsole", "session", "exploit validation"),
    "tshark": ("tshark", "traffic", "pcap", "packet", "packets", "dns", "tcp"),
}
CORRELATION_TERMS = ("correlation", "correlated", "capture during validation")
MONGREL_CAPABILITIES = {
    "nmap": "Observe host reachability, exposed ports, and service classifications; it does not prove application behavior or vulnerabilities.",
    "bbot": "Perform bounded reconnaissance and asset/discovery enumeration.",
    "nuclei": "Run approved template-based checks against a suitable target; matches are scanner evidence, not automatic exploit proof.",
    "httpx": "Probe and characterize HTTP/HTTPS endpoints and record reachable web responses, including status, titles, redirects, and technology hints; it does not itself establish vulnerability or misconfiguration.",
    "playwright": "Observe a web application through a browser, including rendered pages, DOM behavior, screenshots, and browser-visible flows.",
    "katana": "Crawl a web application to discover reachable URLs, paths, forms, and linked resources.",
    "ffuf": "Perform bounded web content/path discovery using an approved fuzzing profile.",
    "testssl.sh": "Assess observed TLS endpoints for protocol, cipher, and certificate behavior.",
    "gitleaks": "Scan authorized repositories or files for redacted secret-pattern matches; it does not prove a secret is valid or usable.",
    "prowler": "Evaluate supported cloud-provider checks; each result applies to its specific check, not the whole account posture.",
    "metasploit": "Perform explicitly approved, allowlisted validation; execution, target response, sessions, and compromise remain distinct facts.",
    "tshark": "Observe packet/capture metadata from uploaded PCAPs, standalone live capture, or capture during approved validation; it does not establish encryption security, exploitability, compromise, or application security.",
}
TELEGRAM_CAPABILITY_GUIDANCE = {
    "httpx": {
        "assessment_action": "Run httpx",
        "guidance": "Return to the assessment dashboard and choose Run httpx; Mongrel will collect the required target through its workflow.",
    },
    "tshark": {
        "assessment_action": "Run TShark",
        "choices": ["Capture During Validation", "Analyze PCAP", "Standalone Live Capture"],
        "guidance": "Return to the assessment dashboard and choose Run TShark, then choose the mode that matches the evidence gap.",
    },
}
WEB_QUESTION_TERMS = ("web", "website", "http", "https", "url", "endpoint", "service", "services")
TRAFFIC_QUESTION_TERMS = ("traffic", "packet", "packets", "pcap", "capture", "network conversation")
NOVICE_QUESTION_TERMS = ("novice", "beginner", "don't know", "do not know", "new to", "what should i do next")
WEB_SERVICE_PORTS = {80, 443, 8080, 8443}
PRODUCT_QUESTION_PATTERNS = (
    "what can mongrel", "what does mongrel do", "what are your tools", "what tools do you have",
    "what modes does mongrel", "difference between assessment mode", "can you run tools automatically",
)
RECOMMENDATION_QUESTION_TERMS = (
    "what next", "what is next", "do next", "run next", "should i run", "which tool", "which mongrel tool",
    "recommend", "what would you investigate", "would you investigate", "how do i investigate",
)
ASSESSMENT_QUESTION_TERMS = ("what did", "what was found", "what have we found", "current assessment", "assessment evidence", "scan result")
SECURITY_CONCEPT_TERMS = (
    "owasp", "ssrf", "injection", "path traversal", "file upload", "access control", "authentication",
    "lateral movement", "persistence", "privilege", "attack chain",
)
ATTACKER_QUESTION_TERMS = ("think like an attacker", "attacker", "attack path", "attack chain")
TOOL_EXPLANATION_TERMS = ("what does", "why would i use", "what can", "explain", "what is")
FOLLOW_UP_PATTERNS = (
    r"^(?:and\s+)?(?:why|why (?:that|this) one|which one|after that|what do you mean|what did you mean by that)\??$",
    r"^(?:and\s+)?what (?:will|would) that (?:tell|show|mean)(?: me)?\??$",
    r"^and (?:what about )?(?:port\s+)?\d{1,5}\??$",
)
PRIORITIZATION_TERMS = ("which one first", "what first", "prioriti", "highest priority", "most important")
COVERAGE_GAP_TERMS = ("anything else", "haven't we checked", "have not we checked", "not checked", "coverage gap", "what is missing")
SIGNIFICANCE_TERMS = ("anything worrying", "is that bad", "does that matter", "how serious", "why should i care")
UNCERTAINTY_TERMS = ("are we secure", "is it secure", "do we know it's vulnerable", "do we know it is vulnerable", "is it vulnerable", "are we safe")
SIMPLIFY_TERMS = ("like i'm new", "like i am new", "simply", "simple terms", "plain english", "beginner")


def build_assessment_conversation_context(
    *,
    user_id: int,
    assessment_id: int,
    question: str,
    conversation_id: str | None = None,
    recent_message_limit: int = DEFAULT_RECENT_MESSAGE_LIMIT,
) -> dict:
    assessment = get_user_assessment(user_id, assessment_id)
    if assessment is None:
        raise ValueError("Assessment not found for user.")

    assessment_context = build_assessment_context(assessment_id=assessment_id, user_id=user_id)
    conversation = _resolve_conversation(user_id, assessment_id, conversation_id)
    recent_messages = (
        list_recent_messages(user_id, conversation["id"], limit=recent_message_limit) if conversation is not None else []
    )
    selected_tools = detect_question_tools(question)
    question_intent = classify_assessment_conversation_intent(question, selected_tools=selected_tools)
    full_assessment = not selected_tools
    evidence = _build_evidence_context(assessment_context, selected_tools)
    provenance = _build_provenance(
        assessment_context=assessment_context,
        evidence=evidence,
        user_id=user_id,
        assessment_id=assessment_id,
        conversation=conversation,
        selected_tools=selected_tools,
        recent_messages=recent_messages,
        full_assessment=full_assessment,
    )
    context = {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "current_question": str(question or "").strip(),
        "question_intent": question_intent,
        "priority_rules": [
            "current_user_question",
            "stored_normalized_assessment_evidence",
            "assessment_artifacts_and_provenance",
            "stored_conversation_summary",
            "recent_conversation_messages",
        ],
        "evidence_precedence": (
            "Stored normalized assessment evidence is authoritative. Conversation history is interpretation, not evidence. "
            "Newer assessment evidence supersedes older assistant statements."
        ),
        "selection": {
            "mode": "full_assessment" if full_assessment else "tool_relevant",
            "selected_tools": selected_tools,
        },
        "conversation": {
            "id": conversation["id"] if conversation is not None else None,
            "summary": conversation.get("summary") if conversation is not None else None,
            "recent_messages": [_message_for_context(message) for message in recent_messages],
            "recent_message_limit": max(0, int(recent_message_limit or 0)),
        },
        "assessment_context": evidence,
        "mongrel_capabilities": MONGREL_CAPABILITIES,
        "mongrel_self_knowledge": build_mongrel_self_knowledge_profile(),
        "telegram_capability_guidance": TELEGRAM_CAPABILITY_GUIDANCE,
        "recommendation_context": _build_recommendation_context(
            question,
            assessment_context,
            question_intent=question_intent,
        ),
        "evidence_language_contract": [
            "Nmap port/service labels are classifications only and do not establish application behavior, vulnerability, exploitability, interception, or encryption quality.",
            "A scanned hostname and its resolved IP identify the same scanned endpoint unless stored evidence explicitly records independently discovered hosts; do not count them as two hosts.",
            "httpx characterizes observed HTTP endpoints and responses; it does not by itself establish vulnerability or misconfiguration.",
            "TShark reports only packet/capture facts actually present in normalized evidence and must not promise conclusions about encryption security, exploitability, compromise, or application security.",
            "The user-facing cloud assessment tool name is Prowler; never use legacy or combined internal cloud-tool aliases.",
        ],
        "truthfulness": {
            "guard": build_assessment_guard(assessment_context, question=question),
            "prompt_section": build_guard_prompt_section(assessment_context, question=question),
            "tool_boundaries": _tool_boundaries(),
        },
        "provenance": provenance,
    }
    context["evidence_context_digest"] = build_context_digest(context)
    return context


def classify_assessment_conversation_intent(question: str, *, selected_tools: list[str] | None = None) -> str:
    """Classify current intent without invoking the model; order resolves overlapping wording."""

    normalized = " ".join(str(question or "").lower().split())
    tools = selected_tools if selected_tools is not None else detect_question_tools(question)
    if any(pattern in normalized for pattern in PRODUCT_QUESTION_PATTERNS):
        return "product_self_knowledge"
    if "tshark" in tools and any(term in normalized for term in ("can mongrel", "can you", "what can")):
        return "individual_tool_explanation"
    if any(term in normalized for term in ATTACKER_QUESTION_TERMS):
        return "attacker_informed_defensive_reasoning"
    if any(term in normalized for term in RECOMMENDATION_QUESTION_TERMS):
        return "next_step_recommendation"
    if any(term in normalized for term in PRIORITIZATION_TERMS):
        return "prioritization"
    if re.search(r"\b(?:what|which)\b.{0,32}\bnext\b", normalized):
        return "next_step_recommendation"
    if any(term in normalized for term in COVERAGE_GAP_TERMS):
        return "remaining_coverage_gaps"
    if any(term in normalized for term in UNCERTAINTY_TERMS):
        return "uncertainty_safety"
    if any(term in normalized for term in SIGNIFICANCE_TERMS):
        return "significance_interpretation"
    if any(term in normalized for term in SIMPLIFY_TERMS):
        return "simplify_explanation"
    if any(re.search(pattern, normalized) for pattern in FOLLOW_UP_PATTERNS):
        return "follow_up_reference"
    if tools and any(term in normalized for term in TOOL_EXPLANATION_TERMS):
        return "individual_tool_explanation"
    if any(term in normalized for term in ASSESSMENT_QUESTION_TERMS):
        return "current_assessment_evidence"
    if any(term in normalized for term in SECURITY_CONCEPT_TERMS):
        return "security_concept"
    if any(term in normalized for term in ("explain that", "what does that mean", "what do you mean")):
        return "explanation"
    return "current_assessment_evidence"


def build_context_digest(context: dict) -> str:
    payload = {key: value for key, value in context.items() if key != "evidence_context_digest"}
    encoded = json.dumps(payload, default=_json_default, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def detect_question_tools(question: str) -> list[str]:
    normalized = f" {str(question or '').lower()} "
    selected = []
    for tool, aliases in TOOL_ALIASES.items():
        if any(alias in normalized for alias in aliases):
            selected.append(tool)
    if any(term in normalized for term in CORRELATION_TERMS):
        for tool in ("tshark", "metasploit"):
            if tool not in selected:
                selected.append(tool)
    packet_provenance = any(term in normalized for term in ("packet", "packets", "pcap", "capture"))
    explicit_testssl = any(term in normalized for term in ("testssl", "tls configuration", "cipher", "certificate"))
    if packet_provenance and "tshark" in selected and "testssl" in selected and not explicit_testssl:
        selected.remove("testssl")
    return selected


def _resolve_conversation(user_id: int, assessment_id: int, conversation_id: str | None) -> dict | None:
    if conversation_id:
        conversation = get_user_conversation(user_id, conversation_id)
        if conversation is None:
            raise ValueError("Assessment conversation not found.")
        if int(conversation["assessment_id"]) != int(assessment_id):
            raise ValueError("Assessment conversation does not belong to the requested assessment.")
        return conversation
    return get_latest_assessment_conversation(user_id, assessment_id)


def _build_evidence_context(assessment_context: dict, selected_tools: list[str]) -> dict:
    scan_ids = set()
    finding_ids = set()
    scans = []
    findings_by_tool: dict[str, int] = {}
    full_assessment = not selected_tools
    for scan in assessment_context.get("scans") or []:
        tool = _normalize_tool(scan.get("tool"))
        if not _include_tool(tool, selected_tools, full_assessment):
            continue
        scans.append(_sanitize(scan, drop_finding=True))
        scan_ids.add(scan.get("id"))
        finding = scan.get("finding")
        if isinstance(finding, dict):
            finding_id = finding.get("id")
            if finding_id in finding_ids:
                continue
            count = findings_by_tool.get(tool, 0)
            if count >= MAX_FINDINGS_PER_TOOL:
                continue
            findings_by_tool[tool] = count + 1
            finding_ids.add(finding_id)

    findings = []
    included_finding_ids = set()
    for finding in assessment_context.get("findings") or []:
        tool = _normalize_tool(finding.get("source"))
        if not _include_tool(tool, selected_tools, full_assessment):
            continue
        if finding.get("id") in included_finding_ids:
            continue
        if len([item for item in findings if item.get("source") == tool]) >= MAX_FINDINGS_PER_TOOL:
            continue
        included_finding_ids.add(finding.get("id"))
        findings.append(_sanitize(finding))

    artifacts = []
    selected_scan_ids = {scan.get("id") for scan in scans}
    for artifact in assessment_context.get("artifacts") or []:
        if not _include_artifact(artifact, selected_tools, full_assessment, selected_scan_ids):
            continue
        artifacts.append(_artifact_for_context(artifact))
        if len(artifacts) >= MAX_ARTIFACTS:
            break

    return {
        "assessment": _sanitize(assessment_context.get("assessment") or {}),
        "targets": _sanitize(assessment_context.get("targets") or []),
        "scans": scans,
        "findings": findings,
        "artifacts": artifacts,
        "notes": _sanitize(assessment_context.get("notes") or []),
        "budget": {
            "recent_messages_bounded": True,
            "evidence_prioritized_over_history": True,
            "raw_outputs_excluded": True,
            "max_findings_per_tool": MAX_FINDINGS_PER_TOOL,
            "max_items_per_list": MAX_ITEMS_PER_LIST,
            "max_artifacts": MAX_ARTIFACTS,
            "max_text_length": MAX_TEXT_LENGTH,
        },
    }


def _build_provenance(
    *,
    assessment_context: dict,
    evidence: dict,
    user_id: int,
    assessment_id: int,
    conversation: dict | None,
    selected_tools: list[str],
    recent_messages: list[dict],
    full_assessment: bool,
) -> dict:
    return {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "user_id": user_id,
        "assessment_id": assessment_id,
        "conversation_id": conversation["id"] if conversation is not None else None,
        "conversation_summary_present": bool(conversation and conversation.get("summary")),
        "history_message_ids": [message.get("id") for message in recent_messages],
        "selection_mode": "full_assessment" if full_assessment else "tool_relevant",
        "selected_tools": selected_tools,
        "included_scan_ids": [scan.get("id") for scan in evidence.get("scans") or []],
        "included_finding_ids": [finding.get("id") for finding in evidence.get("findings") or []],
        "included_artifact_ids": [artifact.get("id") for artifact in evidence.get("artifacts") or []],
        "available_scan_ids": [scan.get("id") for scan in assessment_context.get("scans") or []],
        "available_artifact_ids": [artifact.get("id") for artifact in assessment_context.get("artifacts") or []],
        "evidence_counts": {
            "targets": len(evidence.get("targets") or []),
            "scans": len(evidence.get("scans") or []),
            "findings": len(evidence.get("findings") or []),
            "artifacts": len(evidence.get("artifacts") or []),
            "notes": len(evidence.get("notes") or []),
        },
    }


def _message_for_context(message: dict) -> dict:
    return {
        "id": message.get("id"),
        "role": message.get("role"),
        "content": _truncate(str(message.get("content") or "")),
        "created_at": message.get("created_at"),
    }


def _artifact_for_context(artifact: dict) -> dict:
    safe_artifact = {
        "id": artifact.get("id"),
        "assessment_id": artifact.get("assessment_id"),
        "scan_id": artifact.get("scan_id"),
        "artifact_type": artifact.get("artifact_type"),
        "title": artifact.get("title"),
        "file_path": artifact.get("file_path"),
        "created_at": artifact.get("created_at"),
    }
    content = artifact.get("content")
    if isinstance(content, str) and content.strip():
        safe_artifact["content"] = _parse_or_excerpt(content)
    return _sanitize(safe_artifact)


def _parse_or_excerpt(value: str) -> Any:
    trimmed = value.strip()
    if len(trimmed) > MAX_TEXT_LENGTH:
        return {"excerpt": _truncate(trimmed), "truncated": True}
    try:
        decoded = json.loads(trimmed)
    except ValueError:
        return _truncate(trimmed)
    return _sanitize(decoded)


def _include_artifact(artifact: dict, selected_tools: list[str], full_assessment: bool, selected_scan_ids: set[object]) -> bool:
    if full_assessment:
        return True
    scan_id = artifact.get("scan_id")
    if scan_id in selected_scan_ids:
        return True
    haystack = " ".join(str(artifact.get(key) or "").lower() for key in ("artifact_type", "title", "content"))
    return any(tool in haystack for tool in selected_tools) or (
        "tshark" in selected_tools and "correlation" in haystack
    )


def _include_tool(tool: str, selected_tools: list[str], full_assessment: bool) -> bool:
    if full_assessment:
        return True
    if tool in selected_tools:
        return True
    if tool == "testssl" and "testssl" in selected_tools:
        return True
    return False


def _normalize_tool(value: object) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "testssl.sh":
        return "testssl"
    return normalized


def _sanitize(value: Any, *, drop_finding: bool = False) -> Any:
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            if drop_finding and key_lower == "finding":
                continue
            if key_lower in RAW_FIELD_NAMES:
                continue
            if "secret" in key_lower and key_lower not in SECRET_FIELD_ALLOWLIST and not key_lower.startswith("redacted_"):
                sanitized[key_text] = "<REDACTED>"
                continue
            sanitized[key_text] = _sanitize(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize(item) for item in value[:MAX_ITEMS_PER_LIST]]
    if isinstance(value, tuple):
        return [_sanitize(item) for item in list(value)[:MAX_ITEMS_PER_LIST]]
    if isinstance(value, str):
        return _truncate(value)
    return value


def _truncate(value: str) -> str:
    if len(value) <= MAX_TEXT_LENGTH:
        return value
    return value[: MAX_TEXT_LENGTH - 15].rstrip() + "... [truncated]"


def _tool_boundaries() -> list[str]:
    return [
        "Stored normalized evidence is authoritative; conversation history is interpretation only.",
        "Absence of findings is not proof of security or vulnerability absence.",
        "Metasploit module execution, subprocess success, sessions, exploitation, and compromise are distinct states.",
        "TShark correlation confidence describes attribution confidence, not exploitability confidence.",
        "Prowler PASS/FAIL applies to the specific scanner check and does not prove account-wide posture.",
        "Gitleaks findings are redacted secret-pattern matches; validity, ownership, usability, and compromise are not established.",
        "Nmap service labels classify exposed services; HTTP does not prove sensitive cleartext data or interception risk, and HTTPS does not prove a successful or secure TLS exchange.",
    ]


def _build_recommendation_context(
    question: str,
    assessment_context: dict,
    *,
    question_intent: str = "current_assessment_evidence",
) -> dict:
    normalized_question = str(question or "").lower()
    completed_tools = []
    for scan in assessment_context.get("scans") or []:
        tool = _normalize_tool(scan.get("tool"))
        if str(scan.get("status") or "").lower() == "completed" and tool and tool not in completed_tools:
            completed_tools.append(tool)

    web_services_observed = _has_nmap_web_service(assessment_context)
    traffic_intent = any(term in normalized_question for term in TRAFFIC_QUESTION_TERMS)
    web_intent = any(term in normalized_question for term in WEB_QUESTION_TERMS)
    novice_intent = any(term in normalized_question for term in NOVICE_QUESTION_TERMS)
    preferred_next_tools = []
    rationale = []
    if traffic_intent:
        preferred_next_tools.append("tshark")
        rationale.append("TShark is Mongrel's packet/capture capability; explain the mode that addresses the evidence gap without claiming packets already exist.")
    elif web_services_observed and "httpx" not in completed_tools and (
        web_intent or novice_intent or any(term in normalized_question for term in RECOMMENDATION_QUESTION_TERMS)
        or question_intent in {"next_step_recommendation", "prioritization"}
    ):
        preferred_next_tools.append("httpx")
        rationale.append("Nmap already identified web-associated exposed services; httpx can test which HTTP(S) endpoints respond and characterize them.")

    return {
        "completed_tools": completed_tools,
        "web_services_observed_by_nmap": web_services_observed,
        "question_intents": {"web": web_intent, "traffic": traffic_intent, "novice": novice_intent},
        "preferred_next_tools": preferred_next_tools,
        "rationale": rationale,
        "rules": [
            "Do not blindly recommend a completed tool when another Mongrel capability fills the current evidence gap.",
            "Do not recommend a tool merely because it has not run; it must answer the question and fill an identified evidence gap.",
            "Prefer Mongrel's own capability when it satisfies the request; name an external tool only for a clearly explained capability gap.",
            "Guide the user through the verified Telegram capability guidance; do not provide installation steps, shell commands, or invented navigation labels.",
            "A recommendation is advice only and must never trigger tool execution.",
        ],
    }


def _has_nmap_web_service(assessment_context: dict) -> bool:
    for finding in assessment_context.get("findings") or []:
        if _normalize_tool(finding.get("source")) != "nmap":
            continue
        for item in finding.get("open_ports") or []:
            try:
                port = int(item.get("port"))
            except (TypeError, ValueError, AttributeError):
                port = None
            service = str(item.get("service") or "").lower() if isinstance(item, dict) else ""
            if port in WEB_SERVICE_PORTS or service in {"http", "https", "http-proxy", "https-alt"}:
                return True
    return False


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
