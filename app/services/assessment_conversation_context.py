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
from app.services.assessment_map_retrieval import build_assessment_map_context
from app.services.assessment_store import get_user_assessment
from app.services.mongrel_self_knowledge import build_mongrel_self_knowledge_profile, get_mongrel_tool_names
from app.services.scan_status import normalize_scan_status

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
    "playwright": ("playwright", "playright", "browser", "dom"),
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
NOVICE_QUESTION_TERMS = ("novice", "beginner", "don't know", "do not know", "new to", "completely new", "what should i do next")
WEB_SERVICE_PORTS = {80, 443, 8080, 8443}
PRODUCT_QUESTION_PATTERNS = (
    "what can mongrel", "what does mongrel do", "what are your tools", "what tools do you have",
    "what modes does mongrel", "difference between assessment mode", "can you run tools automatically",
)
RECOMMENDATION_QUESTION_TERMS = (
    "what next", "what is next", "do next", "run next", "should i run", "which tool", "which mongrel tool",
    "which missing tool",
    "try next", "should i try", "will i try next", "what do i run next",
    "recommend", "what would you investigate", "would you investigate", "how do i investigate", "what should we do",
    "where do we go from here", "where should we go from here",
)
ASSESSMENT_QUESTION_TERMS = ("what did", "what was found", "what have we found", "current assessment", "assessment evidence", "scan result")
ASSESSMENT_SUMMARY_TERMS = (
    "what have we established", "what do we actually know", "what have we found so far", "summarize what we know",
    "summarise what we know", "what evidence do we have", "what do we know", "what have we found",
    "summarize this assessment", "summarise this assessment", "what does all this tell us",
    "what did the tools find", "what have the tools found", "what did our tools find",
    "what can you actually say with confidence", "what can we say with confidence",
)
ASSESSMENT_HIGHLIGHT_TERMS = (
    "most interesting thing", "what stands out", "most significant", "what's significant", "what is significant",
    "what should i pay attention to", "which evidence matters most", "biggest risk", "highest risk",
    "anything i should be worried about", "should i be worried about anything", "what should concern me",
    "what are the main concerns", "main concerns",
)
ASSESSMENT_SUMMARY_PATTERNS = (
    re.compile(r"\bwhat\s+have\s+we\s+(?:actually\s+)?established\b"),
    re.compile(r"\bwhat\s+do\s+we\s+(?:actually\s+)?know\b"),
)
FALSE_PREMISE_PATTERNS = (
    re.compile(r"\b(?:confirmed|proved|proves?|definitely)\b.{0,80}\b(?:vulnerab|exploit|compromis|insecure|secure|compliant|no secrets|xss|sqli|sql injection)"),
    re.compile(r"\b(?:vulnerab|exploit|compromis)\w*\b.{0,30}\bright\b"),
    re.compile(r"\bscans?\s+found\s+everything\b"),
    re.compile(r"\b(?:the\s+)?exploit\s+(?:worked|succeeded)\b"),
    re.compile(r"\btshark\b.{0,50}\b(?:proved|confirmed)\b.{0,50}\bmetasploit\b.{0,30}\b(?:worked|succeeded|exploited)\b"),
    re.compile(r"\b(?:there\s+(?:were|are)|we\s+found)\s+no\s+secrets\b"),
    re.compile(r"\b(?:the\s+)?cloud\s+(?:passed|is\s+compliant|is\s+clean)\b"),
    re.compile(r"\btls\s+handshake\s+(?:completed|succeeded)\b"),
    re.compile(r"\bno\s+(?:other\s+)?vulnerabilit(?:y|ies)\s+(?:exist|remain|were\s+found)\b"),
    re.compile(r"\bnothing\s+else\s+(?:needs?|requires?)\s+(?:testing|checking|validation)\b"),
    re.compile(r"\b(?:credentials?|tokens?|keys?|secrets?)\s+(?:works?|are\s+(?:active|valid|usable))\b"),
)
SECURITY_CONCEPT_TERMS = (
    "owasp", "ssrf", "injection", "path traversal", "file upload", "access control", "authentication",
    "lateral movement", "persistence", "privilege", "attack chain",
)
ATTACKER_QUESTION_TERMS = ("think like an attacker", "attacker", "attack path", "attack chain")
TOOL_EXPLANATION_TERMS = ("what does", "why would i use", "what can", "explain", "what is")
FOLLOW_UP_PATTERNS = (
    r"^(?:and\s+)?(?:why|why (?:that|this) (?:one|tool)|which one|after that(?: one)?|what do you mean|what did you mean(?: by that)?)\??$",
    r"^(?:and\s+)?what (?:exactly\s+)?(?:will|would) (?:this|that|it) (?:tell|show|mean)(?: me| us)?\??$",
    r"^and (?:what about )?(?:port\s+)?\d{1,5}\??$",
    r"^(?:and\s+)?what about (?:this|that|it)\??$",
    r"^(?:and\s+)?how do you know\??$",
    r"^(?:and\s+)?what evidence supports (?:this|that|it)\??$",
)
PRIORITIZATION_TERMS = ("which one first", "what first", "attention first", "prioriti", "highest priority", "most important")
COVERAGE_GAP_TERMS = (
    "anything else", "haven't we checked", "have not we checked", "not checked", "coverage gap", "what is missing",
    "what haven't we done", "what have we not done", "what remains", "biggest unknown", "what don't we know",
    "what do we not know", "gaps remain", "remaining gaps",
)
SIGNIFICANCE_TERMS = ("anything worrying", "is that bad", "does that matter", "how serious", "why should i care")
UNCERTAINTY_TERMS = (
    "are we secure", "is it secure", "do we know it's vulnerable", "do we know it is vulnerable", "is it vulnerable",
    "is that a vulnerability", "does that mean it is vulnerable", "does that mean it's vulnerable", "are we safe",
)
CASUAL_SECURITY_TERM_ALIASES = (
    (re.compile(r"\b(?:vulnerabilty|vunerability|vuln)\b"), "vulnerability"),
    (re.compile(r"\bexploitible\b"), "exploitable"),
    (re.compile(r"\bonw\b"), "one"),
    (re.compile(r"\bwouldnt\b"), "wouldn't"),
    (re.compile(r"\bdont\b"), "don't"),
    (re.compile(r"\bwat\b"), "what"),
    (re.compile(r"\bnxt\b"), "next"),
)
TOOL_RELEVANCE_PATTERNS = (
    re.compile(r"\b(?:why|what)\s+wouldn'?t\s+(?:you|we)\s+(?:use|run)\b"),
    re.compile(r"\bwhy\s+not\b"),
    re.compile(r"\bshould\s+(?:you|we|i)\s+(?:use|run)\b"),
    re.compile(r"\bdo\s+(?:you|we|i)\s+need\b"),
    re.compile(r"\bis\s+.+\s+useful(?:\s+here)?\b"),
    re.compile(r"\bwhat\s+about\b"),
    re.compile(r"\bwhy\s+haven'?t\s+(?:you|we)\s+(?:used|run)\b"),
)
TOOL_STATE_OVERVIEW_PATTERNS = (
    re.compile(r"\bwhich\s+tools?\s+(?:have|has)\s+(?:run|been\s+run)\b"),
    re.compile(r"\bwhich\s+tools?\s+(?:haven'?t|have\s+not)\s+(?:run|been\s+run)\b"),
    re.compile(r"\bwhich\s+tools?\s+(?:completed|failed|timed\s+out)\b"),
    re.compile(r"\bwhich\s+tools?\s+(?:(?:were|are)\s+)?not\s+run\b"),
    re.compile(r"\bwhat\s+(?:tools?\s+)?(?:failed|timed\s+out)\b"),
    re.compile(r"\bwhat\s+(?:was|were)\s+(?:or|and)\s+(?:was|were)\s+not\s+run\b"),
    re.compile(r"\bshow\s+(?:me\s+)?(?:the\s+)?scan\s+statuses\b"),
    re.compile(r"\bassessment\s+(?:coverage|status)(?:\s*(?:and|/)\s*(?:coverage|status))?\b"),
    re.compile(r"\bwhich\s+(?:ones|tools?)\s+haven'?t\b"),
    re.compile(r"^which\s+haven'?t\??$"),
)
CROSS_TOOL_CONFIRMATION_PATTERNS = (
    re.compile(r"\bdo\s+(?:these|the)\s+(?:findings|results|observations)\s+confirm\s+each\s+other\b"),
    re.compile(r"\bmetasploit\b.{0,80}\btshark\b.{0,80}\bconfirm\w*\b.{0,40}\bexploit"),
)
TOOL_STATE_QUESTION_PATTERNS = (
    re.compile(r"\bdid\s+(?:we|you)\s+run\b"),
    re.compile(r"\bhas\s+.+\s+been\s+run\b"),
    re.compile(r"\bwhat\s+did\s+.+\s+(?:find|report|observe|add|prove|establish)\b"),
    re.compile(r"\bdid\s+.+\s+find\s+anything\b"),
)
UNCERTAINTY_PATTERNS = (
    re.compile(r"\bis\s+(?:this|that|it)\s+(?:a\s+)?vulnerability\b"),
    re.compile(r"\bdoes\s+(?:this|that|it)\s+mean\s+(?:(?:it\s+is|it'?s)\s+)?vulnerable\b"),
    re.compile(r"\bcan\s+(?:this|that|it)\s+be\s+exploit(?:ed|able)\b"),
    re.compile(r"\bcould\s+(?:someone|an?\s+attacker)\s+exploit\s+(?:this|that|it)\b"),
    re.compile(r"\bcan\s+an?\s+attacker\s+(?:actually\s+)?use\s+(?:this|that|it)\b"),
    re.compile(r"\bare\s+we\s+(?:safe|secure)\b"),
    re.compile(r"\bis\s+(?:the\s+)?(?:site|target|system|application)\s+(?:safe|secure)\b"),
    re.compile(r"\b(?:so\s+)?everything\s+is\s+safe\b"),
    re.compile(r"\bare\s+we\s+insecure\b"),
    re.compile(r"\bhave\s+we\s+compromised\s+(?:this|that|it|the\s+(?:site|target|system))\b"),
)
SIMPLIFY_TERMS = ("like i'm new", "like i am new", "new to cybersecurity", "completely new", "simply", "simple terms", "plain english", "beginner")


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
    inherited_scope = False
    if not selected_tools and _is_referential_follow_up(question, question_intent):
        selected_tools = _tools_from_immediately_relevant_history(recent_messages, question)
        inherited_scope = bool(selected_tools)
        if inherited_scope:
            recent_messages = _relevant_follow_up_messages(recent_messages, question)
    uncertainty_subtype = classify_uncertainty_subtype(question) if question_intent == "uncertainty_safety" else None
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
        "uncertainty_subtype": uncertainty_subtype,
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
            "inherited_evidence_scope": inherited_scope,
        },
        "conversation": {
            "id": conversation["id"] if conversation is not None else None,
            "summary": conversation.get("summary") if conversation is not None else None,
            "recent_messages": [_message_for_context(message) for message in recent_messages],
            "recent_message_limit": max(0, int(recent_message_limit or 0)),
        },
        "assessment_context": evidence,
        "assessment_map": _build_assessment_map_context_safe(
            user_id=user_id,
            assessment_id=assessment_id,
            question=_assessment_map_retrieval_query(
                question=question,
                recent_messages=recent_messages,
                referential=_is_referential_follow_up(question, question_intent),
            ),
        ),
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


def _build_assessment_map_context_safe(*, user_id: int, assessment_id: int, question: str) -> dict:
    try:
        return build_assessment_map_context(
            user_id=user_id,
            assessment_id=assessment_id,
            question=question,
        )
    except Exception:
        return {
            "version": "assessment-map.retrieval.v1",
            "available": False,
            "reason": "retrieval_error",
            "coverage": {
                "supported_tools": [],
                "represented_tools": [],
                "limitation": "Assessment-map retrieval was unavailable for this turn.",
            },
            "entities": [],
            "relationships": [],
            "truncated": False,
        }


def _assessment_map_retrieval_query(
    *, question: str, recent_messages: list[dict], referential: bool
) -> str:
    """Use bounded prior user wording only as a retrieval hint, never as evidence."""

    current = str(question or "").strip()
    if not referential:
        return current
    skipped_current = False
    for message in reversed(recent_messages):
        if str(message.get("role") or "").lower() != "user":
            continue
        content = str(message.get("content") or "").strip()
        if not skipped_current and _normalize_intent_text(content) == _normalize_intent_text(current):
            skipped_current = True
            continue
        if content:
            return f"{current}\nPrior user topic (retrieval hint only): {content[:500]}"
    return current


def _is_referential_follow_up(question: str, intent: str) -> bool:
    normalized = _normalize_intent_text(question)
    referential = bool(re.search(
        r"\b(?:that|it|this finding|this conclusion|that conclusion|why|how confident|how sure|how strong is (?:that|the) evidence|why should i trust|what does (?:that|it) mean)\b",
        normalized,
    ))
    return referential and intent in {
        "follow_up_reference", "explanation", "simplify_explanation", "significance_interpretation",
        "uncertainty_safety", "current_assessment_evidence",
    }


def _tools_from_immediately_relevant_history(recent_messages: list[dict], current_question: str) -> list[str]:
    skipped_current = False
    for message in reversed(recent_messages):
        if str(message.get("role") or "").lower() != "user":
            continue
        content = str(message.get("content") or "")
        if not skipped_current and _normalize_intent_text(content) == _normalize_intent_text(current_question):
            skipped_current = True
            continue
        tools = detect_question_tools(content)
        if tools:
            return tools
    return []


def _relevant_follow_up_messages(recent_messages: list[dict], current_question: str) -> list[dict]:
    """Keep the prior referent exchange plus the current question, not unrelated history."""
    prior_user_index = None
    skipped_current = False
    for index in range(len(recent_messages) - 1, -1, -1):
        message = recent_messages[index]
        if str(message.get("role") or "").lower() != "user":
            continue
        content = str(message.get("content") or "")
        if not skipped_current and _normalize_intent_text(content) == _normalize_intent_text(current_question):
            skipped_current = True
            continue
        if detect_question_tools(content):
            prior_user_index = index
            break
    if prior_user_index is None:
        return recent_messages[-3:]
    return recent_messages[prior_user_index:][-3:]


def classify_assessment_conversation_intent(question: str, *, selected_tools: list[str] | None = None) -> str:
    """Classify current intent without invoking the model; order resolves overlapping wording."""

    normalized = _normalize_intent_text(question)
    tools = selected_tools if selected_tools is not None else detect_question_tools(question)
    if any(pattern in normalized for pattern in PRODUCT_QUESTION_PATTERNS):
        return "product_self_knowledge"
    if "tshark" in tools and any(term in normalized for term in ("can mongrel", "can you", "what can")):
        return "individual_tool_explanation"
    if "think like an attacker" in normalized:
        return "attacker_informed_defensive_reasoning"
    if "tls" in normalized and "handshake" in normalized and any(
        term in normalized for term in ("packet", "capture", "tshark")
    ):
        return "current_assessment_evidence"
    if any(pattern.search(normalized) for pattern in FALSE_PREMISE_PATTERNS):
        return "unsupported_premise_check"
    if any(pattern.search(normalized) for pattern in CROSS_TOOL_CONFIRMATION_PATTERNS):
        return "cross_tool_confirmation"
    if classify_uncertainty_subtype(normalized):
        return "uncertainty_safety"
    if any(pattern.search(normalized) for pattern in TOOL_STATE_OVERVIEW_PATTERNS) and not any(
        term in normalized for term in PRIORITIZATION_TERMS
    ):
        return "tool_state_overview"
    if any(term in normalized for term in ASSESSMENT_SUMMARY_TERMS) or any(
        pattern.search(normalized) for pattern in ASSESSMENT_SUMMARY_PATTERNS
    ):
        return "assessment_summary"
    if any(term in normalized for term in ASSESSMENT_HIGHLIGHT_TERMS):
        return "assessment_highlight"
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
    if any(term in normalized for term in UNCERTAINTY_TERMS) or any(
        pattern.search(normalized) for pattern in UNCERTAINTY_PATTERNS
    ):
        return "uncertainty_safety"
    if any(term in normalized for term in SIGNIFICANCE_TERMS):
        return "significance_interpretation"
    if any(term in normalized for term in SIMPLIFY_TERMS):
        return "simplify_explanation"
    if any(re.search(pattern, normalized) for pattern in FOLLOW_UP_PATTERNS):
        return "follow_up_reference"
    if tools and has_explicit_tool_name(normalized) and re.search(
        r"\bdid\s+(?:we|you)\s+run\b|\bhas\s+.+\s+been\s+run\b", normalized
    ):
        return "individual_tool_state"
    if tools and has_explicit_tool_name(normalized) and is_tool_relevance_question(normalized):
        return "individual_tool_explanation"
    if tools and any(term in normalized for term in TOOL_EXPLANATION_TERMS):
        return "individual_tool_explanation"
    if any(term in normalized for term in ASSESSMENT_QUESTION_TERMS):
        return "current_assessment_evidence"
    if any(term in normalized for term in SECURITY_CONCEPT_TERMS):
        return "security_concept"
    if any(term in normalized for term in ("explain that", "what does that mean", "what do you mean")):
        return "explanation"
    return "current_assessment_evidence"


def _normalize_intent_text(question: str) -> str:
    normalized = " ".join(str(question or "").lower().replace("’", "'").split())
    for pattern, replacement in CASUAL_SECURITY_TERM_ALIASES:
        normalized = pattern.sub(replacement, normalized)
    return normalized


def is_tool_relevance_question(question: str) -> bool:
    normalized = _normalize_intent_text(question)
    return any(pattern.search(normalized) for pattern in TOOL_RELEVANCE_PATTERNS)


def is_tool_state_question(question: str) -> bool:
    normalized = _normalize_intent_text(question)
    return any(pattern.search(normalized) for pattern in TOOL_STATE_QUESTION_PATTERNS)


def has_explicit_tool_name(question: str) -> bool:
    normalized = _normalize_intent_text(question)
    return any(
        re.search(rf"(?<!\w){re.escape(alias.strip())}(?!\w)", normalized)
        for aliases in TOOL_ALIASES.values()
        for alias in aliases
    )


def classify_uncertainty_subtype(question: str) -> str | None:
    normalized = _normalize_intent_text(question)
    if re.search(r"\b(?:exploit(?:ed|able|ation)?|attacker\s+(?:actually\s+)?use)\b", normalized):
        return "exploitability"
    if re.search(r"\b(?:vulnerabilit(?:y|ies)|vulnerable)\b", normalized):
        return "vulnerability"
    if re.search(r"\bcompromis(?:e|ed|ing)\b", normalized):
        return "compromise"
    if re.search(r"\b(?:safe|secure|security|insecure)\b", normalized) or re.search(
        r"\btrust\b.{0,30}\b(?:site|target|system|application)\b|\btrust\s+(?:it|this|that)\b", normalized
    ):
        return "overall_security"
    return None


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
    full_assessment = not selected_tools
    source_scans = [scan for scan in assessment_context.get("scans") or [] if isinstance(scan, dict)]
    tools = selected_tools or sorted({_normalize_tool(scan.get("tool")) for scan in source_scans})
    authoritative_scans = [
        scan for tool in tools
        if (scan := select_latest_tool_scan(source_scans, tool)) is not None
    ]
    scans = [_sanitize(scan, drop_finding=True) for scan in authoritative_scans]
    selected_scan_ids = {scan.get("id") for scan in authoritative_scans}

    findings_by_id = {
        str(finding.get("id")): finding
        for finding in assessment_context.get("findings") or []
        if isinstance(finding, dict) and finding.get("id") is not None
    }
    findings = []
    for scan in authoritative_scans:
        finding = findings_by_id.get(str(scan.get("finding_id")))
        if finding is None and isinstance(scan.get("finding"), dict):
            finding = scan["finding"]
        if finding is not None:
            findings.append(_sanitize(finding))

    artifacts = []
    for artifact in reversed(assessment_context.get("artifacts") or []):
        scan_id = artifact.get("scan_id")
        include_unlinked = not scan_id and _include_artifact(
            artifact, selected_tools, full_assessment, selected_scan_ids
        )
        if scan_id not in selected_scan_ids and not include_unlinked:
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
    tool_states = {_normalize_tool(name): "NOT_RUN" for name in get_mongrel_tool_names()}
    for tool in tool_states:
        scan = select_latest_tool_scan(assessment_context.get("scans") or [], tool)
        if scan is None:
            continue
        status = normalize_scan_status(scan.get("status"), default="")
        tool_states[tool] = {
            "completed": "COMPLETED",
            "partial": "PARTIAL",
            "running": "RUNNING",
            "interrupted": "INTERRUPTED",
            "failed": "FAILED",
            "error": "FAILED",
            "timed_out": "TIMED_OUT",
            "skipped": "SKIPPED",
            "cancelled": "CANCELLED",
        }.get(status, "PARTIAL" if status else "NOT_RUN")
    completed_tools = [tool for tool, state in tool_states.items() if state == "COMPLETED"]

    web_services_observed = _has_nmap_web_service(assessment_context)
    traffic_intent = any(term in normalized_question for term in TRAFFIC_QUESTION_TERMS)
    web_intent = any(term in normalized_question for term in WEB_QUESTION_TERMS)
    novice_intent = any(term in normalized_question for term in NOVICE_QUESTION_TERMS)
    preferred_next_tools = []
    rationale = []
    if traffic_intent and "tshark" not in completed_tools:
        preferred_next_tools.append("tshark")
        rationale.append("TShark is Mongrel's packet/capture capability; explain the mode that addresses the evidence gap without claiming packets already exist.")
    elif web_services_observed and "httpx" not in completed_tools and (
        web_intent or novice_intent or any(term in normalized_question for term in RECOMMENDATION_QUESTION_TERMS)
        or question_intent in {"next_step_recommendation", "prioritization"}
    ):
        preferred_next_tools.append("httpx")
        rationale.append("Nmap already identified web-associated exposed services; httpx can test which HTTP(S) endpoints respond and characterize them.")
    elif web_services_observed and question_intent in {"next_step_recommendation", "prioritization"}:
        if "katana" not in completed_tools:
            preferred_next_tools.append("katana")
            rationale.append(
                "The assessment has a web-associated surface and httpx coverage, but no stored Katana crawl coverage; "
                "Katana can add URL, path, form, and linked-resource observations."
            )
        elif "playwright" not in completed_tools:
            preferred_next_tools.append("playwright")
            rationale.append(
                "The assessment has web discovery coverage but no stored browser-observation coverage; Playwright can "
                "observe rendered pages and browser-visible behavior."
            )
        elif "ffuf" not in completed_tools:
            preferred_next_tools.append("ffuf")
            rationale.append(
                "The assessment has web characterization and crawl coverage but no stored bounded path-discovery "
                "coverage; ffuf can add path/status/size observations."
            )

    return {
        "tool_states": tool_states,
        "completed_tools": completed_tools,
        "relevant_unperformed_tools": [
            tool for tool in ("bbot", "katana", "playwright", "ffuf") if tool_states.get(tool) != "COMPLETED"
        ] if web_services_observed else [],
        "repository_context_present": False,
        "cloud_context_present": False,
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


def select_latest_tool_scan(scans: list[dict], tool: str) -> dict | None:
    """Select a tool's authoritative latest scan by stored chronology and ID."""

    normalized_tool = _normalize_tool(tool)
    candidates = [
        scan for scan in scans
        if isinstance(scan, dict) and _normalize_tool(scan.get("tool")) == normalized_tool
    ]
    if not candidates:
        return None
    return max(candidates, key=_scan_chronology_key)


def _scan_chronology_key(scan: dict) -> tuple[float, int]:
    value = scan.get("created_at") or scan.get("started_at") or scan.get("updated_at")
    if isinstance(value, datetime):
        timestamp = value.timestamp()
    else:
        try:
            timestamp = datetime.fromisoformat(str(value)).timestamp()
        except (TypeError, ValueError):
            timestamp = float("-inf")
    try:
        scan_id = int(scan.get("id") or 0)
    except (TypeError, ValueError):
        scan_id = 0
    return timestamp, scan_id


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
