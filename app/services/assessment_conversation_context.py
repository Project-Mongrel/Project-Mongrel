import hashlib
import json
import re
from collections import Counter
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
from app.services.conversation_understanding import normalize_conversational_text, understand_conversation
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
TOOL_SUITABILITY_RULES = {
    "nmap": {
        "capability": "Network reachability, exposed ports, and service classifications.",
        "prerequisites": "An authorized hostname, IP address, CIDR, or network target.",
        "limitations": "Does not prove application behavior, vulnerability, exploitability, or safety.",
    },
    "bbot": {
        "capability": "Bounded reconnaissance and related asset discovery within authorized scope.",
        "prerequisites": "A target where broader reconnaissance is in scope.",
        "limitations": "Discoveries do not prove ownership, breach, reachability, vulnerability, or exploitability.",
    },
    "nuclei": {
        "capability": "Template-based checks against appropriate observed targets.",
        "prerequisites": "A suitable target or observed endpoint for approved templates.",
        "limitations": "Template matches preserve scanner severity and do not automatically prove exploitability.",
    },
    "httpx": {
        "capability": "HTTP(S) response, redirect, title, server, and technology-hint observations.",
        "prerequisites": "An authorized web endpoint, hostname, or web-associated service surface.",
        "limitations": "Responses and technology hints do not prove vulnerability, misconfiguration, or safety.",
    },
    "playwright": {
        "capability": "Browser-rendered page and client-visible application behavior observations.",
        "prerequisites": "A web application surface worth observing in a browser.",
        "limitations": "Rendered state does not prove XSS, SQLi, CSRF, auth weakness, or complete coverage.",
    },
    "katana": {
        "capability": "Web crawl observations such as URLs, paths, forms, and linked resources.",
        "prerequisites": "An observed or authorized web application surface.",
        "limitations": "Crawl output does not prove vulnerability or complete hidden-endpoint coverage.",
    },
    "ffuf": {
        "capability": "Bounded web content/path discovery using an approved profile.",
        "prerequisites": "A web surface where path discovery is authorized and useful.",
        "limitations": "Status codes and path hits do not automatically prove sensitive exposure or vulnerability.",
    },
    "testssl": {
        "capability": "TLS protocol, cipher, certificate, and scanner finding observations.",
        "prerequisites": "An appropriate TLS endpoint or HTTPS-associated service.",
        "limitations": "Individual scanner observations do not prove exploitability or overall TLS safety.",
    },
    "gitleaks": {
        "capability": "Redacted secret-pattern matches in authorized repositories or filesystem content.",
        "prerequisites": "Authorized repository or filesystem input.",
        "limitations": "Matches do not prove a credential is active, valid, usable, or compromised; not-run is not no secrets.",
    },
    "prowler": {
        "capability": "Supported cloud-provider check observations for cloud accounts/environments.",
        "prerequisites": "Authorized cloud account/environment context and access.",
        "limitations": "PASS/FAIL is scoped to individual checks/resources and is not account-wide security or compliance proof.",
    },
    "metasploit": {
        "capability": "Explicitly approved validation of a supported hypothesis.",
        "prerequisites": "A supported validation opportunity plus Mongrel's explicit review/approval flow.",
        "limitations": "Execution, target response, session establishment, exploitation, and compromise remain distinct.",
    },
    "tshark": {
        "capability": "Packet/capture metadata from uploaded PCAPs, standalone capture, or capture during approved validation.",
        "prerequisites": "Authorized packet capture, PCAP analysis, or traffic-correlation need.",
        "limitations": "Packets do not prove application success, TLS-handshake completion, exploitability, or compromise.",
    },
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
    "what modes does mongrel", "can you run tools automatically",
    "difference between assessment mode",
)
RECOMMENDATION_QUESTION_TERMS = (
    "what next", "what is next", "do next", "run next", "should i run", "which tool", "which mongrel tool",
    "which missing tool",
    "try next", "should i try", "will i try next", "what do i run next",
    "recommend", "what would you investigate", "what should we investigate", "should we investigate",
    "would you investigate", "how do i investigate", "what should we do",
    "where do we go from here", "where should we go from here",
)
ASSESSMENT_QUESTION_TERMS = ("what did", "what was found", "what have we found", "current assessment", "assessment evidence", "scan result")
ASSESSMENT_SUMMARY_TERMS = (
    "what have we established", "what do we actually know", "what have we found so far", "summarize what we know",
    "summarise what we know", "what evidence do we have", "what do we know", "what have we found",
    "what have we learned", "what have we learnt",
    "summarize this assessment", "summarise this assessment", "what does all this tell us",
    "what did the tools find", "what have the tools found", "what did our tools find",
    "what can you actually say with confidence", "what can you say with confidence", "what can we say with confidence",
)
ASSESSMENT_HIGHLIGHT_TERMS = (
    "most interesting thing", "what stands out", "most significant", "what's significant", "what is significant",
    "what should i pay attention to", "which evidence matters most", "biggest risk", "highest risk",
    "anything i should be worried about", "should i be worried about anything", "what should concern me",
    "what are the main concerns", "main concerns",
)
ASSESSMENT_SUMMARY_PATTERNS = (
    re.compile(r"\bwhat\s+have\s+we\s+(?:actually\s+)?established\b"),
    re.compile(r"\bwhat\s+have\s+we\s+(?:actually\s+)?(?:learned|learnt)\b"),
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
PRIORITIZATION_TERMS = (
    "which one first", "what first", "attention first", "prioriti", "highest priority", "most important",
    "actually matters",
)
COVERAGE_GAP_TERMS = (
    "anything else", "haven't we checked", "have not we checked", "not checked", "coverage gap", "what is missing",
    "what haven't we done", "what have we not done", "what remains", "biggest unknown", "what don't we know",
    "what do we not know", "gaps remain", "remaining gaps", "tested properly", "tested thoroughly",
)
SIGNIFICANCE_TERMS = ("anything worrying", "is that bad", "does that matter", "how serious", "why should i care")
UNCERTAINTY_TERMS = (
    "are we secure", "is it secure", "do we know it's vulnerable", "do we know it is vulnerable", "is it vulnerable",
    "is that a vulnerability", "does that mean it is vulnerable", "does that mean it's vulnerable", "are we safe",
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
    re.compile(r"\b(?:did|does)\s+(?:anything|another\s+tool|any\s+other\s+tool)\s+(?:else\s+)?(?:see|confirm|find|observe)\b"),
    re.compile(r"\bwas\s+that\s+seen\s+anywhere\s+else\b"),
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
    understanding = understand_conversation(
        question,
        tuple(
            (str(message.get("role") or ""), str(message.get("content") or ""))
            for message in recent_messages
            if isinstance(message, dict)
        ),
    )
    if (
        understanding.is_follow_up
        and (understanding.requests_detail or understanding.narrows_selection)
        and question_intent in {"current_assessment_evidence", "next_step_recommendation", "prioritization"}
    ):
        question_intent = "follow_up_reference"
    compound_requirements = _detect_compound_requirements(
        question,
        selected_tools=selected_tools,
        primary_intent=question_intent,
    )
    inherited_scope = False
    referent_scope = _recent_referent_scope(recent_messages, question)
    if not selected_tools and _is_referential_follow_up(question, question_intent):
        selected_tools = _tools_from_immediately_relevant_history(recent_messages, question, referent_scope=referent_scope)
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
        "conversation_understanding": {
            "follow_up": understanding.is_follow_up,
            "requests_detail": understanding.requests_detail,
            "narrows_selection": understanding.narrows_selection,
            "referenced_ordinal": understanding.referenced_ordinal,
        },
        "compound_requirements": compound_requirements,
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
    if referent_scope:
        context["selection"]["recent_referent_scope"] = referent_scope
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
        "cross_tool_confirmation",
    }


def _recent_referent_scope(recent_messages: list[dict], current_question: str) -> list[str]:
    """Infer only a bounded topic scope from the immediately preceding exchange."""
    current_index = None
    normalized_current = _normalize_intent_text(current_question)
    for index in range(len(recent_messages) - 1, -1, -1):
        if _normalize_intent_text(str(recent_messages[index].get("content") or "")) == normalized_current:
            current_index = index
            break
    if current_index is None:
        current_index = len(recent_messages)
    prior_user_index = None
    for index in range(current_index - 1, -1, -1):
        if str(recent_messages[index].get("role") or "").lower() == "user":
            prior_user_index = index
            break
    if prior_user_index is None:
        return []
    exchange = recent_messages[prior_user_index:current_index]
    topic_text = " ".join(str(message.get("content") or "") for message in exchange).lower()
    if re.search(r"\b(?:tls|testssl(?:\.sh)?|cert(?:ificate)?|cipher|ssl)\b", topic_text):
        return ["testssl"]
    return []


def _tools_from_immediately_relevant_history(
    recent_messages: list[dict], current_question: str, *, referent_scope: list[str] | None = None,
) -> list[str]:
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
    return list(referent_scope or [])


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
    if any(term in normalized for term in ASSESSMENT_HIGHLIGHT_TERMS) or re.search(
        r"\bwhat\b.{0,24}\bworth\s+investigating\b", normalized
    ):
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


def _detect_compound_requirements(
    question: str,
    *,
    selected_tools: list[str],
    primary_intent: str,
) -> dict:
    normalized = _normalize_intent_text(question)
    needs_next_step = (
        primary_intent in {"next_step_recommendation", "prioritization"}
        or any(term in normalized for term in RECOMMENDATION_QUESTION_TERMS)
        or bool(re.search(r"\b(?:what|which)\b.{0,40}\bnext\b", normalized))
        or bool(re.search(r"\binvestigat\w*.{0,20}\bnext\b", normalized))
    )
    tool_summary_terms = re.search(
        r"\bwhat\s+did\b.{0,80}\b(?:add|find|observe|report|establish|tell|show)\b|"
        r"\bwhat\s+.+\s+added\s+to\b",
        normalized,
    )
    status_summary = bool(re.search(r"\bwhat\s+(?:failed|timed out|was interrupted|didn'?t complete)\b", normalized))
    requirements = {
        "needs_next_step": needs_next_step,
        "tool_evidence_summary": list(selected_tools) if selected_tools and tool_summary_terms else [],
        "status_summary": status_summary,
        "limitations": bool(re.search(r"\b(?:limitations?|what does(?:n'?t| not) (?:this|that|it) prove|what don'?t we know)\b", normalized)),
    }
    return {key: value for key, value in requirements.items() if value}


def _normalize_intent_text(question: str) -> str:
    normalized = normalize_conversational_text(question)
    normalized = re.sub(r"[?!.,;:]+", " ", normalized)
    normalized = " ".join(normalized.split())
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
        if str(artifact.get("artifact_type") or "").strip().lower() == "tshark_normalized_evidence":
            safe_artifact["content"] = _parse_tshark_artifact_or_excerpt(content)
        else:
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


def _parse_tshark_artifact_or_excerpt(value: str) -> Any:
    """Preserve bounded capture aggregates before compacting packet collections."""

    try:
        decoded = json.loads(value.strip())
    except ValueError:
        return _parse_or_excerpt(value)
    if not isinstance(decoded, dict):
        return _parse_or_excerpt(value)

    scalar_fields = (
        "source", "execution_status", "success", "packet_count", "byte_count",
        "capture_start", "capture_end", "duration", "duration_seconds", "elapsed_seconds",
        "error_type",
    )
    collection_fields = (
        "source_file", "observed_protocols", "observed_endpoints", "observed_conversations",
        "dns_observations", "http_observations", "tls_observations", "parser_warnings",
        "truncation", "evidence_limitations",
    )
    bounded = {
        key: decoded[key]
        for key in (*scalar_fields, *collection_fields)
        if key in decoded
    }
    return _sanitize(bounded)


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
            if key_lower == "nuclei_findings" and isinstance(item, list):
                template_counts = Counter(
                    str(entry.get("name") or entry.get("template_id") or "unnamed template")
                    for entry in item
                    if isinstance(entry, dict)
                )
                if template_counts and "nuclei_template_counts" not in sanitized:
                    sanitized["nuclei_template_counts"] = dict(template_counts)
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
    tls_services_observed = _has_nmap_tls_service(assessment_context)
    target_context = _classify_assessment_target_context(assessment_context)
    any_scan_recorded = bool(assessment_context.get("scans"))
    any_finding_recorded = bool(assessment_context.get("findings"))
    empty_assessment = not any_scan_recorded and not any_finding_recorded
    traffic_intent = any(term in normalized_question for term in TRAFFIC_QUESTION_TERMS)
    web_intent = any(term in normalized_question for term in WEB_QUESTION_TERMS)
    novice_intent = any(term in normalized_question for term in NOVICE_QUESTION_TERMS)
    recon_intent = any(term in normalized_question for term in ("recon", "reconnaissance", "asset", "assets", "subdomain", "subdomains", "broader"))
    secret_intent = any(term in normalized_question for term in ("secret", "secrets", "credential", "credentials", "repository", "repo"))
    cloud_intent = any(term in normalized_question for term in ("cloud", "aws", "azure", "gcp", "account", "prowler"))
    preferred_next_tools = []
    rationale = []
    if traffic_intent and "tshark" not in completed_tools:
        preferred_next_tools.append("tshark")
        rationale.append("TShark is Mongrel's packet/capture capability; explain the mode that addresses the evidence gap without claiming packets already exist.")
    elif empty_assessment and target_context["cloud_context_present"] and "prowler" not in completed_tools:
        preferred_next_tools.append("prowler")
        rationale.append(
            "The assessment has cloud-environment context but no stored scan evidence; Prowler can record authorized cloud check observations. "
            "PASS/FAIL results remain scoped scanner observations, not account-wide security proof."
        )
    elif empty_assessment and target_context["repository_context_present"] and "gitleaks" not in completed_tools:
        preferred_next_tools.append("gitleaks")
        rationale.append(
            "The assessment has repository/filesystem context but no stored scan evidence; Gitleaks can record redacted secret-pattern observations. "
            "A match would not prove credential validity, and a not-run scan proves no absence of secrets."
        )
    elif empty_assessment and target_context["packet_context_present"] and "tshark" not in completed_tools:
        preferred_next_tools.append("tshark")
        rationale.append(
            "The assessment has packet-capture context but no stored packet evidence; TShark can analyze authorized PCAP or capture metadata. "
            "Packets do not establish exploitation, compromise, or TLS success by themselves."
        )
    elif empty_assessment and target_context["external_website_context_present"]:
        if "nmap" not in completed_tools:
            preferred_next_tools.append("nmap")
        if "httpx" not in completed_tools:
            preferred_next_tools.append("httpx")
        rationale.append(
            "The assessment has an external website/hostname target but no stored scan evidence; Nmap can observe reachable ports/services and "
            "httpx can record HTTP response metadata. Neither tool proves vulnerability or security by itself."
        )
    elif empty_assessment and target_context["network_context_present"]:
        preferred_next_tools.append("nmap")
        rationale.append(
            "The assessment has a network-style target but no stored scan evidence; Nmap can record host reachability, ports, and service classifications. "
            "Those observations do not prove vulnerabilities or security."
        )
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
        else:
            if "nuclei" not in completed_tools:
                preferred_next_tools.append("nuclei")
                rationale.append(
                    "The assessment has a confirmed web surface and core web discovery coverage, but no stored Nuclei "
                    "template-check coverage; Nuclei can add scanner-severity template match observations."
                )
            if tls_services_observed and "testssl" not in completed_tools:
                preferred_next_tools.append("testssl")
                rationale.append(
                    "The assessment has HTTPS/TLS-associated surface evidence, but no stored testssl.sh TLS configuration "
                    "coverage; testssl.sh can add protocol, cipher, certificate, and scanner finding observations."
                )
            if "bbot" not in completed_tools and (recon_intent or target_context["external_website_context_present"]):
                preferred_next_tools.append("bbot")
                rationale.append(
                    "The assessment has a public web target and no stored BBOT reconnaissance coverage; BBOT can add "
                    "bounded discovery observations if broader reconnaissance is in scope."
                )
    elif target_context["repository_context_present"] and secret_intent and "gitleaks" not in completed_tools:
        preferred_next_tools.append("gitleaks")
        rationale.append("Repository/filesystem context is present; Gitleaks can add redacted secret-pattern evidence without proving credential validity.")
    elif target_context["cloud_context_present"] and cloud_intent and "prowler" not in completed_tools:
        preferred_next_tools.append("prowler")
        rationale.append("Cloud context is present; Prowler can add scoped cloud check observations without proving account-wide security.")

    tool_decisions = _build_tool_decision_contract(
        tool_states=tool_states,
        target_context=target_context,
        web_services_observed=web_services_observed,
        tls_services_observed=tls_services_observed,
        traffic_intent=traffic_intent,
        secret_intent=secret_intent,
        cloud_intent=cloud_intent,
        preferred_next_tools=preferred_next_tools,
    )

    return {
        "tool_states": tool_states,
        "completed_tools": completed_tools,
        "relevant_unperformed_tools": [
            tool for tool in ("bbot", "nuclei", "katana", "playwright", "ffuf", "testssl") if tool_states.get(tool) != "COMPLETED"
        ] if web_services_observed else (
            [tool for tool in ("nmap", "httpx") if tool_states.get(tool) != "COMPLETED"]
            if empty_assessment and target_context["external_website_context_present"] else []
        ),
        "supported_tool_candidates": [
            tool for tool, decision in tool_decisions.items()
            if decision.get("recommendation_allowed") and tool_states.get(tool) != "COMPLETED"
        ],
        "tool_decisions": tool_decisions,
        "repository_context_present": target_context["repository_context_present"],
        "cloud_context_present": target_context["cloud_context_present"],
        "external_website_context_present": target_context["external_website_context_present"],
        "network_context_present": target_context["network_context_present"],
        "packet_context_present": target_context["packet_context_present"],
        "empty_assessment": empty_assessment,
        "assessment_has_scans": any_scan_recorded,
        "assessment_has_findings": any_finding_recorded,
        "web_services_observed_by_nmap": web_services_observed,
        "question_intents": {"web": web_intent, "traffic": traffic_intent, "novice": novice_intent},
        "preferred_next_tools": preferred_next_tools,
        "rationale": rationale,
        "rules": [
            "Do not blindly recommend a completed tool when another Mongrel capability fills the current evidence gap.",
            "Do not recommend a tool merely because it has not run; it must answer the question and fill an identified evidence gap.",
            "For an empty external website/hostname assessment, initial reconnaissance should use Nmap and/or httpx rather than cloud, repository, validation, or packet-capture tools.",
            "Prowler requires authorized cloud-account or cloud-environment context; it is not a general hostname, operating-system, service, or website reconnaissance scanner.",
            "Gitleaks requires suitable authorized repository or filesystem context; do not infer no secrets when it has not run.",
            "Metasploit requires an appropriate approved validation opportunity, and TShark requires packet-capture or traffic-analysis context.",
            "Prefer Mongrel's own capability when it satisfies the request; name an external tool only for a clearly explained capability gap.",
            "Guide the user through the verified Telegram capability guidance; do not provide installation steps, shell commands, or invented navigation labels.",
            "A recommendation is advice only and must never trigger tool execution.",
        ],
    }


def _classify_assessment_target_context(assessment_context: dict) -> dict:
    """Infer broad target suitability context from stored target descriptors only."""

    target_text = " ".join(
        " ".join(
            str(target.get(field) or "")
            for field in ("address", "name", "target_type")
            if isinstance(target, dict)
        )
        for target in (assessment_context.get("targets") or [])
    ).lower()
    assessment_text = " ".join(
        str((assessment_context.get("assessment") or {}).get(field) or "")
        for field in ("name", "description")
    ).lower()
    haystack = f"{target_text} {assessment_text}"
    target_types = " ".join(
        str(target.get("target_type") or "")
        for target in (assessment_context.get("targets") or [])
        if isinstance(target, dict)
    ).lower()

    cloud_context = bool(re.search(
        r"\b(?:aws|amazon web services|azure|gcp|google cloud|cloud account|cloud environment|iam|s3|ec2|subscription|tenant)\b",
        haystack,
    )) or "cloud" in target_types
    repository_context = bool(re.search(
        r"\b(?:git|github|gitlab|bitbucket|repository|repo|source code|filesystem|file system)\b|"
        r"(?:^|\s)(?:https?://)?(?:www\.)?(?:github|gitlab|bitbucket)\.com/|\bgit@",
        haystack,
    )) or any(term in target_types for term in ("repo", "repository", "filesystem", "file"))
    packet_context = bool(re.search(r"\b(?:pcap|packet|traffic capture|network capture|capture file)\b", haystack)) or any(
        term in target_types for term in ("pcap", "packet", "capture")
    )
    network_context = bool(re.search(
        r"\b(?:network|cidr|subnet|ip address|host)\b|"
        r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b|"
        r"\[[0-9a-f:]{2,}\]|\b[0-9a-f]{0,4}:[0-9a-f:]{2,}\b",
        haystack,
    )) or any(term in target_types for term in ("network", "ip", "cidr", "host"))
    website_context = bool(re.search(
        r"\b(?:https?://|www\.|website|web site|webapp|web app|hostname|domain)\b|"
        r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+\b",
        target_text,
    ))
    return {
        "cloud_context_present": cloud_context,
        "repository_context_present": repository_context,
        "packet_context_present": packet_context,
        "network_context_present": network_context,
        "external_website_context_present": website_context and not cloud_context and not repository_context and not packet_context,
    }


def _build_tool_decision_contract(
    *,
    tool_states: dict,
    target_context: dict,
    web_services_observed: bool,
    tls_services_observed: bool,
    traffic_intent: bool,
    secret_intent: bool,
    cloud_intent: bool,
    preferred_next_tools: list[str],
) -> dict:
    decisions = {}
    web_context = bool(target_context.get("external_website_context_present") or web_services_observed)
    network_context = bool(target_context.get("network_context_present") or target_context.get("external_website_context_present"))
    repo_context = bool(target_context.get("repository_context_present"))
    cloud_context = bool(target_context.get("cloud_context_present"))
    packet_context = bool(target_context.get("packet_context_present") or traffic_intent)
    preferred = {str(tool).lower().removesuffix(".sh") for tool in preferred_next_tools}
    for tool, rule in TOOL_SUITABILITY_RULES.items():
        state = str(tool_states.get(tool, "NOT_RUN"))
        allowed = False
        reason = ""
        if tool == "nmap":
            allowed = network_context
            reason = "authorized network, hostname, or website target context is present" if allowed else "no network/hostname target context is established"
        elif tool == "httpx":
            allowed = web_context
            reason = "web target or observed web service context is present" if allowed else "no web endpoint or web-service evidence is established"
        elif tool == "bbot":
            allowed = network_context or web_context
            reason = "broader authorized reconnaissance could add discovery observations" if allowed else "no reconnaissance target context is established"
        elif tool == "nuclei":
            allowed = web_context
            reason = "an appropriate target or web surface is available for template checks" if allowed else "no suitable checked target surface is established"
        elif tool in {"katana", "playwright", "ffuf"}:
            allowed = web_context
            reason = "web surface context is present" if allowed else "no web application surface is established"
        elif tool == "testssl":
            allowed = web_context or tls_services_observed
            reason = "TLS/HTTPS endpoint context is present" if allowed else "no TLS endpoint context is established"
        elif tool == "gitleaks":
            allowed = repo_context and (secret_intent or state != "NOT_RUN" or tool in preferred)
            reason = "repository/filesystem context is present" if repo_context else "no repository/filesystem context is established"
        elif tool == "prowler":
            allowed = cloud_context and (cloud_intent or state != "NOT_RUN" or tool in preferred)
            reason = "authorized cloud context is present" if cloud_context else "no authorized cloud account/environment context is established"
        elif tool == "metasploit":
            allowed = tool in preferred
            reason = "an explicit approved validation opportunity is required"
        elif tool == "tshark":
            allowed = packet_context
            reason = "packet/capture or traffic-analysis context is present" if allowed else "no packet/capture context is established"
        if state == "COMPLETED" and tool not in preferred:
            allowed = False
            reason = "already completed; rerun needs a separate justification"
        decisions[tool] = {
            "state": state,
            "recommendation_allowed": bool(allowed),
            "reason": reason,
            "capability": rule["capability"],
            "prerequisites": rule["prerequisites"],
            "limitations": rule["limitations"],
        }
    return decisions


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


def _has_nmap_tls_service(assessment_context: dict) -> bool:
    for finding in assessment_context.get("findings") or []:
        if _normalize_tool(finding.get("source")) != "nmap":
            continue
        for item in finding.get("open_ports") or []:
            try:
                port = int(item.get("port"))
            except (TypeError, ValueError, AttributeError):
                port = None
            service = str(item.get("service") or "").lower() if isinstance(item, dict) else ""
            if port in {443, 8443} or service in {"https", "https-alt", "ssl", "tls"}:
                return True
    return False


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
