import json
import re
from time import perf_counter

from app.core.config import get_settings
from app.services.ai_client import ask_ai
from app.services.assessment_ai import AI_UNAVAILABLE_MESSAGES
from app.services.assessment_conversation_context import build_assessment_conversation_context

FALLBACK_ANSWER = (
    "Ask Mongrel is unavailable. Review the assessment dashboard, scan history, stored findings, and reports for next steps."
)
TRUTHFULNESS_FALLBACK_ANSWER = (
    "Ask Mongrel withheld a generated answer because it made a security conclusion that was not supported by the stored "
    "assessment evidence. Review the current assessment evidence and rerun the question with a narrower scope."
)
NATIVE_GUIDANCE_FALLBACK_ANSWER = (
    "Ask Mongrel withheld guidance that did not use Mongrel's supported workflow. Return to the assessment dashboard and "
    "choose the relevant Mongrel action; no tool was run."
)
UNSUPPORTED_CONVERSATION_CLAIM_PATTERNS = (
    re.compile(r"\b(?:target|host|system|application|site|aws account|cloud account|environment|resource)\s+(?:is|appears|looks|seems)\s+(?:safe|secure|hardened|protected)\b"),
    re.compile(r"\b(?:no|zero)\s+(?:vulnerabilities|security issues|security risks|misconfigurations|attack paths)\s+(?:exist|were found|were detected|are present)\b"),
    re.compile(r"\b(?:exploit|exploitation)\s+(?:succeeded|worked|was successful)\b"),
    re.compile(r"\b(?:target|host|system|repository|environment|resource)\s+(?:was|is|has been)\s+(?:compromised|owned|exploited)\b"),
    re.compile(r"\b(?:credential|token|key|secret)\s+(?:is|was|has been)\s+(?:active|valid|usable|confirmed)\b"),
    re.compile(r"\b(?:tls|ssl)\s+configuration\s+(?:is|appears|looks|seems)\s+(?:secure|robust|hardened)\b"),
    re.compile(r"\b(?:http\s+transaction|tls\s+handshake)\s+(?:completed|succeeded|was successful)\b"),
    re.compile(r"\b(?:organization|company|aws account|cloud account)\s+(?:is|was)\s+(?:compliant|non-compliant)\b"),
)
SESSION_CLAIM_PATTERN = re.compile(r"\b(?:shell|session)\s+(?:was|is)\s+(?:obtained|opened|established)\b")
SERVICE_LABEL_OVERCLAIM_PATTERNS = (
    re.compile(r"\b(?:port\s+80|http(?:\s+service)?)\b.{0,80}\b(?:sensitive data|credentials?|secrets?)\b.{0,50}\b(?:cleartext|unencrypted|interceptable|exposed)\b"),
    re.compile(r"\b(?:sensitive data|credentials?|secrets?)\b.{0,60}\b(?:cleartext|unencrypted|interceptable|exposed)\b.{0,80}\b(?:port\s+80|http(?:\s+service)?)\b"),
    re.compile(r"\b(?:port\s+80|http(?:\s+service)?)\b.{0,100}\b(?:proves?|confirms?|establishes?)\b.{0,60}\b(?:mitm|man-in-the-middle|interception|exploitab)"),
    re.compile(r"\b(?:443|8443|https|https-alt)\b.{0,100}\b(?:proves?|confirms?|establishes?|means)\b.{0,60}\b(?:successful|secure|encrypted communication|tls handshake)"),
    re.compile(r"\b(?:443|8443|https|https-alt)\b.{0,60}\b(?:is|are|provides?|uses?)\b.{0,40}\b(?:established|successful|completed)\s+(?:tls|encrypted communication)"),
    re.compile(r"\b(?:http exposure|exposed http|port\s+80)\b.{0,50}\b(?:is|constitutes?|creates?)\b.{0,40}\b(?:security weakness|vulnerability|mitm risk|interception risk)\b"),
)
DETACHED_REMEDIATION_TERMS = ("content security policy", "csp", "cdn", "ip whitelist", "ip allowlist")
TRAFFIC_TERMS = ("traffic", "packet", "packets", "pcap", "capture")
EXTERNAL_TRAFFIC_TOOLS = ("tcpdump", "mitmproxy", "wireshark")
INSTALL_OR_RAW_COMMAND_PATTERNS = (
    re.compile(r"\b(?:install|brew install|apt(?:-get)? install|pipx? install|go install)\b.{0,50}\b(?:httpx|tshark)\b"),
    re.compile(r"(?:```(?:bash|sh|shell)?\s*|^|\n)\s*\$?\s*(?:sudo\s+)?(?:httpx|tshark)\s+(?:-|--|https?://|[\w.-]+\s+-)"),
)
EVIDENCE_LANGUAGE_OVERCLAIM_PATTERNS = (
    re.compile(r"\bhttpx\b.{0,80}\b(?:proves?|confirms?|establishes?|shows?)\b.{0,60}\b(?:vulnerab|misconfigur)"),
    re.compile(r"\btshark\b.{0,80}\b(?:will|can)\s+(?:prove|confirm|establish|determine|verify)\b.{0,80}\b(?:encryption security|secure encryption|exploitab|compromise|application security|vulnerab)"),
    re.compile(r"\b(?:two|2)\s+(?:independent(?:ly discovered)?\s+)?hosts?\b.{0,100}\b(?:hostname|domain)\b.{0,100}\b(?:resolved\s+)?ip\b"),
    re.compile(r"\bscoutsuite\s*/\s*prowler\b"),
)


def answer_assessment_conversation_question(
    *,
    user_id: int,
    assessment_id: int,
    conversation_id: str | None,
    question: str,
) -> dict:
    engine_started = perf_counter()
    context_started = perf_counter()
    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment_id,
        conversation_id=conversation_id,
        question=question,
    )
    context_ms = _elapsed_ms(context_started)
    context_chars = len(json.dumps(context, default=_json_default, sort_keys=True))
    prompt_started = perf_counter()
    prompt = build_assessment_conversation_prompt(context)
    prompt_ms = _elapsed_ms(prompt_started)
    output_token_budget = _conversation_num_predict()
    ai_started = perf_counter()
    try:
        response = ask_ai(prompt, num_predict=output_token_budget)
    except Exception:
        return _result(
            FALLBACK_ANSWER,
            context,
            fallback_reason="exception",
            instrumentation=_instrumentation(
                context,
                context_ms=context_ms,
                prompt_ms=prompt_ms,
                ai_ms=_elapsed_ms(ai_started),
                postprocess_ms=0.0,
                engine_ms=_elapsed_ms(engine_started),
                context_chars=context_chars,
                prompt_chars=len(prompt),
                output_token_budget=output_token_budget,
            ),
        )

    ai_ms = _elapsed_ms(ai_started)
    postprocess_started = perf_counter()
    fallback_reason = None
    if _is_unavailable_response(response):
        answer = FALLBACK_ANSWER
        fallback_reason = "ai_unavailable"
    else:
        answer = str(response or "").strip()
        if not answer:
            answer = FALLBACK_ANSWER
            fallback_reason = "empty"
        elif violates_conversation_truthfulness(answer, context):
            answer = TRUTHFULNESS_FALLBACK_ANSWER
            fallback_reason = "truthfulness_guard"
        elif violates_mongrel_native_guidance(answer, context):
            answer = NATIVE_GUIDANCE_FALLBACK_ANSWER
            fallback_reason = "native_guidance_guard"
    postprocess_ms = _elapsed_ms(postprocess_started)
    return _result(
        answer,
        context,
        fallback_reason=fallback_reason,
        instrumentation=_instrumentation(
            context,
            context_ms=context_ms,
            prompt_ms=prompt_ms,
            ai_ms=ai_ms,
            postprocess_ms=postprocess_ms,
            engine_ms=_elapsed_ms(engine_started),
            context_chars=context_chars,
            prompt_chars=len(prompt),
            output_token_budget=output_token_budget,
        ),
    )


def build_assessment_conversation_prompt(context: dict) -> str:
    return "\n".join(
        [
            "You are Mongrel, answering an assessment-scoped Ask Mongrel question.",
            "",
            "Core rule:",
            "Stored normalized assessment evidence is authoritative. Conversation history is interpretation only.",
            "If older assistant text conflicts with newer stored assessment evidence, newer evidence wins and you must say so.",
            "",
            "Rules:",
            "- Answer only from the supplied current assessment context.",
            "- Never invent findings, vulnerabilities, exploitability, compromise, access, ownership, compliance, or security posture.",
            "- Separate observed facts, interpretation, uncertainty, and recommendations.",
            "- If evidence is insufficient, say what is missing and avoid filling gaps.",
            "- Do not treat no findings, no packets, PASS checks, failed validations, or empty tool results as proof of security.",
            "- Metasploit subprocess success, module execution, validation state, target response, session establishment, exploitation, and compromise are separate facts.",
            "- TShark correlation confidence means attribution confidence only, not exploitation or vulnerability confidence.",
            "- Prowler PASS/FAIL applies to the specific scanner check only; PASS is not account/resource security proof.",
            "- Gitleaks findings are redacted secret-pattern matches only; never reveal or infer raw secret values.",
            "- testssl.sh findings preserve scanner wording, severity, and uncertainty.",
            "- Nmap service names are observations/classifications only. `80/tcp http` does not prove sensitive data is sent in cleartext, interception/MITM risk, a vulnerability, or exploitability.",
            "- `443/tcp https` and `8443/tcp https-alt` do not prove a successful TLS handshake, completed encrypted communication, certificate validity, or TLS quality. testssl.sh or protocol evidence is needed for TLS claims.",
            "- Treat a scanned hostname and its resolved IP as two identifiers for the same scanned endpoint unless stored evidence explicitly establishes independently discovered hosts. Never inflate the host count from DNS resolution alone.",
            "- Describe httpx as probing and characterizing observed HTTP endpoints and responses. Do not claim httpx itself establishes vulnerability or misconfiguration without separate supporting evidence.",
            "- Describe only packet/capture facts actually present in normalized TShark evidence. Never promise that running TShark will establish encryption security, exploitability, compromise, vulnerability, or application security.",
            "- The user-facing cloud tool is Prowler. Never emit legacy or combined internal cloud-tool aliases.",
            "- Do not invent remediation such as CSP, CDN use, or IP allowlisting unless stored evidence establishes the specific problem it would address.",
            "- Use the supplied Mongrel capability catalog and recommendation context. Prefer a fitting Mongrel tool over an external tool.",
            "- Speak as Mongrel, not as a generic chatbot. When Mongrel provides the capability, guide the user through the verified Telegram workflow in `telegram_capability_guidance`.",
            "- Never tell the user to install Mongrel's tools, and never provide raw shell/CLI commands for them. Do not invent buttons, menu labels, or navigation paths.",
            "- Recommend a tool only when it answers the current question and fills an evidence gap; being unrun is not itself a reason. Do not append unrelated tools as optional extras.",
            "- If Nmap already found web-associated services and the user asks how to investigate them, normally recommend httpx first because it fills the HTTP reachability/fingerprinting gap; do not simply repeat Nmap.",
            "- For traffic or packet analysis, recognize TShark and explain the applicable uploaded-PCAP, standalone-capture, or capture-during-approved-validation mode without claiming packet evidence exists.",
            "- You may recommend tools, but every recommendation must explain why and must not execute anything.",
            "- Active or invasive execution must remain behind Mongrel's existing explicit approval and execution flows.",
            "- Adapt depth to the user: plain English for beginner questions, concise technical comparison for experienced questions.",
            "- For a novice summary, give plain-English observed facts, what they do not prove, one Mongrel-specific next action, and why it fills the evidence gap. Avoid a generic security lecture.",
            "- For novice users, recommend exactly one clear next action unless the question explicitly asks for alternatives.",
            "- Keep the answer concise.",
            "",
            "Recommended answer shape:",
            "Observed Facts",
            "Interpretation",
            "Uncertainty",
            "Recommended Next Step",
            "",
            "Conversation Context JSON:",
            json.dumps(context, default=_json_default, sort_keys=True, indent=2),
            "",
            "Answer:",
        ]
    )


def violates_conversation_truthfulness(answer: str, context: dict | None = None) -> bool:
    normalized = str(answer or "").lower()
    if not normalized.strip():
        return False
    if any(pattern.search(normalized) for pattern in UNSUPPORTED_CONVERSATION_CLAIM_PATTERNS):
        return True
    if _has_service_label_overclaim(normalized):
        return True
    if _has_evidence_language_overclaim(normalized):
        return True
    if SESSION_CLAIM_PATTERN.search(normalized) and not _metasploit_session_established(context or {}):
        return True
    question = str((context or {}).get("current_question") or "").lower()
    if any(term in question for term in TRAFFIC_TERMS) and any(tool in normalized for tool in EXTERNAL_TRAFFIC_TOOLS) and "tshark" not in normalized:
        return True
    if any(term in normalized for term in DETACHED_REMEDIATION_TERMS) and not _answer_remediation_supported(normalized, context or {}):
        return True
    return False


def violates_mongrel_native_guidance(answer: str, context: dict | None = None) -> bool:
    normalized = str(answer or "").lower()
    if any(pattern.search(normalized) for pattern in INSTALL_OR_RAW_COMMAND_PATTERNS):
        return True

    recommendation = (context or {}).get("recommendation_context") or {}
    preferred = {str(tool).lower() for tool in recommendation.get("preferred_next_tools") or []}
    if not preferred:
        return False
    recommended_tools = set(
        re.findall(
            r"\b(?:recommend|use|run|try|choose)\s+(?:mongrel(?:'s)?\s+)?(?:the\s+)?(nmap|bbot|nuclei|httpx|playwright|katana|ffuf|testssl(?:\.sh)?|gitleaks|prowler|metasploit|tshark)\b",
            normalized,
        )
    )
    return bool(recommended_tools - preferred)


def _result(answer: str, context: dict, fallback_reason: str | None = None, instrumentation: dict | None = None) -> dict:
    provenance = context.get("provenance") or {}
    result = {
        "answer": answer,
        "assessment_id": provenance.get("assessment_id"),
        "user_id": provenance.get("user_id"),
        "conversation_id": provenance.get("conversation_id"),
        "evidence_context_digest": context.get("evidence_context_digest"),
        "evidence_refs": {
            "scan_ids": provenance.get("included_scan_ids") or [],
            "finding_ids": provenance.get("included_finding_ids") or [],
            "artifact_ids": provenance.get("included_artifact_ids") or [],
            "history_message_ids": provenance.get("history_message_ids") or [],
            "selected_tools": provenance.get("selected_tools") or [],
            "selection_mode": provenance.get("selection_mode"),
        },
        "provenance": provenance,
        "fallback_reason": fallback_reason,
        "instrumentation": instrumentation or {},
    }
    return result


def _conversation_num_predict() -> int:
    configured = int(get_settings().ask_mongrel_num_predict or 512)
    return max(256, min(configured, 2048))


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)


def _metasploit_session_established(context: dict) -> bool:
    for finding in ((context.get("assessment_context") or {}).get("findings") or []):
        evidence = finding.get("metasploit_evidence") if isinstance(finding, dict) else None
        if isinstance(evidence, dict) and evidence.get("session_established") is True:
            return True
    return False


def _answer_remediation_supported(answer: str, context: dict) -> bool:
    if re.search(r"\b(?:no evidence|not justified|not established|unsupported|cannot recommend)\b.{0,80}\b(?:csp|cdn|ip whitelist|ip allowlist)\b", answer):
        return True
    evidence_text = json.dumps((context.get("assessment_context") or {}).get("findings") or [], default=_json_default).lower()
    return any(term in evidence_text for term in DETACHED_REMEDIATION_TERMS if term in answer)


def _has_service_label_overclaim(answer: str) -> bool:
    for pattern in SERVICE_LABEL_OVERCLAIM_PATTERNS:
        match = pattern.search(answer)
        if match is None:
            continue
        claim = match.group(0)
        if re.search(r"\b(?:does|do|did|is|are)\s+not\b|\bnot\s+(?:proof|proven|established|confirmed)\b|\bno evidence\b", claim):
            continue
        return True
    return False


def _has_evidence_language_overclaim(answer: str) -> bool:
    for pattern in EVIDENCE_LANGUAGE_OVERCLAIM_PATTERNS:
        match = pattern.search(answer)
        if match is None:
            continue
        claim = match.group(0)
        if re.search(r"\b(?:does|do|did|will|can|is|are)\s+not\b|\bnot\s+(?:proof|proven|established|confirmed)\b", claim):
            continue
        return True
    return False


def _json_default(value: object) -> str:
    return str(value)


def _instrumentation(
    context: dict,
    *,
    context_ms: float,
    prompt_ms: float,
    ai_ms: float,
    postprocess_ms: float,
    engine_ms: float,
    context_chars: int,
    prompt_chars: int,
    output_token_budget: int,
) -> dict:
    provenance = context.get("provenance") or {}
    counts = provenance.get("evidence_counts") or {}
    recent_messages = ((context.get("conversation") or {}).get("recent_messages") or [])
    return {
        "context_ms": context_ms,
        "prompt_ms": prompt_ms,
        "ai_ms": ai_ms,
        "postprocess_ms": postprocess_ms,
        "engine_ms": engine_ms,
        "prompt_chars": int(prompt_chars),
        "context_chars": int(context_chars),
        "history_message_count": len(recent_messages),
        "evidence_scan_count": int(counts.get("scans") or 0),
        "evidence_finding_count": int(counts.get("findings") or 0),
        "evidence_artifact_count": int(counts.get("artifacts") or 0),
        "output_token_budget": int(output_token_budget),
    }


def _elapsed_ms(started: float) -> float:
    return round((perf_counter() - started) * 1000, 3)
