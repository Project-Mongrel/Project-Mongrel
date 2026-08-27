import json
import re

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


def answer_assessment_conversation_question(
    *,
    user_id: int,
    assessment_id: int,
    conversation_id: str | None,
    question: str,
) -> dict:
    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment_id,
        conversation_id=conversation_id,
        question=question,
    )
    prompt = build_assessment_conversation_prompt(context)
    try:
        response = ask_ai(prompt, num_predict=_conversation_num_predict())
    except Exception:
        return _result(FALLBACK_ANSWER, context, fallback_reason="exception")

    if _is_unavailable_response(response):
        return _result(FALLBACK_ANSWER, context, fallback_reason="ai_unavailable")

    answer = str(response or "").strip()
    if not answer:
        return _result(FALLBACK_ANSWER, context, fallback_reason="empty")
    if violates_conversation_truthfulness(answer, context):
        return _result(TRUTHFULNESS_FALLBACK_ANSWER, context, fallback_reason="truthfulness_guard")
    return _result(answer, context)


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
            "- You may recommend tools, but every recommendation must explain why and must not execute anything.",
            "- Active or invasive execution must remain behind Mongrel's existing explicit approval and execution flows.",
            "- Adapt depth to the user: plain English for beginner questions, concise technical comparison for experienced questions.",
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
    if SESSION_CLAIM_PATTERN.search(normalized) and not _metasploit_session_established(context or {}):
        return True
    return False


def _result(answer: str, context: dict, fallback_reason: str | None = None) -> dict:
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


def _json_default(value: object) -> str:
    return str(value)
