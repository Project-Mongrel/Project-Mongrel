import re

from app.services.ai_client import ask_ai

AI_UNAVAILABLE_MESSAGES = (
    "AI integration is not configured yet.",
    "Unsupported AI provider.",
    "Ollama base URL is not configured.",
    "AI request timed out.",
    "Unable to connect to Ollama server.",
    "AI request failed.",
    "Malformed Ollama response.",
    "Empty AI response.",
    "Mongrel generated internal reasoning but no final answer.",
)

FALLBACK_LINES = [
    "Gitleaks AI assessment unavailable.",
    "Use the deterministic Gitleaks result for redacted secret-exposure evidence and next actions.",
]

TRUTHFULNESS_FALLBACK_LINES = [
    "Gitleaks AI assessment withheld.",
    "The generated response contained an unsupported conclusion about secret validity, usability, ownership, compromise, or repository security.",
    "Use the deterministic Gitleaks result for redacted secret-pattern evidence and review/rotation decisions.",
]

EVIDENCE_SCOPED_MARKERS = (
    "not established",
    "not validated",
    "were not validated",
    "was not validated",
    "not confirmed",
    "does not prove",
    "does not establish",
    "not proof",
    "insufficient",
    "unknown",
    "within the scanned scope",
    "within scanned scope",
    "within the configured rules",
)

UNSUPPORTED_GITLEAKS_CLAIM_PATTERNS = (
    re.compile(r"\bactive\s+(?:credential|credentials|token|tokens|key|keys|secret|secrets)\b[^.!?]{0,100}\b(?:exposed|leaked|found|detected|reported)\b"),
    re.compile(r"\b(?:credential|credentials|token|tokens|key|keys|secret|secrets)\b[^.!?]{0,100}\b(?:is|are|was|were|has\s+been|have\s+been)\s+(?:valid|active|usable|live)\b"),
    re.compile(r"\b(?:credential|credentials|token|tokens|key|keys|secret|secrets)\b[^.!?]{0,100}\b(?:can|could)\s+(?:be\s+)?(?:used|provide|grant)\b"),
    re.compile(r"\b(?:attacker|attackers|unauthori[sz]ed\s+user|unauthori[sz]ed\s+access)\b[^.!?]{0,100}\b(?:can|could|has|have|gained|confirmed)\b[^.!?]{0,100}\b(?:access|use|occurred)\b"),
    re.compile(r"\b(?:repository|repo|target|system)\b[^.!?]{0,100}\b(?:is|was|has\s+been)\s+(?:compromised|secure|safe|insecure)\b"),
    re.compile(r"\b(?:compromise|compromised)\b[^.!?]{0,100}\b(?:confirmed|occurred|detected|proven)\b"),
    re.compile(r"\b(?:sensitive\s+data|data|credentials|credential|secrets|secret)\b[^.!?]{0,100}\b(?:was|were|has\s+been|have\s+been)?\s*(?:leaked|exfiltrated)\b"),
    re.compile(r"\b(?:leaked|exposed)\s+(?:credential|credentials|token|tokens|key|keys|secret|secrets)\b[^.!?]{0,100}\b(?:confirmed|valid|active|usable)?\b"),
    re.compile(r"\b(?:no|zero)\s+(?:secrets|credentials|tokens|keys)\b[^.!?]{0,100}\b(?:exist|are\s+exposed|were\s+found|detected)\b"),
)


def generate_gitleaks_ai_assessment(finding: dict) -> list[str]:
    prompt = build_gitleaks_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)
    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)
    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return _guard_truthfulness_response(lines or list(FALLBACK_LINES))


def build_gitleaks_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing secret-exposure notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied redacted Gitleaks evidence.",
            "- Never include or infer raw secret values.",
            "- Do not validate, use, or test credentials.",
            "- Do not claim compromise.",
            "- Do not claim detected values are valid, active, usable, owned by the target, or known to provide access.",
            "- Do not claim unauthorized access, exfiltration, or repository security/insecurity from Gitleaks evidence alone.",
            "- If there are zero findings, say Gitleaks did not report matches within the scanned scope/rules; do not say no secrets exist.",
            "- Treat detections as secret-exposure evidence, not proof of account access.",
            "- Recommend review and rotation/revocation if the potential secret is confirmed.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Redacted Facts",
            "Potential Risks",
            "Recommended Next Actions",
            "Confidence",
            "Evidence Limitations",
            "",
            "Observed Gitleaks Evidence:",
            _format_gitleaks_evidence(finding),
        ]
    )


def _format_gitleaks_evidence(finding: dict) -> str:
    evidence = finding.get("gitleaks_evidence") or {}
    summary = finding.get("gitleaks_summary") or {}
    lines = [
        f"- Scope: {_clean(evidence.get('scan_root') or finding.get('target') or 'unknown')}",
        f"- Status: {_clean(finding.get('status') or 'unknown')}",
        f"- Secret finding count: {int(summary.get('finding_count') or 0)}",
        f"- Affected files count: {int(summary.get('affected_files_count') or 0)}",
        f"- Rule summary: {_format_counts(summary.get('rule_summary') or {})}",
        f"- Provider summary: {_format_counts(summary.get('provider_summary') or {})}",
        f"- Severity summary: {_format_counts(summary.get('severity_summary') or {})}",
    ]
    findings = evidence.get("findings") or []
    if findings:
        lines.append("- Redacted findings:")
        for item in findings[:30]:
            lines.append(
                "  - "
                f"rule={_clean(item.get('rule_id') or 'unknown')} "
                f"file={_clean(item.get('file_path') or 'unknown')} "
                f"line={_clean(item.get('line_number') or 'unknown')} "
                f"provider={_clean(item.get('provider') or 'unknown')} "
                f"severity={_clean(item.get('severity') or 'unknown')} "
                f"fingerprint={_clean(item.get('fingerprint') or 'not supplied')} "
                f"secret={_clean(item.get('redacted_secret_preview') or '<REDACTED>')}"
            )
    else:
        lines.append("- Redacted findings: none recorded")
        lines.append("- Zero findings only means Gitleaks reported no matches within the scanned scope and configured rules.")
    for limitation in evidence.get("limitations") or []:
        lines.append(f"- Limitation: {_clean(limitation)}")
    lines.append("- Boundary: Gitleaks output is secret-pattern detection evidence only; validity, current usability, ownership, access, compromise, exfiltration, and repository security were not established.")
    return "\n".join(lines)


def _format_counts(counts: dict) -> str:
    return ", ".join(f"{_clean(key)}={int(value or 0)}" for key, value in sorted(counts.items())) if counts else "none"


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:500]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)


def _guard_truthfulness_response(lines: list[str]) -> list[str]:
    if _contains_unsupported_claim(lines):
        return list(TRUTHFULNESS_FALLBACK_LINES)
    return lines


def _contains_unsupported_claim(lines: list[str]) -> bool:
    for sentence in _claim_sentences(lines):
        lowered = sentence.lower()
        if _is_evidence_scoped_statement(lowered):
            continue
        if any(pattern.search(lowered) for pattern in UNSUPPORTED_GITLEAKS_CLAIM_PATTERNS):
            return True
    return False


def _claim_sentences(lines: list[str]) -> list[str]:
    text = " ".join(str(line or "").strip() for line in lines if str(line or "").strip())
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", text) if part.strip()]


def _is_evidence_scoped_statement(sentence: str) -> bool:
    return any(marker in sentence for marker in EVIDENCE_SCOPED_MARKERS)
