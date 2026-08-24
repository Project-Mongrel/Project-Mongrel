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
    "testssl.sh AI assessment unavailable.",
    "Use the deterministic testssl.sh result for TLS configuration evidence and next actions.",
]
TRUTHFULNESS_FALLBACK_LINES = [
    "Executive Summary",
    "- The testssl.sh AI assessment was withheld because the generated response contained an unsupported TLS security conclusion.",
    "",
    "Observed TLS Facts",
    "- Use the deterministic testssl.sh result for scanner-reported protocols, certificate metadata, cipher observations, headers, findings, severities, and wording.",
    "",
    "Interpretation",
    "- testssl.sh evidence is TLS scanner output only; it does not by itself prove exploitability, compromise, robust configuration, or overall endpoint security.",
    "",
    "Limitations / Uncertainty",
    "- Potential findings require validation in the application and deployment context. Absence of reported findings is not proof that TLS vulnerabilities do not exist.",
    "",
    "Recommended Next Actions",
    "- Review scanner-reported TLS observations with the service owner before drawing remediation or risk conclusions.",
]
EVIDENCE_SCOPED_MARKERS = (
    "testssl.sh reported",
    "scanner-reported",
    "scanner reported",
    "reported as potentially",
    "potentially vulnerable",
    "does not establish",
    "does not prove",
    "not proof",
    "requires validation",
    "requiring validation",
    "depends on",
    "within its tested scope",
    "observed as supported",
    "was observed",
    "were observed",
    "severity",
    "finding=",
)
UNSUPPORTED_TESTSSL_CLAIM_PATTERNS = (
    re.compile(r"\b(?:tls|ssl|configuration|endpoint|site|target|server|host|service)\b[^.!?]{0,80}\b(?:is|are|was|were|appears|seems|looks)\s+(?:to\s+be\s+)?(?:secure|safe|robust|hardened|strong|compromised|exploitable)\b"),
    re.compile(r"\ball\s+(?:supported\s+)?ciphers?\b[^.!?]{0,80}\b(?:strong|secure|safe)\b"),
    re.compile(r"\b(?:breach|early[_ -]?data|heartbleed|lucky13|poodle|crime|freak|logjam|drown|sweet32|ticketbleed|ccs)\b[^.!?]{0,100}\b(?:is|are|was|were|can\s+be|has\s+been)?\s*(?:confirmed|exploitable|exploited|vulnerable|compromised)\b"),
    re.compile(r"\b(?:the\s+)?(?:site|target|server|host|endpoint)\b[^.!?]{0,80}\b(?:is|are|was|were)\s+(?:vulnerable|exploitable|compromised)\b"),
    re.compile(r"\bno\s+(?:(?:tls|ssl)\s+)?(?:vulnerabilities|security\s+issues|security\s+risks|weaknesses)\s+(?:exist|were\s+found|were\s+detected|found|detected)\b"),
    re.compile(r"\b(?:no|none)\s+of\s+the\s+(?:(?:tls|ssl)\s+)?(?:configuration|findings?)\b[^.!?]{0,80}\b(?:is|are|was|were)\s+(?:vulnerable|weak|risky)\b"),
)


def generate_testssl_ai_assessment(finding: dict) -> list[str]:
    prompt = build_testssl_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return _guard_truthfulness_response(lines or list(FALLBACK_LINES))


def build_testssl_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing TLS configuration notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied observed testssl.sh evidence.",
            "- Treat this as TLS configuration evidence only.",
            "- Do not invent TLS vulnerabilities, protocols, certificate fields, ciphers, headers, or grades.",
            "- Do not claim the overall site is safe or secure from TLS evidence alone.",
            "- Do not characterize TLS configuration as robust or provide a broad TLS safety verdict.",
            "- Do not say all supported ciphers are strong unless the supplied evidence explicitly states that.",
            "- Preserve scanner wording, severity labels, confidence, and uncertainty exactly.",
            "- Preserve 'potentially VULNERABLE' as scanner-reported potential evidence requiring validation, not confirmed exploitability.",
            "- BREACH findings are scanner-reported potential evidence unless the supplied evidence explicitly proves practical exploitability.",
            "- early_data severity must be described as scanner severity and contextualized; do not infer practical exploitability or compromise.",
            "- Supported, offered, and not offered protocol/cipher observations are observations only.",
            "- Absence of reported TLS findings does not prove the endpoint is secure or that no TLS vulnerabilities exist.",
            "- Preserve scanner confidence and describe early_data, LUCKY13, BREACH, and similar items as scanner-reported evidence requiring context and validation.",
            "- Do not claim exploitation or compromise.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Mention uncertainty clearly when evidence is limited.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed TLS Facts",
            "Certificate Notes",
            "Protocol and Cipher Notes",
            "Potential Risks",
            "Confidence",
            "Recommended Next Actions",
            "",
            "Observed testssl.sh Evidence:",
            _format_testssl_evidence(finding),
        ]
    )


def _format_testssl_evidence(finding: dict) -> str:
    evidence = finding.get("testssl_evidence") or {}
    summary = finding.get("testssl_summary") or {}
    metadata = finding.get("metadata") or {}
    certificate = evidence.get("certificate") or {}
    lines = [
        f"- Target: {_clean(finding.get('target') or evidence.get('target') or 'unknown')}",
        f"- Status: {_clean(finding.get('status') or evidence.get('scan_status') or 'unknown')}",
        f"- Host: {_clean(evidence.get('host') or 'unknown')}",
        f"- Port: {_clean(evidence.get('port') or 'unknown')}",
        f"- Elapsed time: {_clean(metadata.get('elapsed_seconds') or 'not supplied')}",
        f"- Supported protocols: {_clean(', '.join(summary.get('supported_protocols') or []) or 'none extracted')}",
        f"- Weak/deprecated protocol count: {int(summary.get('weak_protocol_count') or 0)}",
        f"- Notable TLS finding count: {int(summary.get('notable_count') or 0)}",
        "- Evidence boundary: testssl.sh observations are TLS scanner evidence only; preserve scanner severity and uncertainty.",
    ]
    if certificate:
        lines.extend(
            [
                f"- Certificate common name: {_clean(certificate.get('common_name') or 'not extracted')}",
                f"- Certificate subject: {_clean(certificate.get('subject') or 'not extracted')}",
                f"- Certificate issuer: {_clean(certificate.get('issuer') or 'not extracted')}",
                f"- Certificate expiry: {_clean(certificate.get('not_after') or 'not extracted')}",
                f"- Certificate SAN: {_clean(certificate.get('subject_alt_names') or 'not extracted')}",
            ]
        )
    protocols = evidence.get("protocols") or []
    if protocols:
        lines.append("- Protocol observations:")
        for protocol in protocols[:20]:
            lines.append(
                f"  - {_clean(protocol.get('name') or protocol.get('id') or 'unknown')} "
                f"severity={_clean(protocol.get('severity') or 'info')} finding={_clean(protocol.get('finding') or '')}"
            )
    for title, key in (
        ("Weak/deprecated observations", "weak_protocols"),
        ("Vulnerabilities/misconfigurations", "vulnerabilities"),
        ("Cipher findings", "cipher_findings"),
        ("Security header evidence", "security_headers"),
        ("Other notable findings", "notable_findings"),
    ):
        values = evidence.get(key) or []
        if values:
            lines.append(f"- {title}:")
            for item in values[:20]:
                if isinstance(item, dict):
                    lines.append(
                        f"  - {_clean(item.get('id') or 'finding')} severity={_clean(item.get('severity') or 'info')} "
                        f"finding={_clean(item.get('finding') or '')}"
                    )
                else:
                    lines.append(f"  - {_clean(item)}")
    for limitation in evidence.get("limitations") or []:
        lines.append(f"- Limitation: {_clean(limitation)}")
    if not evidence:
        lines.append("- Limitation: No structured testssl.sh evidence was stored.")
        lines.append("- Limitation: Absence of structured TLS evidence does not prove the endpoint is secure or that no TLS vulnerabilities exist.")
    return "\n".join(lines)


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:500]


def _guard_truthfulness_response(lines: list[str]) -> list[str]:
    if _contains_unsupported_testssl_claim(lines):
        return list(TRUTHFULNESS_FALLBACK_LINES)
    return lines


def _contains_unsupported_testssl_claim(lines: list[str]) -> bool:
    for sentence in _claim_sentences(lines):
        if _is_evidence_scoped_statement(sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_TESTSSL_CLAIM_PATTERNS):
            return True
    return False


def _claim_sentences(lines: list[str]) -> list[str]:
    text = " ".join(str(line or "").strip() for line in lines)
    return [
        re.sub(r"\s+", " ", sentence).strip().lower()
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", text)
        if sentence.strip()
    ]


def _is_evidence_scoped_statement(sentence: str) -> bool:
    return any(marker in sentence for marker in EVIDENCE_SCOPED_MARKERS)


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
