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
    "Observed Facts",
    "- Use the deterministic testssl.sh result for scanner-reported protocols, certificate metadata, cipher observations, headers, findings, severities, and wording.",
    "",
    "Potential Risks",
    "- testssl.sh evidence is TLS scanner output only; it does not by itself prove exploitability, compromise, robust configuration, or overall endpoint security.",
    "",
    "Confidence",
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
    re.compile(r"\b(?:low|warn|warning|medium|high|critical)\b[^.!?]{0,80}\b(?:breach|early[_ -]?data|heartbleed|lucky13|poodle|crime|freak|logjam|drown|sweet32|ticketbleed|ccs)\b[^.!?]{0,100}\b(?:proves?|confirms?|means|shows|demonstrates)\b[^.!?]{0,80}\b(?:exploitable|exploitation|vulnerable|vulnerability|compromise)\b"),
    re.compile(r"\b(?:breach|early[_ -]?data|heartbleed|lucky13|poodle|crime|freak|logjam|drown|sweet32|ticketbleed|ccs)\b[^.!?]{0,100}\b(?:proves?|confirms?|means|shows|demonstrates)\b[^.!?]{0,80}\b(?:exploitable|exploitation|vulnerable|vulnerability|compromise)\b"),
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
    return _guard_truthfulness_response(lines or list(FALLBACK_LINES), finding)


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
            "Observed Facts",
            "Observed Assets",
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
    weak_protocols = evidence.get("weak_protocols") or []
    if weak_protocols:
        lines.append("- Weak/deprecated protocol observations:")
        for item in weak_protocols[:20]:
            lines.append(f"  - {_clean(item)}")

    ok_records, potential_records = _split_scanner_records(evidence)
    if ok_records:
        lines.append("- Scanner OK/INFO observations (record IDs are scanner checks, not TLS safety verdicts):")
        for item in ok_records[:30]:
            lines.append(_format_record_line(item))
    if potential_records:
        lines.append("- Potential scanner findings requiring context/validation:")
        for item in potential_records[:30]:
            lines.append(_format_record_line(item))
    for limitation in evidence.get("limitations") or []:
        lines.append(f"- Limitation: {_clean(limitation)}")
    if not evidence:
        lines.append("- Limitation: No structured testssl.sh evidence was stored.")
        lines.append("- Limitation: Absence of structured TLS evidence does not prove the endpoint is secure or that no TLS vulnerabilities exist.")
    return "\n".join(lines)


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:500]


def _guard_truthfulness_response(lines: list[str], finding: dict | None = None) -> list[str]:
    if _contains_unsupported_testssl_claim(lines):
        return _build_truthfulness_fallback(finding or {})
    return lines


def _build_truthfulness_fallback(finding: dict) -> list[str]:
    evidence = finding.get("testssl_evidence") or {}
    summary = finding.get("testssl_summary") or {}
    certificate = evidence.get("certificate") or {}
    target = _clean(finding.get("target") or evidence.get("target") or evidence.get("host") or "unknown")
    host = _clean(evidence.get("host") or target)
    port = _clean(evidence.get("port") or "unknown")
    protocols = summary.get("supported_protocols") or [
        item.get("name")
        for item in evidence.get("protocols") or []
        if _looks_supported(item.get("finding"), item.get("severity"))
    ]
    notable = _collect_notable_records(evidence)
    lines = [
        "Executive Summary",
        "- The generated testssl.sh AI assessment was replaced because it made an unsupported TLS security conclusion. The summary below is deterministic and limited to stored scanner evidence.",
        "",
        "Observed Facts",
        f"- Target: {target}.",
        f"- Observed service endpoint: {host}:{port}.",
        f"- Supported protocols reported by testssl.sh: {_clean(', '.join(str(item) for item in protocols if item) or 'none extracted')}.",
        f"- Certificate common name: {_clean(certificate.get('common_name') or 'not extracted')}.",
        f"- Certificate expiry: {_clean(certificate.get('not_after') or 'not extracted')}.",
        f"- Notable scanner records: {len(notable)}.",
    ]
    for item in notable:
        lines.append(_format_record_line(item))
    lines.extend(
        [
            "",
            "Observed Assets",
            f"- {host}:{port}",
            "",
            "Potential Risks",
            "- Scanner LOW/WARN/HIGH findings are potential TLS configuration observations requiring deployment context and validation; they are not proof of exploitability or compromise.",
            "- Scanner OK/INFO records are preserved as scanner wording only and are not an overall secure, safe, robust, or hardened TLS verdict.",
            "",
            "Confidence",
            "- Medium: this is based on stored normalized testssl.sh output. It preserves scanner severities and wording, but testssl.sh alone does not establish overall endpoint security.",
            "",
            "Recommended Next Actions",
            "- Review the scanner-reported records with the service owner and validate any potential finding in application and deployment context before drawing remediation or risk conclusions.",
        ]
    )
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


def _split_scanner_records(evidence: dict) -> tuple[list[dict], list[dict]]:
    records = _all_scanner_records(evidence)
    ok_records = []
    potential_records = []
    for record in records:
        severity = str(record.get("severity") or "").upper()
        finding = str(record.get("finding") or "").lower()
        negative_scanner_observation = any(term in finding for term in ("not vulnerable", "not offered", "not supported", "no vulnerability", "no "))
        if severity in {"OK", "INFO"} and (
            negative_scanner_observation or not any(term in finding for term in ("potentially vulnerable", "vulnerable", "weak", "risk"))
        ):
            ok_records.append(record)
        else:
            potential_records.append(record)
    return ok_records, potential_records


def _all_scanner_records(evidence: dict) -> list[dict]:
    records = []
    for key in ("vulnerabilities", "cipher_findings", "security_headers", "notable_findings"):
        for item in evidence.get(key) or []:
            if isinstance(item, dict):
                records.append(item)
    return records


def _collect_notable_records(evidence: dict) -> list[dict]:
    return [item for item in _all_scanner_records(evidence) if _is_notable_record(item)]


def _is_notable_record(item: dict) -> bool:
    severity = str(item.get("severity") or "").upper()
    finding = str(item.get("finding") or "").lower()
    if severity in {"HIGH", "CRITICAL", "MEDIUM", "LOW", "WARN", "WARNING"}:
        return True
    return not any(term in finding for term in ("not vulnerable", "not offered", "not supported", "no vulnerability"))


def _looks_supported(finding: object, severity: object = None) -> bool:
    text = str(finding or "").lower()
    sev = str(severity or "").upper()
    if sev in {"OK", "INFO"} and any(term in text for term in ("not offered", "not supported", "no ")):
        return False
    return any(term in text for term in ("offered", "supported", "yes", "enabled", "available"))


def _format_record_line(item: dict) -> str:
    return (
        f"  - {_clean(item.get('id') or 'finding')} "
        f"severity={_clean(item.get('severity') or 'INFO')} "
        f"finding={_clean(item.get('finding') or '')}"
    )
