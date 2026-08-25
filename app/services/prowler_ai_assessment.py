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
    "Prowler AI assessment unavailable.",
    "Use the deterministic Prowler result for scanner-reported cloud posture evidence and next actions.",
]

TRUTHFULNESS_FALLBACK_LINES = [
    "Prowler AI assessment withheld.",
    "The generated response contained an unsupported conclusion about cloud security, exploitability, compromise, exposure, or compliance.",
    "Use the deterministic Prowler result for scanner-reported PASS/FAIL checks, severity, resource metadata, and remediation review.",
]

EVIDENCE_SCOPED_MARKERS = (
    "does not prove",
    "does not establish",
    "not proof",
    "not confirmed",
    "not established",
    "not automatically",
    "specific tested check",
    "specific check",
    "within the scanned scope",
    "within scanned scope",
    "requires validation",
    "should be reviewed",
)

UNSUPPORTED_PROWLER_CLAIM_PATTERNS = (
    re.compile(r"\b(?:aws|azure|gcp|cloud)?\s*(?:account|environment|resource|service|bucket|instance|tenant|target)\b[^.!?]{0,100}\b(?:is|are|was|were|appears|seems|looks)\s+(?:to\s+be\s+)?(?:secure|safe|hardened|fully\s+protected|protected)\b"),
    re.compile(r"\b(?:confirmed|proven|validated)\s+(?:exploitable\s+)?(?:vulnerability|vulnerabilities|misconfiguration|misconfigurations)\b"),
    re.compile(r"\b(?:vulnerability|vulnerabilities|misconfiguration|misconfigurations)\b[^.!?]{0,100}\b(?:is|are|was|were|has\s+been|have\s+been)\s+(?:confirmed|proven|validated|exploitable)\b"),
    re.compile(r"\b(?:resource|service|bucket|instance|account|environment|target)\b[^.!?]{0,100}\b(?:is|are|was|were|can\s+be|could\s+be)\s+(?:exploitable|exploited|vulnerable)\b"),
    re.compile(r"\b(?:attacker|attackers|unauthori[sz]ed\s+user|unauthori[sz]ed\s+access)\b[^.!?]{0,100}\b(?:can|could|has|have|gained|confirmed)\b[^.!?]{0,100}\b(?:access|exploit|use|occurred)\b"),
    re.compile(r"\b(?:confirms?|proves?|establishes?)\b[^.!?]{0,80}\b(?:compromise|breach|unauthori[sz]ed\s+access|data\s+exposure|data\s+exfiltration)\b"),
    re.compile(r"\b(?:compromise|compromised|breach|breached)\b[^.!?]{0,100}\b(?:confirmed|occurred|detected|proven|established)\b"),
    re.compile(r"\b(?:sensitive\s+data|data|secrets|credentials|customer\s+data)\b[^.!?]{0,100}\b(?:is|are|was|were|has\s+been|have\s+been)?\s*(?:exposed|leaked|exfiltrated|stolen)\b"),
    re.compile(r"\b(?:organization|organisation|company|cloud\s+account|aws\s+account|azure\s+tenant|gcp\s+project|environment)\b[^.!?]{0,100}\b(?:is|are|was|were)\s+(?:compliant|non-compliant|noncompliant)\b"),
    re.compile(r"\b(?:organization|organisation|company|cloud\s+account|aws\s+account|azure\s+tenant|gcp\s+project|environment)\b[^.!?]{0,100}\b(?:violates|breaches|fails)\s+(?:gdpr|hipaa|pci|pci-dss|cis|soc\s*2|iso)\b"),
    re.compile(r"\b(?:no|zero)\s+(?:vulnerabilities|misconfigurations|security\s+issues|security\s+risks|attack\s+paths)\b[^.!?]{0,100}\b(?:exist|were\s+found|were\s+detected|are\s+present|remain)\b"),
)

_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(access[_-]?key|secret[_-]?key|session[_-]?token|api[_-]?key|password)\s*[:=]\s*\S+"),
)


def generate_prowler_ai_assessment(finding: dict) -> list[str]:
    prompt = build_prowler_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)
    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)
    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return _guard_truthfulness_response(lines or list(FALLBACK_LINES))


def build_prowler_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior cloud security consultant preparing Prowler assessment notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied normalized Prowler evidence.",
            "- Do not request, include, infer, or expose raw cloud credentials, cloud access keys, secret keys, or session tokens.",
            "- Do not include huge raw JSON or unnormalized scanner output.",
            "- Preserve Prowler scanner-reported PASS, FAIL, and severity wording.",
            "- PASS means Prowler reported the specific tested check as passed; it does not prove the resource, service, account, or environment is secure, hardened, vulnerability-free, or compliant.",
            "- FAIL means Prowler reported a failed check; it is not proof of exploitability, compromise, unauthorized access, data exposure, data theft, or an attack path.",
            "- Severity is Prowler scanner-reported severity for the check, not proof of exploitability, likelihood, compromise, or business impact.",
            "- Compliance mappings are check/control mappings only; do not state organization-wide compliance or non-compliance.",
            "- If no FAIL findings are reported, say only that no failing conditions were reported within the scanned scope; do not say no misconfigurations or vulnerabilities exist.",
            "- Preserve partial/failed scan uncertainty when credentials, permissions, provider APIs, skipped checks, regions, or services limit coverage.",
            "- Use cautious language such as could allow, may indicate, and requires validation in cloud context.",
            "- Do not invent exploitability, breach, attack paths, account compromise, attacker access, data exposure, or regulatory conclusions.",
            "- Separate observed scanner-reported facts from potential risk themes and next actions.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Scanner-Reported Facts",
            "Most Important Failed Checks",
            "Potential Risk Themes",
            "Recommended Next Actions",
            "Evidence Confidence / Limitations",
            "",
            "Normalized Prowler Evidence:",
            _format_prowler_evidence(finding),
        ]
    )


def _format_prowler_evidence(finding: dict) -> str:
    evidence = finding.get("prowler_evidence") or {}
    summary = finding.get("prowler_summary") or {}
    provider = _clean(finding.get("provider") or evidence.get("provider") or "unknown").upper()
    cloud_context = _clean(finding.get("cloud_context") or evidence.get("cloud_context") or finding.get("target") or "unknown")
    lines = [
        f"- Provider: {provider}",
        f"- Context: {cloud_context}",
        f"- Status: {_clean(finding.get('status') or 'unknown')}",
        f"- Total checks/findings parsed: {int(summary.get('finding_count') or evidence.get('finding_count') or 0)}",
        f"- Failed checks: {int(summary.get('failed_count') or 0)}",
        f"- Passed checks: {int(summary.get('passed_count') or 0)}",
        f"- Highest scanner-reported severity: {_clean(summary.get('highest_severity') or 'none')}",
        "- Top failed services: " + _format_list(summary.get("top_failed_services") or []),
    ]

    findings = evidence.get("findings") or []
    if findings:
        lines.append("- Normalized checks:")
        for item in findings[:40]:
            lines.append(
                "  - "
                f"status={_clean(item.get('status') or 'unknown')} "
                f"severity={_clean(item.get('severity') or 'unknown')} "
                f"check_id={_clean(item.get('check_id') or 'unknown')} "
                f"title={_clean(item.get('check_title') or 'unknown')} "
                f"service={_clean(item.get('service') or 'unknown')} "
                f"region={_clean(item.get('region') or 'unknown')} "
                f"resource={_clean(item.get('resource_identifier') or item.get('resource_name') or 'not supplied')} "
                f"interpretation={_clean(item.get('status_interpretation') or 'scanner_reported_status')}"
            )
    else:
        lines.append("- Normalized checks: none recorded")

    for limitation in evidence.get("limitations") or []:
        lines.append(f"- Limitation: {_clean(limitation)}")
    lines.append("- Boundary: Prowler output is scanner-reported cloud check evidence only; PASS/FAIL, severity, compliance mappings, and resource metadata do not by themselves prove security posture, exploitability, compromise, data exposure, or organization-wide compliance.")
    return "\n".join(lines)


def _format_list(values: list[object]) -> str:
    return ", ".join(_clean(value) for value in values[:10]) if values else "none"


def _clean(value: object) -> str:
    text = str(value or "").replace("\n", " ").strip()[:500]
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("<REDACTED>", text)
    return text


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)


def _guard_truthfulness_response(lines: list[str]) -> list[str]:
    if _contains_unsupported_prowler_claim(lines):
        return list(TRUTHFULNESS_FALLBACK_LINES)
    return lines


def _contains_unsupported_prowler_claim(lines: list[str]) -> bool:
    for sentence in _claim_sentences(lines):
        if _is_evidence_scoped_statement(sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_PROWLER_CLAIM_PATTERNS):
            return True
    return False


def _claim_sentences(lines: list[str]) -> list[str]:
    text = " ".join(str(line or "").strip() for line in lines if str(line or "").strip())
    return [
        re.sub(r"\s+", " ", sentence).strip().lower()
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", text)
        if sentence.strip()
    ]


def _is_evidence_scoped_statement(sentence: str) -> bool:
    return any(marker in sentence for marker in EVIDENCE_SCOPED_MARKERS)
