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
    return lines or list(FALLBACK_LINES)


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
            "- PASS means Prowler reported the check as passed.",
            "- FAIL means Prowler reported a failed check.",
            "- FAIL does not automatically mean confirmed exploitable vulnerability.",
            "- Severity is scanner-reported severity, not proof of real-world exploitability.",
            "- Use cautious language such as could allow, may indicate, and requires validation in cloud context.",
            "- Do not invent exploitability, breach, attack paths, account compromise, or attacker access.",
            "- Do not claim a compliance breach unless Prowler evidence explicitly includes compliance metadata.",
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
