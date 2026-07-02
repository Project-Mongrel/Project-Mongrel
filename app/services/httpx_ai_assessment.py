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
    "httpx AI assessment unavailable.",
    "Use the deterministic httpx result for observed HTTP fingerprinting and next actions.",
]


def generate_httpx_ai_assessment(finding: dict) -> list[str]:
    prompt = build_httpx_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return lines or list(FALLBACK_LINES)


def build_httpx_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing HTTP fingerprinting notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied observed httpx evidence.",
            "- Do not invent vulnerabilities.",
            "- Do not invent assets, URLs, technologies, headers, redirects, or status codes.",
            "- Do not claim compromise.",
            "- Do not recommend exploitation.",
            "- Do not claim the target is safe or secure.",
            "- Explain what the HTTP fingerprinting suggests and what follow-up actions are reasonable.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Mention uncertainty clearly when evidence is limited.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Facts",
            "HTTP Fingerprinting Notes",
            "Potential Risks",
            "Confidence",
            "Recommended Next Actions",
            "",
            "Observed httpx Evidence:",
            _format_httpx_evidence(finding),
        ]
    )


def _format_httpx_evidence(finding: dict) -> str:
    services = finding.get("httpx_services") or []
    summary = finding.get("httpx_summary") or {}
    metadata = finding.get("metadata") or {}
    lines = [
        f"- Target: {_clean(finding.get('target') or 'unknown')}",
        f"- Status: {_clean(finding.get('status') or 'unknown')}",
        f"- HTTP service/URL count: {int(finding.get('finding_count') or len(services) or 0)}",
        f"- Elapsed time: {_clean(metadata.get('elapsed') or metadata.get('elapsed_seconds') or 'not supplied')}",
    ]
    status_codes = summary.get("status_codes") or {}
    if status_codes:
        lines.append("- Status codes: " + ", ".join(f"{_clean(code)}={int(count or 0)}" for code, count in sorted(status_codes.items())))
    technologies = summary.get("technologies") or []
    if technologies:
        lines.append("- Technologies: " + ", ".join(_clean(value) for value in technologies[:20]))
    if not services:
        lines.append("- Limitation: No structured httpx service observations were stored.")
        return "\n".join(lines)

    lines.append("- Observed HTTP services:")
    for service in services[:20]:
        parts = [
            f"url={_clean(service.get('url') or service.get('host') or 'unknown')}",
            f"status={_clean(service.get('status_code') or 'unknown')}",
        ]
        if service.get("title"):
            parts.append(f"title={_clean(service.get('title'))}")
        if service.get("web_server"):
            parts.append(f"server={_clean(service.get('web_server'))}")
        if service.get("technologies"):
            parts.append("tech=" + ", ".join(_clean(value) for value in service.get("technologies")[:8]))
        if service.get("redirect_location") or service.get("final_url"):
            parts.append(f"redirect={_clean(service.get('redirect_location') or service.get('final_url'))}")
        if service.get("tls"):
            parts.append("tls_metadata=present")
        lines.append("  - " + " ".join(parts))
    return "\n".join(lines)


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:500]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
