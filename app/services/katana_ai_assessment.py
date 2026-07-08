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
    "Katana AI assessment unavailable.",
    "Use the deterministic Katana result for observed crawl surface and next actions.",
]


def generate_katana_ai_assessment(finding: dict) -> list[str]:
    prompt = build_katana_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return lines or list(FALLBACK_LINES)


def build_katana_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing web crawl notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied observed Katana evidence.",
            "- Do not invent vulnerabilities.",
            "- Do not invent URLs, endpoints, JavaScript files, forms, parameters, hosts, or status codes.",
            "- Do not call a discovered URL a vulnerable endpoint unless the supplied evidence proves it.",
            "- Describe discovered URLs and endpoints as attack surface, not confirmed risk.",
            "- Do not claim compromise.",
            "- Do not recommend exploitation.",
            "- Do not claim the target is safe or secure.",
            "- A small crawl surface under HTTP 429 or challenge conditions means crawl visibility was limited, not that site structure is limited.",
            "- Explain what the crawl surface suggests and what follow-up actions are reasonable.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Mention uncertainty clearly when evidence is limited.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Facts",
            "Crawl Surface Notes",
            "Potential Risks",
            "Confidence",
            "Recommended Next Actions",
            "",
            "Observed Katana Evidence:",
            _format_katana_evidence(finding),
        ]
    )


def _format_katana_evidence(finding: dict) -> str:
    observations = finding.get("katana_observations") or []
    summary = finding.get("katana_summary") or {}
    metadata = finding.get("metadata") or {}
    lines = [
        f"- Target: {_clean(finding.get('target') or 'unknown')}",
        f"- Status: {_clean(finding.get('status') or 'unknown')}",
        f"- URL/endpoint count: {int(finding.get('finding_count') or len(observations) or 0)}",
        f"- Unique hosts: {int(summary.get('host_count') or 0)}",
        f"- JavaScript files: {int(summary.get('javascript_count') or 0)}",
        f"- Query parameters: {int(summary.get('query_parameter_count') or 0)}",
        f"- Forms/actions: {int(summary.get('form_count') or 0)}",
        f"- Max observed crawl depth: {int(summary.get('max_depth') or 0)}",
        f"- Configured crawl depth: {_clean(metadata.get('crawl_depth') or 'not supplied')}",
    ]
    parameters = summary.get("query_parameters") or []
    if parameters:
        lines.append("- Query parameter names: " + ", ".join(_clean(value) for value in parameters[:30]))
    if not observations:
        lines.append("- Limitation: No structured Katana crawl observations were stored.")
        return "\n".join(lines)

    lines.append("- Observed crawl records:")
    for observation in observations[:30]:
        parts = [
            f"url={_clean(observation.get('url') or 'unknown')}",
            f"type={_clean(observation.get('endpoint_type') or 'url')}",
        ]
        if observation.get("method"):
            parts.append(f"method={_clean(observation.get('method'))}")
        if observation.get("status_code"):
            parts.append(f"status={_clean(observation.get('status_code'))}")
        if observation.get("depth") is not None:
            parts.append(f"depth={_clean(observation.get('depth'))}")
        if observation.get("source"):
            parts.append(f"source={_clean(observation.get('source'))}")
        if observation.get("query_parameters"):
            parts.append("params=" + ", ".join(_clean(value) for value in observation.get("query_parameters")[:10]))
        if observation.get("forms"):
            parts.append(f"forms={len(observation.get('forms') or [])}")
        lines.append("  - " + " ".join(parts))
    return "\n".join(lines)


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:500]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
