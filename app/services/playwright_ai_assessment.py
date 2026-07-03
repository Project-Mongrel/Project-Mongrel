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
    "Playwright AI assessment unavailable.",
    "Use the deterministic Playwright result for observed browser behavior and next actions.",
]


def generate_playwright_ai_assessment(finding: dict) -> list[str]:
    prompt = build_playwright_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return lines or list(FALLBACK_LINES)


def build_playwright_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing passive browser-observation notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied observed Playwright evidence.",
            "- Do not invent vulnerabilities.",
            "- Do not invent URLs, forms, links, console errors, network errors, titles, or status codes.",
            "- Do not say the site is safe or vulnerable from page load alone.",
            "- Describe observations as browser behavior and web surface, not confirmed vulnerabilities.",
            "- Do not claim compromise.",
            "- Do not recommend exploitation.",
            "- No clicking, form submission, login attempts, or bot-bypass activity was performed.",
            "- Explain what the browser observation suggests and what follow-up actions are reasonable.",
            "- Mention uncertainty clearly when evidence is limited.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Facts",
            "Browser Surface Notes",
            "Potential Risks",
            "Confidence",
            "Recommended Next Actions",
            "",
            "Observed Playwright Evidence:",
            _format_playwright_evidence(finding),
        ]
    )


def _format_playwright_evidence(finding: dict) -> str:
    observation = finding.get("playwright_observation") or {}
    summary = finding.get("playwright_summary") or {}
    metadata = finding.get("metadata") or {}
    lines = [
        f"- Target: {_clean(finding.get('target') or 'unknown')}",
        f"- Status: {_clean(finding.get('status') or 'unknown')}",
        f"- Requested URL: {_clean(observation.get('requested_url') or summary.get('requested_url') or 'unknown')}",
        f"- Final URL: {_clean(observation.get('final_url') or summary.get('final_url') or 'unknown')}",
        f"- Title: {_clean(observation.get('title') or summary.get('title') or 'not observed')}",
        f"- Load status: {_clean(observation.get('load_status') or summary.get('load_status') or 'unknown')}",
        f"- Status code: {_clean(observation.get('status_code') or summary.get('status_code') or 'not observed')}",
        f"- Forms: {int(summary.get('forms_count') or observation.get('forms_count') or 0)}",
        f"- Inputs: {int(summary.get('inputs_count') or observation.get('inputs_count') or 0)}",
        f"- Links: {int(summary.get('links_count') or observation.get('links_count') or 0)}",
        f"- Console issues: {int(summary.get('console_issue_count') or observation.get('console_issue_count') or 0)}",
        f"- Network issues: {int(summary.get('network_issue_count') or observation.get('network_issue_count') or 0)}",
        f"- Page errors: {int(summary.get('page_error_count') or observation.get('page_error_count') or 0)}",
        f"- Screenshot metadata present: {bool(summary.get('screenshot_present') or observation.get('screenshot'))}",
        f"- Elapsed time: {_clean(metadata.get('elapsed_seconds') or 'not supplied')}",
    ]
    links = observation.get("link_samples") or []
    if links:
        lines.append("- Link samples:")
        lines.extend(f"  - {_clean(link)}" for link in links[:10])
    redirects = observation.get("redirects") or []
    if redirects:
        lines.append("- Redirect chain:")
        lines.extend(f"  - {_clean(redirect)}" for redirect in redirects[:10])
    limitations = observation.get("limitations") or []
    if limitations:
        lines.append("- Limitations:")
        lines.extend(f"  - {_clean(limitation)}" for limitation in limitations[:10])
    return "\n".join(lines)


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:500]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
