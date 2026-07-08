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
    "ffuf AI assessment unavailable.",
    "Use the deterministic ffuf result for hidden-content observations and next actions.",
]


def generate_ffuf_ai_assessment(finding: dict) -> list[str]:
    prompt = build_ffuf_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return lines or list(FALLBACK_LINES)


def build_ffuf_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing hidden-content discovery notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied observed ffuf evidence.",
            "- Do not invent vulnerabilities.",
            "- Do not invent paths, URLs, status codes, redirects, response sizes, words, or lines.",
            "- Do not claim discovered admin, backup, API, or config-looking paths are exploitable.",
            "- Phrase discovered paths as observations and follow-up candidates, not confirmed risk.",
            "- Do not claim compromise.",
            "- Do not recommend exploitation.",
            "- Do not claim the target is safe or secure.",
            "- Zero discoveries means no paths were discovered with the selected wordlist/profile.",
            "- Zero discoveries does not imply a static site, no exploitable paths, or resistance to injection.",
            "- Explain what the hidden-content observations suggest and what follow-up actions are reasonable.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Mention uncertainty clearly when evidence is limited.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Facts",
            "Hidden Content Notes",
            "Potential Risks",
            "Confidence",
            "Recommended Next Actions",
            "",
            "Observed ffuf Evidence:",
            _format_ffuf_evidence(finding),
        ]
    )


def _format_ffuf_evidence(finding: dict) -> str:
    results = finding.get("ffuf_results") or []
    summary = finding.get("ffuf_summary") or {}
    metadata = finding.get("metadata") or {}
    lines = [
        f"- Target: {_clean(finding.get('target') or 'unknown')}",
        f"- Status: {_clean(finding.get('status') or 'unknown')}",
        f"- Discovered path count: {int(finding.get('finding_count') or len(results) or 0)}",
        f"- Wordlist entries: {int(metadata.get('wordlist_count') or 0)}",
        f"- Fuzz URL: {_clean(metadata.get('fuzz_url') or 'not supplied')}",
        f"- Status codes: {_clean(_format_status_codes(summary.get('status_codes') or {}))}",
        f"- Redirects: {int(summary.get('redirect_count') or 0)}",
        f"- Forbidden/auth-gated responses: {int(summary.get('forbidden_count') or 0)}",
        f"- Server-error responses: {int(summary.get('server_error_count') or 0)}",
    ]
    if not results:
        lines.append("- Limitation: No structured ffuf observations were stored.")
        return "\n".join(lines)

    lines.append("- Observed ffuf records:")
    for result in results[:30]:
        parts = [
            f"url={_clean(result.get('url') or 'unknown')}",
            f"status={_clean(result.get('status_code') or 'unknown')}",
            f"classification={_clean(result.get('classification') or 'observed')}",
        ]
        if result.get("content_length") is not None:
            parts.append(f"length={_clean(result.get('content_length'))}")
        if result.get("words") is not None:
            parts.append(f"words={_clean(result.get('words'))}")
        if result.get("lines") is not None:
            parts.append(f"lines={_clean(result.get('lines'))}")
        if result.get("redirect_location"):
            parts.append(f"redirect={_clean(result.get('redirect_location'))}")
        if result.get("input_word"):
            parts.append(f"word={_clean(result.get('input_word'))}")
        lines.append("  - " + " ".join(parts))
    return "\n".join(lines)


def _format_status_codes(status_codes: dict) -> str:
    return ", ".join(f"{code}: {count}" for code, count in sorted(status_codes.items())) if status_codes else "none"


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:500]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
