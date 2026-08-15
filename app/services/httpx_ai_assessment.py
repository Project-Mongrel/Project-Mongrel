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
    "httpx AI assessment unavailable.",
    "Use the deterministic httpx result for observed HTTP fingerprinting and next actions.",
]
TRUTHFULNESS_FALLBACK_LINES = [
    "Executive Summary",
    "- The httpx AI assessment was withheld because the generated response contained an unsupported security conclusion.",
    "",
    "Observed Facts",
    "- Use the deterministic httpx result for response status codes, titles, redirects, headers, TLS metadata, and technology fingerprints observed in this run.",
    "",
    "Interpretation",
    "- httpx fingerprinting evidence is response metadata only; it does not prove vulnerability, exploitability, compromise, authentication strength, sensitive-data exposure, or application health.",
    "",
    "Limitations",
    "- No usable response or an empty result preserves uncertainty and must not be interpreted as proof that the host is down, no web application exists, or the target is safe.",
    "",
    "Recommended Next Actions",
    "- Validate observed responses, redirects, headers, and technology fingerprints with authorized follow-up testing before drawing security conclusions.",
]
EVIDENCE_SCOPED_MARKERS = (
    "does not establish",
    "does not prove",
    "did not establish",
    "not evidence of",
    "not a vulnerability",
    "not vulnerability",
    "insufficient evidence",
    "cannot determine",
    "no usable response",
    "response was observed",
    "response was reported",
    "status code was observed",
    "status code was reported",
)
UNSUPPORTED_HTTPX_CLAIM_PATTERNS = (
    re.compile(r"\b(?:target|site|system|application|app|server|host)\b[^.!?]{0,80}\b(?:is|are|was|were|appears|seems|looks)\s+(?:safe|secure|insecure|vulnerable|compromised)\b"),
    re.compile(r"\bno\s+(?:exploitable\s+)?vulnerabilities\s+(?:exist|were\s+found|were\s+detected|detected|found)\b"),
    re.compile(r"\b(?:free\s+of|without)\s+vulnerabilities\b"),
    re.compile(r"\b(?:compromise|exploitation)\s+(?:was\s+)?(?:detected|observed|identified|found)\b"),
    re.compile(r"\b(?:technology|nginx|apache|react|wordpress|php|server)\b[^.!?]{0,100}\b(?:is|are|was|were)\s+(?:vulnerable|exploitable)\b"),
    re.compile(r"\bhttp\s*200\b[^.!?]{0,100}\b(?:functioning\s+normally|healthy|available|fully\s+available)\b"),
    re.compile(r"\b(?:401|http\s*401)\b[^.!?]{0,100}\b(?:secure\s+credentials|strong\s+authentication|authentication\s+is\s+secure)\b"),
    re.compile(r"\b(?:403|http\s*403)\b[^.!?]{0,100}\b(?:waf|firewall)\b[^.!?]{0,60}\b(?:blocked|protected|prevented)\b"),
    re.compile(r"\b(?:404|http\s*404)\b[^.!?]{0,100}\b(?:site|application|resource\s+space|web\s+app(?:lication)?)\b[^.!?]{0,80}\b(?:does\s+not\s+exist|absent|missing)\b"),
    re.compile(r"\b(?:429|http\s*429)\b[^.!?]{0,100}\b(?:because|due\s+to|after)\s+\d+\s+requests?\b"),
    re.compile(r"\b(?:5\d\d|server\s+error)\b[^.!?]{0,100}\b(?:vulnerability|vulnerable|exploitable)\b"),
    re.compile(r"\bmissing\s+(?:security\s+)?headers?\b[^.!?]{0,100}\bconfirmed\s+vulnerability\b"),
    re.compile(r"\bmissing\s+(?:security\s+)?headers?\b[^.!?]{0,100}\b(?:confirmed\s+vulnerab|exploitable|creates?\s+an?\s+exploitable)\b"),
    re.compile(r"\b(?:sensitive\s+data|secrets?|credentials?)\b[^.!?]{0,80}\b(?:exposed|leaked|disclosed|found)\b"),
    re.compile(r"\b(?:host\s+is\s+down|service\s+does\s+not\s+exist|no\s+web\s+application\s+exists)\b"),
)


def generate_httpx_ai_assessment(finding: dict) -> list[str]:
    prompt = build_httpx_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    lines = lines or list(FALLBACK_LINES)
    return _guard_truthfulness_response(lines)


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
            "- Do not claim the target, application, server, or technology is insecure or vulnerable from fingerprinting alone.",
            "- HTTP 200 means a response was observed; it does not prove the application is functioning normally or fully available.",
            "- HTTP 401 means an authentication-required response was observed; do not claim authentication strength.",
            "- HTTP 403 means a forbidden response was observed; do not claim a WAF or firewall blocked the request unless separately evidenced.",
            "- HTTP 404 means the tested resource returned Not Found; do not infer the whole site or resource space is absent.",
            "- HTTP 429 means a rate-limited response was observed; preserve unknown cause and do not infer request counts.",
            "- HTTP 5xx means a server-error response was observed; do not automatically call it a vulnerability.",
            "- Technology fingerprints are observations, not vulnerability findings.",
            "- Headers are contextual observations; missing headers are not automatically confirmed vulnerabilities.",
            "- If no usable response was obtained, preserve uncertainty and do not say the host is down, the service does not exist, no web application exists, or the target is safe.",
            "- Do not call HTTP 429 a misconfiguration without explicit evidence; preserve rate-limit, challenge, or access-control uncertainty.",
            "- Explain only what the HTTP fingerprinting observed and what follow-up actions are reasonable.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Mention uncertainty clearly when evidence is limited.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Facts",
            "HTTP Fingerprinting Notes",
            "Interpretation",
            "Potential Risks",
            "Limitations",
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
        f"- HTTP response/URL observation count: {int(finding.get('finding_count') or len(services) or 0)}",
        f"- Elapsed time: {_clean(metadata.get('elapsed') or metadata.get('elapsed_seconds') or 'not supplied')}",
    ]
    status_codes = summary.get("status_codes") or {}
    if status_codes:
        lines.append("- Status codes: " + ", ".join(f"{_clean(code)}={int(count or 0)}" for code, count in sorted(status_codes.items())))
    technologies = summary.get("technologies") or []
    if technologies:
        lines.append("- Technologies: " + ", ".join(_clean(value) for value in technologies[:20]))
    if not services:
        lines.append("- Limitation: No usable structured httpx response observations were stored for this run.")
        lines.append("- Limitation: This does not prove the host is down, no web application exists, or the target is safe.")
        return "\n".join(lines)

    lines.append("- Observed HTTP responses/URLs:")
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


def _guard_truthfulness_response(lines: list[str]) -> list[str]:
    if _contains_unsupported_httpx_claim(lines):
        return list(TRUTHFULNESS_FALLBACK_LINES)
    return lines


def _contains_unsupported_httpx_claim(lines: list[str]) -> bool:
    for sentence in _claim_sentences(lines):
        if _is_evidence_scoped_statement(sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_HTTPX_CLAIM_PATTERNS):
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
