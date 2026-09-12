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
    "Katana AI assessment unavailable.",
    "Use the deterministic Katana result for observed crawl surface and next actions.",
]
TRUTHFULNESS_FALLBACK_LINES = [
    "Executive Summary",
    "- The Katana AI assessment was withheld because the generated response contained an unsupported crawl-evidence security conclusion.",
    "",
    "Observed Facts",
    "- Use the deterministic Katana result for URLs, paths, forms, parameters, scripts, hosts, status codes, and crawl depth observed in this run.",
    "",
    "Interpretation",
    "- Katana crawl evidence is discovery metadata only; it does not prove vulnerability, exploitability, sensitive exposure, ownership, public availability at all times, or complete application coverage.",
    "",
    "Limitations",
    "- Undiscovered forms, endpoints, parameters, scripts, or paths may still exist outside this crawl's visibility.",
    "",
    "Recommended Next Actions",
    "- Validate observed crawl items with authorized follow-up testing before drawing security conclusions.",
]
EVIDENCE_SCOPED_MARKERS = (
    "does not establish",
    "does not prove",
    "did not establish",
    "not observed during this crawl",
    "were not observed during this crawl",
    "was not observed during this crawl",
    "observed during this crawl",
    "crawl observation",
    "crawl evidence",
    "discovery metadata",
    "insufficient evidence",
    "cannot determine",
    "may warrant further validation",
    "coverage was limited",
    "visibility was limited",
)
UNSUPPORTED_KATANA_CLAIM_PATTERNS = (
    re.compile(r"\b(?:target|site|system|application|app|host|endpoint|url|path|route)\b[^.!?]{0,80}\b(?:is|are|was|were|appears|seems|looks)\s+(?:to\s+be\s+)?(?:safe|secure|insecure|vulnerable|exploitable|compromised)\b"),
    re.compile(r"\b(?:parameter|param|query\s+parameter)\b[^.!?]{0,80}\b(?:is|are|was|were|appears|seems|looks)\s+(?:to\s+be\s+)?(?:injectable|vulnerable|exploitable)\b"),
    re.compile(r"\b(?:parameter|param|query\s+parameter)\b[^.!?]{0,100}\b(?:sql\s+injection|xss|command\s+injection)\b"),
    re.compile(r"\b(?:form|forms?)\b[^.!?]{0,80}\b(?:is|are|was|were|appears|seems|looks)\s+(?:to\s+be\s+)?(?:exploitable|vulnerable|injectable)\b"),
    re.compile(r"\b(?:script|javascript)\b[^.!?]{0,80}\b(?:is|are|was|were)\s+(?:vulnerable|exploitable)\b"),
    re.compile(r"\b(?:sensitive\s+data|secrets?|credentials?)\b[^.!?]{0,80}\b(?:exposed|leaked|disclosed|found)\b"),
    re.compile(r"\b(?:found|discovered|identified)\s+(?:all|every)\s+(?:application\s+)?(?:routes?|endpoints?|paths?|urls?)\b"),
    re.compile(r"\b(?:crawl|crawler)\b[^.!?]{0,80}\b(?:complete|full\s+coverage|covered\s+all|found\s+all)\b"),
    re.compile(r"\b(?:site|application|app)\b[^.!?]{0,80}\b(?:has|contains)\s+no\s+(?:hidden\s+)?(?:endpoints?|routes?|paths?|forms?|parameters?|scripts?)\b"),
    re.compile(r"\b(?:no\s+hidden\s+endpoints?|undiscovered\s+content\s+does\s+not\s+exist)\b"),
    re.compile(r"\b(?:endpoint|url|path|route)\b[^.!?]{0,80}\bpublicly\s+accessible\s+at\s+all\s+times\b"),
)


def generate_katana_ai_assessment(finding: dict) -> list[str]:
    prompt = build_katana_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    lines = lines or list(FALLBACK_LINES)
    return _guard_truthfulness_response(lines)


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
            "- Describe discovered URLs and endpoints as crawl observations, not confirmed risk.",
            "- Do not infer that a parameter is injectable or vulnerable from its presence in a URL.",
            "- Do not infer that a form is exploitable from its presence in crawl output.",
            "- Do not infer sensitive exposure, ownership, public availability at all times, or complete application coverage.",
            "- If forms, endpoints, parameters, scripts, or paths are absent from the crawl, say they were not observed during this crawl; do not say they do not exist.",
            "- Do not claim compromise.",
            "- Do not recommend exploitation.",
            "- Do not claim the target is safe, secure, insecure, or vulnerable from crawl evidence alone.",
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
            "Interpretation",
            "Potential Risks",
            "Limitations / Uncertainty",
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
        f"- URLs/endpoints observed during this crawl: {int(finding.get('finding_count') or len(observations) or 0)}",
        f"- Unique hosts: {int(summary.get('host_count') or 0)}",
        f"- JavaScript files observed during this crawl: {int(summary.get('javascript_count') or 0)}",
        f"- Query parameters observed during this crawl: {int(summary.get('query_parameter_count') or 0)}",
        f"- Forms/actions observed during this crawl: {int(summary.get('form_count') or 0)}",
        f"- Max observed crawl depth: {int(summary.get('max_depth') or 0)}",
        f"- Configured crawl depth: {_clean(metadata.get('crawl_depth') or 'not supplied')}",
        "- Evidence boundary: Katana crawl observations do not prove vulnerability, exploitability, sensitive exposure, ownership, public availability at all times, or complete coverage.",
    ]
    parameters = summary.get("query_parameters") or []
    if parameters:
        lines.append("- Query parameter names: " + ", ".join(_clean(value) for value in parameters[:30]))
    if not observations:
        lines.append("- Limitation: No structured Katana crawl observations were stored.")
        lines.append("- Limitation: This does not prove forms, endpoints, parameters, scripts, paths, or hidden content do not exist.")
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


def _guard_truthfulness_response(lines: list[str]) -> list[str]:
    if _contains_unsupported_katana_claim(lines):
        return list(TRUTHFULNESS_FALLBACK_LINES)
    return lines


def _contains_unsupported_katana_claim(lines: list[str]) -> bool:
    for sentence in _claim_sentences(lines):
        if _is_evidence_scoped_statement(sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_KATANA_CLAIM_PATTERNS):
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
