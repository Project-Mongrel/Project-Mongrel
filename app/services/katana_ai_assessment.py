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
ALWAYS_UNSUPPORTED_KATANA_CLAIM_PATTERNS = (
    re.compile(r"\b(?:max(?:imum)?\s+)?(?:observed\s+)?crawl\s+depth\b[^.!?]{0,120}\b(?:fully\s+crawled|fully\s+explored|complete(?:d)?\s+(?:crawl|coverage)|all\s+pages)\b"),
    re.compile(r"\b(?:configured\s+)?(?:crawl\s+)?depth(?:\s+limit)?\b[^.!?]{0,120}\b(?:caused|limited|prevented|due\s+to|because\s+of)\b"),
    re.compile(r"\b(?:no|zero)\s+pages?\s+beyond\b[^.!?]{0,120}\b(?:due\s+to|because\s+of|caused\s+by)\b"),
    re.compile(r"\b(?:site|application|app)\b[^.!?]{0,80}\b(?:basic|simple)\s+structure\b"),
    re.compile(r"\b(?:no|without)\s+(?:apparent\s+)?(?:exploitation\s+points?|attack\s+surface|security\s+risks?|vulnerabilities)\b"),
    re.compile(r"\b(?:forms?|parameters?|scripts?|javascript(?:\s+files?)?)\b[^.!?]{0,120}\b(?:suspicious|malicious)\b"),
    re.compile(r"\bsuspicious\s+elements?\b[^.!?]{0,120}\b(?:forms?|parameters?|scripts?|javascript)\b"),
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
    re.compile(r"\b(?:site|application|app)\b[^.!?]{0,80}\b(?:has|contains)\s+(?:a\s+)?(?:single|one|only\s+one)\s+(?:url|endpoint|page|host)\b"),
    re.compile(r"\b(?:single|one|only\s+one)\s+observed\s+(?:url|endpoint|page)\b[^.!?]{0,80}\b(?:and|with)\s+no\s+unique\s+hosts?\b"),
    re.compile(r"\bno\s+unique\s+hosts?\b"),
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
    return _guard_truthfulness_response(lines, finding)


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
            "- Treat max_depth as maximum observed crawl depth only. It does not prove configured crawl depth, complete crawling, or why no deeper URLs were observed.",
            "- If configured crawl depth is not supplied, do not infer a depth limit or say the depth limit caused the observed result.",
            "- Do not describe forms, parameters, or JavaScript files as suspicious merely because they were present or absent.",
            "- If only one URL was observed, say only one URL was observed and coverage is limited; do not characterize the site's overall structure.",
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


def _guard_truthfulness_response(lines: list[str], finding: dict) -> list[str]:
    if _contains_unsupported_katana_claim(lines, finding):
        return list(TRUTHFULNESS_FALLBACK_LINES)
    return lines


def _contains_unsupported_katana_claim(lines: list[str], finding: dict) -> bool:
    for sentence in _claim_sentences(lines):
        if any(pattern.search(sentence) for pattern in ALWAYS_UNSUPPORTED_KATANA_CLAIM_PATTERNS):
            return True
        if _contradicts_katana_summary(sentence, finding):
            return True
        if _is_evidence_scoped_statement(sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_KATANA_CLAIM_PATTERNS):
            return True
    return False


def _contradicts_katana_summary(sentence: str, finding: dict) -> bool:
    summary = finding.get("katana_summary") if isinstance(finding.get("katana_summary"), dict) else {}
    observations = finding.get("katana_observations") if isinstance(finding.get("katana_observations"), list) else []
    host_count = _as_int(summary.get("host_count"))
    if host_count is None:
        observed_hosts = {
            str(observation.get("host") or "").strip().lower()
            for observation in observations
            if isinstance(observation, dict) and str(observation.get("host") or "").strip()
        }
        host_count = len(observed_hosts) if observed_hosts else None
    if host_count and re.search(r"\b(?:no|zero)\s+unique\s+hosts?\b", sentence):
        return True
    configured_depth = ((finding.get("metadata") or {}).get("crawl_depth") if isinstance(finding.get("metadata"), dict) else None)
    if (
        configured_depth in (None, "", [], {})
        and re.search(r"\bconfigured\s+(?:crawl\s+)?depth\b|\bdepth\s+limit\b", sentence)
        and not re.search(r"\b(?:not\s+supplied|not\s+provided|unknown|unavailable)\b", sentence)
    ):
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


def _as_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
