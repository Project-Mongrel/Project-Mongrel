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
    re.compile(r"\b(?:all|every)\s+pages?\s+(?:were|was|are|is|have\s+been|has\s+been)\s+crawled\b"),
    re.compile(r"\b(?:the\s+)?(?:site|application|app)\s+(?:was|were|is|are|has\s+been|have\s+been)\s+fully\s+crawled\b"),
    re.compile(r"\b(?:the\s+)?(?:entire|whole)\s+(?:site|application|app)\s+(?:was|were|is|are|has\s+been|have\s+been)?\s*crawled\b"),
    re.compile(r"\b(?:the\s+)?crawl\s+(?:covered|covers)\s+(?:all|every)\s+pages?\b"),
    re.compile(r"\b(?:complete|full)\s+crawl\s+coverage\s+(?:was\s+|is\s+|has\s+been\s+)?achieved\b"),
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
            "- Do not write that there are no risks, no issues, no exploitation points, or no attack surface. Katana did not test that.",
            "- For sparse crawls, explain the observed crawl surface and the evidence gaps instead of filling a risk section with absence claims.",
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
            "Follow-up Investigation Areas",
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
        return _build_truthfulness_fallback_lines(finding)
    return lines


def _build_truthfulness_fallback_lines(finding: dict) -> list[str]:
    observations = finding.get("katana_observations") if isinstance(finding.get("katana_observations"), list) else []
    summary = finding.get("katana_summary") if isinstance(finding.get("katana_summary"), dict) else {}
    observed_count = _as_int(finding.get("finding_count")) or len(observations)
    host_count = _as_int(summary.get("host_count"))
    if host_count is None:
        host_count = len({
            str(observation.get("host") or "").strip().lower()
            for observation in observations
            if isinstance(observation, dict) and str(observation.get("host") or "").strip()
        })
    javascript_count = _as_int(summary.get("javascript_count")) or 0
    parameter_count = _as_int(summary.get("query_parameter_count")) or 0
    form_count = _as_int(summary.get("form_count")) or 0
    max_depth = _as_int(summary.get("max_depth")) or 0
    return [
        "Executive Summary",
        f"- Katana stored {observed_count} URL/endpoint crawl observation(s) across {host_count} observed host(s). This is crawl-discovery evidence, not a vulnerability, exploitability, or complete-coverage conclusion.",
        "",
        "Observed Facts",
        f"- JavaScript files observed during this crawl: {javascript_count}.",
        f"- Query parameters observed during this crawl: {parameter_count}.",
        f"- Forms/actions observed during this crawl: {form_count}.",
        f"- Maximum observed crawl depth: {max_depth}.",
        "",
        "Crawl Surface Notes",
        "- Zero counts mean those items were not observed during this crawl; they do not prove those items are absent from the site.",
        "- The observed depth is the maximum depth represented in stored crawl observations; it does not establish configured crawl depth or complete crawl coverage.",
        "",
        "Interpretation",
        "- This crawl provides a limited view of observed URLs, hosts, scripts, parameters, forms, and depth. Katana evidence alone does not establish vulnerability, exploitability, sensitive exposure, or safety.",
        "",
        "Recommended Next Actions",
        "- Use authorized browser/runtime review, additional scoped crawling, or targeted validation to add evidence before drawing security conclusions.",
    ]


def _contains_unsupported_katana_claim(lines: list[str], finding: dict) -> bool:
    for sentence in _claim_sentences(lines):
        if _is_safe_katana_limitation(sentence):
            continue
        if _has_katana_count_contradiction(sentence, finding):
            return True
        if _has_unsupported_depth_or_configuration_claim(sentence, finding):
            return True
        if _has_unsupported_security_absence_claim(sentence):
            return True
        if _has_unsupported_complexity_claim(sentence):
            return True
        if _has_absence_to_security_inference(sentence):
            return True
        if any(pattern.search(sentence) for pattern in ALWAYS_UNSUPPORTED_KATANA_CLAIM_PATTERNS):
            return True
        if _contradicts_katana_summary(sentence, finding):
            return True
        if _is_evidence_scoped_statement(sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_KATANA_CLAIM_PATTERNS):
            return True
    return False


def _has_katana_count_contradiction(sentence: str, finding: dict) -> bool:
    summary = finding.get("katana_summary") if isinstance(finding.get("katana_summary"), dict) else {}
    observations = finding.get("katana_observations") if isinstance(finding.get("katana_observations"), list) else []
    observed_count = _as_int(finding.get("finding_count"))
    if observed_count is None:
        observed_count = _as_int(summary.get("url_count")) or len(observations)
    host_count = _as_int(summary.get("host_count"))
    if host_count is None:
        host_count = len({
            str(observation.get("host") or "").strip().lower()
            for observation in observations
            if isinstance(observation, dict) and str(observation.get("host") or "").strip()
        })
    if observed_count and re.search(r"\b(?:no|zero|absence\s+of)\s+(?:observed\s+)?(?:urls?|endpoints?)\b", sentence):
        return True
    if observed_count and re.search(r"\bno\s+observed\s+endpoints?\b", sentence):
        return True
    if host_count and re.search(r"\b(?:no|zero|absence\s+of)\s+(?:observed\s+)?(?:unique\s+)?hosts?\b", sentence):
        return True
    if host_count and re.search(r"\bno\s+unique\s+hosts?\b", sentence):
        return True
    return False


def _has_unsupported_depth_or_configuration_claim(sentence: str, finding: dict) -> bool:
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    configured_depth = metadata.get("crawl_depth")
    has_configured_depth = configured_depth not in (None, "", [], {})
    mentions_configured_depth = re.search(r"\bconfigured\s+(?:crawl\s+)?depth\b|\bdepth\s+limit\b", sentence)
    if mentions_configured_depth and not has_configured_depth and not re.search(r"\b(?:not\s+supplied|not\s+provided|unknown|unavailable)\b", sentence):
        return True
    if mentions_configured_depth and re.search(r"\b(?:indicat(?:e|es|ing)|mean(?:s|ing)?|shows?|proves?|because|due\s+to|within|consistent\s+with)\b", sentence):
        return True
    if re.search(r"\b(?:did\s+not|does\s+not|could\s+not|cannot)\s+reach\s+(?:any\s+)?deeper\s+(?:urls?|pages?|endpoints?)\b[^.!?]{0,120}\b(?:configured\s+(?:crawl\s+)?depth|depth\s+limit)\b", sentence):
        return True
    return False


def _has_unsupported_security_absence_claim(sentence: str) -> bool:
    if re.search(r"\b(?:no|zero)\s+(?:confirmed\s+)?(?:risks?|security\s+issues?|vulnerabilities|sensitive\s+(?:data\s+)?exposure)\b", sentence):
        return True
    if re.search(r"\b(?:there\s+are|there\s+is|shows?|indicates?|suggests?)\s+no\s+(?:confirmed\s+)?(?:risks?|security\s+issues?|vulnerabilities|sensitive\s+(?:data\s+)?exposure)\b", sentence):
        return True
    if re.search(r"\b(?:absence|lack)\s+of\s+evidence\b[^.!?]{0,160}\b(?:no\s+(?:confirmed\s+)?(?:risks?|security\s+issues?|vulnerabilities)|safe|secure|not\s+vulnerable|no\s+sensitive\s+(?:data\s+)?exposure)\b", sentence):
        return True
    if re.search(r"\bno\s+indications?\s+of\b[^.!?]{0,120}\b(?:vulnerabilities|sensitive\s+(?:data\s+)?exposure|security\s+issues?|risks?)\b", sentence):
        return True
    return False


def _has_unsupported_complexity_claim(sentence: str) -> bool:
    if re.search(r"\b(?:simple|basic|straightforward)\s+(?:structure|site|application|app|functionality|core\s+functionality)\b", sentence):
        return True
    if re.search(r"\b(?:structure|site|application|app|functionality|core\s+functionality)\b[^.!?]{0,80}\b(?:simple|basic|straightforward)\b", sentence):
        return True
    if re.search(r"\b(?:single\s+url|one\s+url|absence\s+of|no\s+forms?|no\s+parameters?|no\s+javascript|no\s+unique\s+hosts?)\b[^.!?]{0,160}\b(?:suggests?|supports?|indicates?)\b[^.!?]{0,80}\b(?:simple|basic|straightforward)\b", sentence):
        return True
    return False


def _has_absence_to_security_inference(sentence: str) -> bool:
    absence_terms = r"(?:absence\s+of|no|zero|not\s+observed)"
    artifact_terms = r"(?:forms?|parameters?|javascript(?:\s+files?)?|scripts?|hosts?|unique\s+hosts?|complex\s+interactions?)"
    security_terms = r"(?:vulnerabilities|vulnerability|sensitive\s+(?:data\s+)?exposure|risks?|security\s+issues?|exploitability|attack\s+surface)"
    inference_terms = r"(?:indicat(?:e|es|ing)|suggest(?:s|ing)?|support(?:s|ing)?|implies?|means?|could\s+indicate)"
    return bool(
        re.search(rf"\b{absence_terms}\b[^.!?]{{0,120}}\b{artifact_terms}\b[^.!?]{{0,160}}\b{inference_terms}\b[^.!?]{{0,120}}\b{security_terms}\b", sentence)
        or re.search(rf"\b{artifact_terms}\b[^.!?]{{0,120}}\b{inference_terms}\b[^.!?]{{0,120}}\b{security_terms}\b", sentence)
    )


def _is_safe_katana_limitation(sentence: str) -> bool:
    if re.search(r"\b(?:not\s+only|no\s+doubt|achieved|fully\s+crawled|fully\s+explored|covered\s+all|all\s+pages)\b", sentence):
        return False
    if re.search(r"\b(?:but|however|although)\b[^.!?]{0,120}\b(?:complete\s+coverage|crawl\s+complete|fully\s+crawled|all\s+pages)\b", sentence):
        return False
    limitation_verbs = r"(?:establish|prove|confirm|demonstrate|show)"
    limitation_objects = (
        r"(?:complete\s+coverage|configured\s+crawl\s+depth|depth\s+configuration|absence|"
        r"vulnerabilit(?:y|ies)|exploitability|exploitation|safety|security)"
    )
    return bool(
        re.search(
            rf"\b(?:does|do|did)\s+not\s+{limitation_verbs}\b[^.!?]{{0,160}}\b{limitation_objects}\b",
            sentence,
        )
    )


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
