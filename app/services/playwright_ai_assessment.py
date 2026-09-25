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
    "Playwright AI assessment unavailable.",
    "Use the deterministic Playwright result for observed browser behavior and next actions.",
]
TRUTHFULNESS_FALLBACK_LINES = [
    "Executive Summary",
    "- The Playwright AI assessment was withheld because the generated response contained an unsupported browser-observation security conclusion.",
    "",
    "Observed Facts",
    "- Use the deterministic Playwright result for the returned browser state, response status, DOM counts, console messages, network events, and artifact metadata observed in this run.",
    "",
    "Interpretation",
    "- Passive Playwright observation reports browser state only; it does not prove vulnerability presence, vulnerability absence, exploitability, secure authentication, or complete application behavior.",
    "",
    "Limitations",
    "- Restricted, partial, failed, or rate-limited responses limit visibility and preserve uncertainty.",
    "",
    "Recommended Next Actions",
    "- Validate observed browser state with authorized follow-up testing before drawing security conclusions.",
]
EVIDENCE_SCOPED_MARKERS = (
    "does not establish",
    "does not prove",
    "did not establish",
    "does not test",
    "not observed during the returned browser state",
    "not observed in the returned browser state",
    "not observed in this capture",
    "was not observed",
    "were not observed",
    "insufficient evidence",
    "cannot determine",
    "visibility",
    "cause is unknown",
    "evidence is insufficient",
)
UNSUPPORTED_PLAYWRIGHT_CLAIM_PATTERNS = (
    re.compile(r"\b(?:target|site|system|application|app|host|page)\b[^.!?]{0,80}\b(?:is|are|was|were|appears|seems|looks)\s+(?:to\s+be\s+)?(?:safe|secure|insecure|vulnerable|compromised)\b"),
    re.compile(r"\b(?:site|application|app|page)\b[^.!?]{0,100}\b(?:functioning\s+normally|healthy|fully\s+available|operating\s+normally)\b"),
    re.compile(r"\b(?:429|http\s*429)\b[^.!?]{0,100}\b(?:means|because|due\s+to|after)\b[^.!?]{0,80}\b(?:too\s+many\s+requests|requests?\s+(?:were\s+)?sent|request\s+count)\b"),
    re.compile(r"\b(?:api|application|site)\b[^.!?]{0,100}\brate-?limit(?:ing|s|ed)?\s+malicious\s+traffic\b"),
    re.compile(r"\b(?:page|site|application|app)\b[^.!?]{0,80}\b(?:has|contains)\s+no\s+(?:forms?|inputs?|links?|javascript)\b"),
    re.compile(r"\b(?:forms?|inputs?|links?|javascript)\s+(?:do|does)\s+not\s+exist\b"),
    re.compile(r"\b(?:application|site|page)\b[^.!?]{0,80}\b(?:contains|has)\s+no\s+javascript\b"),
    re.compile(r"\bno\s+(?:xss|sql\s+injection|csrf|authentication)\s+(?:vulnerabilities|flaws|issues)\s+(?:exist|were\s+found|were\s+detected|detected|found)\b"),
    re.compile(r"\b(?:xss|sql\s+injection|csrf)\s+(?:is|are)\s+not\s+(?:present|possible)\b"),
    re.compile(r"\b(?:authentication|credentials?)\b[^.!?]{0,80}\b(?:is|are|was|were)\s+(?:secure|strong)\b"),
)


def generate_playwright_ai_assessment(finding: dict) -> list[str]:
    prompt = build_playwright_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    lines = lines or list(FALLBACK_LINES)
    return _guard_truthfulness_response(lines, finding)


def build_playwright_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing passive browser-observation notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied observed Playwright evidence.",
            "- Do not invent vulnerabilities.",
            "- Do not invent URLs, forms, links, console errors, network errors, titles, or status codes.",
            "- Do not infer form field meanings or page content beyond normalized evidence.",
            "- Do not say there are no interactive elements when normalized forms, inputs, or links were observed.",
            "- Do not say the site is safe or vulnerable from page load alone.",
            "- Do not say the site is functioning normally from a restricted or partial response.",
            "- HTTP 429 means a rate-limited response was observed; preserve unknown cause and do not infer request counts.",
            "- Forms, inputs, links, or JavaScript may be described only as observed or not observed during the returned browser state.",
            "- Passive browser observation does not test for XSS, SQL injection, CSRF, authentication flaws, or vulnerability absence.",
            "- Restricted or partial states are visibility limitations, not proof of API behavior or protection quality.",
            "- Describe observations as browser behavior and web surface, not confirmed vulnerabilities.",
            "- Do not claim compromise.",
            "- Do not recommend exploitation.",
            "- No clicking, form submission, login attempts, or bot-bypass activity was performed.",
            "- Explain what the browser observation suggests and what follow-up actions are reasonable.",
            "- Separate observed facts from interpretation, recommendations, and limitations.",
            "- Mention uncertainty clearly when evidence is limited.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Facts",
            "Browser Surface Notes",
            "Interpretation",
            "Potential Risks",
            "Limitations / Uncertainty",
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
        f"- Forms observed during returned browser state: {int(summary.get('forms_count') or observation.get('forms_count') or 0)}",
        f"- Inputs observed during returned browser state: {int(summary.get('inputs_count') or observation.get('inputs_count') or 0)}",
        f"- Links observed during returned browser state: {int(summary.get('links_count') or observation.get('links_count') or 0)}",
        f"- Console issues: {int(summary.get('console_issue_count') or observation.get('console_issue_count') or 0)}",
        f"- Network issues: {int(summary.get('network_issue_count') or observation.get('network_issue_count') or 0)}",
        f"- Page errors: {int(summary.get('page_error_count') or observation.get('page_error_count') or 0)}",
        f"- Screenshot metadata present: {bool(summary.get('screenshot_present') or observation.get('screenshot'))}",
        f"- Elapsed time: {_clean(metadata.get('elapsed_seconds') or 'not supplied')}",
        "- Evidence boundary: passive Playwright observation does not test XSS, SQL injection, CSRF, authentication flaws, vulnerability absence, or complete application behavior.",
    ]
    if _status_code(observation, summary) == 429:
        lines.append("- Limitation: HTTP 429 was observed as a rate-limited response; cause is unknown from Playwright evidence.")
    if _is_restricted_or_partial_state(observation, summary):
        lines.append("- Limitation: Restricted or partial browser state limited visibility into the application.")
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


def _status_code(observation: dict, summary: dict) -> int | None:
    try:
        return int(observation.get("status_code") or summary.get("status_code"))
    except (TypeError, ValueError):
        return None


def _count_value(observation: dict, summary: dict, key: str, *, fallback_count_key: str | None = None) -> int:
    value = summary.get(key)
    if value is None:
        value = observation.get(key)
    if value is None and fallback_count_key:
        candidate = observation.get(fallback_count_key)
        if isinstance(candidate, list):
            return len(candidate)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _is_restricted_or_partial_state(observation: dict, summary: dict) -> bool:
    status_code = _status_code(observation, summary)
    load_status = str(observation.get("load_status") or summary.get("load_status") or "").lower()
    return status_code in {401, 403, 429} or load_status in {"domcontentloaded", "timeout", "failed", "navigation_failed"}


def _guard_truthfulness_response(lines: list[str], finding: dict) -> list[str]:
    if _contains_unsupported_playwright_claim(lines, finding):
        return _build_truthfulness_fallback_lines(finding)
    return lines


def _build_truthfulness_fallback_lines(finding: dict) -> list[str]:
    observation = finding.get("playwright_observation") if isinstance(finding.get("playwright_observation"), dict) else {}
    summary = finding.get("playwright_summary") if isinstance(finding.get("playwright_summary"), dict) else {}
    final_url = _clean(observation.get("final_url") or summary.get("final_url") or "unknown")
    status_code = _clean(observation.get("status_code") or summary.get("status_code") or "not observed")
    load_status = _clean(observation.get("load_status") or summary.get("load_status") or "unknown")
    forms_count = _count_value(observation, summary, "forms_count")
    inputs_count = _count_value(observation, summary, "inputs_count")
    links_count = _count_value(observation, summary, "links_count")
    console_count = _count_value(observation, summary, "console_issue_count")
    network_issue_count = _count_value(observation, summary, "network_issue_count")
    page_error_count = _count_value(observation, summary, "page_error_count")
    network_events_count = _count_value(observation, summary, "network_events_count", fallback_count_key="network_events")
    screenshot_present = bool(summary.get("screenshot_present") or observation.get("screenshot"))
    return [
        "Executive Summary",
        "- Playwright stored passive browser-observation evidence. This is observed browser state, not proof of vulnerability presence, vulnerability absence, exploitability, security, or complete application behavior.",
        "",
        "Observed Facts",
        f"- Final URL observed: {final_url}.",
        f"- Status/load observed: status {status_code}, load status {load_status}.",
        f"- DOM counts observed in the returned browser state: {forms_count} forms, {inputs_count} inputs, {links_count} links.",
        f"- Runtime observations stored: {network_events_count} network event(s), {console_count} console issue(s), {network_issue_count} network issue(s), {page_error_count} page error(s).",
        f"- Screenshot metadata present: {'yes' if screenshot_present else 'no'}.",
        "",
        "Interpretation",
        "- Zero counts mean those items were not observed in this returned browser state; they do not prove absence from the application.",
        "- Status 200 and load success indicate an observed browser response/state only; they do not prove security, full functionality, or complete coverage.",
        "- Console messages, network events, forms, inputs, and links require follow-up before drawing security conclusions.",
        "",
        "Recommended Next Actions",
        "- Use authorized follow-up review or targeted testing to validate any observed browser behavior before making security claims.",
    ]


def _contains_unsupported_playwright_claim(lines: list[str], finding: dict) -> bool:
    for sentence in _claim_sentences(lines):
        if _is_safe_playwright_limitation(sentence):
            continue
        if _has_playwright_count_contradiction(sentence, finding):
            return True
        if _has_unsupported_playwright_security_absence_claim(sentence):
            return True
        if _has_dom_to_security_or_business_inference(sentence):
            return True
        if _has_runtime_to_security_claim(sentence):
            return True
        if _has_status_or_load_overclaim(sentence):
            return True
        if _is_evidence_scoped_statement(sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_PLAYWRIGHT_CLAIM_PATTERNS):
            return True
    return False


def _is_safe_playwright_limitation(sentence: str) -> bool:
    if re.search(r"\b(?:no\s+doubt|not\s+only|proves?|confirms?|shows?)\b[^.!?]{0,120}\b(?:secure|safe|no\s+vulnerabilities|complete\s+functionality|fully\s+functional)\b", sentence):
        return False
    objects = (
        r"(?:vulnerabilit(?:y|ies)|exploitability|exploitation|absence|security|safety|"
        r"complete\s+(?:functionality|coverage|application\s+behavior)|business\s+meaning)"
    )
    return bool(re.search(rf"\b(?:does|do|did)\s+not\s+(?:establish|prove|confirm|demonstrate|show|test)\b[^.!?]{{0,180}}\b{objects}\b", sentence))


def _has_playwright_count_contradiction(sentence: str, finding: dict) -> bool:
    observation = finding.get("playwright_observation") if isinstance(finding.get("playwright_observation"), dict) else {}
    summary = finding.get("playwright_summary") if isinstance(finding.get("playwright_summary"), dict) else {}
    forms_count = _count_value(observation, summary, "forms_count")
    inputs_count = _count_value(observation, summary, "inputs_count")
    links_count = _count_value(observation, summary, "links_count")
    network_events_count = _count_value(observation, summary, "network_events_count", fallback_count_key="network_events")
    console_count = _count_value(observation, summary, "console_issue_count")
    network_issue_count = _count_value(observation, summary, "network_issue_count")
    page_error_count = _count_value(observation, summary, "page_error_count")
    if forms_count and re.search(r"\b(?:no|zero|absence\s+of)\s+(?:observed\s+)?forms?\b", sentence):
        return True
    if inputs_count and re.search(r"\b(?:no|zero|absence\s+of)\s+(?:observed\s+)?inputs?\b", sentence):
        return True
    if links_count and re.search(r"\b(?:no|zero|absence\s+of)\s+(?:observed\s+)?links?\b", sentence):
        return True
    if network_events_count and re.search(r"\b(?:no|zero|absence\s+of)\s+(?:observed\s+)?network\s+events?\b", sentence):
        return True
    if console_count and re.search(r"\b(?:no|zero|absence\s+of)\s+(?:console\s+)?(?:issues?|errors?|messages?)\b", sentence):
        return True
    if network_issue_count and re.search(r"\b(?:no|zero|absence\s+of)\s+network\s+(?:issues?|errors?)\b", sentence):
        return True
    if page_error_count and re.search(r"\b(?:no|zero|absence\s+of)\s+page\s+errors?\b", sentence):
        return True
    return False


def _has_unsupported_playwright_security_absence_claim(sentence: str) -> bool:
    if re.search(r"\b(?:no|zero)\s+(?:confirmed\s+)?(?:risks?|security\s+issues?|vulnerabilities|sensitive\s+(?:data\s+)?exposure)\b", sentence):
        return True
    if re.search(r"\b(?:there\s+are|there\s+is|shows?|indicates?|suggests?)\s+no\s+(?:confirmed\s+)?(?:risks?|security\s+issues?|vulnerabilities|xss|sql\s+injection|csrf|auth(?:entication)?\s+issues?)\b", sentence):
        return True
    if re.search(r"\b(?:there\s+are|there\s+is|shows?|indicates?|suggests?)\s+no\s+(?:indications?|evidence|signs?)\s+of\s+(?:vulnerabilit(?:y|ies)|risks?|security\s+issues?|xss|sql\s+injection|csrf|auth(?:entication)?\s+issues?)\b", sentence):
        return True
    if re.search(r"\b(?:absence|lack)\s+of\s+evidence\b[^.!?]{0,160}\b(?:no\s+(?:confirmed\s+)?(?:risks?|security\s+issues?|vulnerabilities)|safe|secure|not\s+vulnerable)\b", sentence):
        return True
    return False


def _has_dom_to_security_or_business_inference(sentence: str) -> bool:
    dom_terms = r"(?:forms?|inputs?|links?|buttons?|fields?|dom|page\s+content)"
    inference_terms = r"(?:indicat(?:e|es|ing)|suggest(?:s|ing)?|support(?:s|ing)?|implies?|means?|shows?)"
    business_or_security = r"(?:login|checkout|contact|business|authentication|admin|vulnerabilit(?:y|ies)|risk|security|sensitive|exploitability)"
    return bool(re.search(rf"\b{dom_terms}\b[^.!?]{{0,120}}\b{inference_terms}\b[^.!?]{{0,120}}\b{business_or_security}\b", sentence))


def _has_runtime_to_security_claim(sentence: str) -> bool:
    runtime_terms = r"(?:console|network\s+events?|network\s+issues?|page\s+errors?|runtime)"
    security_terms = r"(?:vulnerabilit(?:y|ies)|security\s+issues?|safe|secure|compromise|exploitability|attack)"
    return bool(re.search(rf"\b{runtime_terms}\b[^.!?]{{0,140}}\b(?:indicat(?:e|es|ing)|suggest(?:s|ing)?|prove(?:s|d)?|show(?:s|ed)?|confirm(?:s|ed)?)\b[^.!?]{{0,120}}\b{security_terms}\b", sentence))


def _has_status_or_load_overclaim(sentence: str) -> bool:
    if re.search(r"\b(?:status\s+)?200\b[^.!?]{0,140}\b(?:safe|secure|healthy|fully\s+functional|fully\s+available|complete\s+functionality|functioning\s+normally)\b", sentence):
        return True
    if re.search(r"\b(?:loaded|load\s+success(?:ful)?|successfully\s+loaded)\b[^.!?]{0,140}\b(?:safe|secure|healthy|fully\s+functional|fully\s+available|complete\s+functionality|functioning\s+normally)\b", sentence):
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
