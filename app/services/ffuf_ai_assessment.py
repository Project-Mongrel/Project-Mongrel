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
    "ffuf AI assessment unavailable.",
    "Use the deterministic ffuf result for hidden-content observations and next actions.",
]
TRUTHFULNESS_FALLBACK_LINES = [
    "Executive Summary",
    "- The ffuf AI assessment was withheld because the generated response contained an unsupported fuzzing-evidence security conclusion.",
    "",
    "Observed Facts",
    "- Use the deterministic ffuf result for response URLs, paths, status codes, redirects, response sizes, words, lines, and matched input words observed in this run.",
    "",
    "Interpretation",
    "- ffuf evidence is fuzzing response metadata only; it does not prove vulnerability, exploitability, sensitive exposure, authentication bypass, or complete discovery coverage.",
    "",
    "Limitations",
    "- Undiscovered directories, files, parameters, virtual hosts, endpoints, or hidden content may still exist outside this fuzzing run's visibility.",
    "",
    "Recommended Next Actions",
    "- Validate observed ffuf responses with authorized follow-up testing before drawing security conclusions.",
]
ZERO_OBSERVATION_TRUTHFULNESS_FALLBACK_LINES = [
    "Executive Summary",
    "- ffuf recorded no matching structured response observations during this run.",
    "",
    "Observed Facts",
    "- No response URLs, paths, status codes, redirects, response sizes, words, lines, or matched input words were recorded in the structured ffuf evidence for this run.",
    "",
    "Hidden Content Notes",
    "- No matching responses were observed by ffuf with the selected wordlist/profile and FUZZ placement.",
    "",
    "Interpretation",
    "- This result does not establish that hidden content does not exist, and it does not establish security or vulnerability absence.",
    "",
    "Limitations / Uncertainty",
    "- Coverage is bounded by the selected wordlist, target/FUZZ position, runtime, response filtering, and execution conditions.",
    "",
    "Confidence",
    "- Confidence is limited to the observation that this ffuf run produced no structured response observations.",
    "",
    "Recommended Next Actions",
    "- Consider further discovery only if justified by the assessment context, authorization, and scope.",
]
EVIDENCE_SCOPED_MARKERS = (
    "does not establish",
    "does not prove",
    "did not establish",
    "not observed during this fuzzing run",
    "were not observed during this fuzzing run",
    "was not observed during this fuzzing run",
    "observed during this fuzzing run",
    "fuzzing observation",
    "fuzzing evidence",
    "response metadata",
    "insufficient evidence",
    "cannot determine",
    "may warrant further",
    "coverage was limited",
    "visibility was limited",
    "did not discover matching responses",
    "undiscovered content may still exist",
)
UNSUPPORTED_FFUF_CLAIM_PATTERNS = (
    re.compile(r"\b(?:target|site|system|application|app|host|endpoint|url|path|directory|file|parameter|vhost|virtual\s+host)\b[^.!?]{0,80}\b(?:is|are|was|were|appears|seems|looks)\s+(?:to\s+be\s+)?(?:safe|secure|insecure|vulnerable|exploitable|compromised)\b"),
    re.compile(r"\b(?:parameter|param)\b[^.!?]{0,80}\b(?:is|are|was|were|appears|seems|looks)\s+(?:to\s+be\s+)?(?:injectable|vulnerable|exploitable)\b"),
    re.compile(r"\b(?:parameter|param)\b[^.!?]{0,100}\b(?:sql\s+injection|xss|command\s+injection)\b"),
    re.compile(r"\b(?:directory|folder|path|endpoint)\b[^.!?]{0,80}\b(?:is|are|was|were)\s+(?:sensitive|vulnerable|exploitable)\b"),
    re.compile(r"\bsensitive\s+files?\b[^.!?]{0,80}\b(?:is|are|was|were)?\s*(?:exposed|leaked|disclosed|found)\b"),
    re.compile(r"\b(?:file|backup|config|admin)\b[^.!?]{0,80}\b(?:contains?|exposes?|leaks?|reveals?)\s+(?:sensitive\s+)?(?:data|secrets?|credentials?)\b"),
    re.compile(r"\b(?:sensitive\s+data|secrets?|credentials?)\b[^.!?]{0,80}\b(?:exposed|leaked|disclosed|found)\b"),
    re.compile(r"\bauthentication\s+bypass\b"),
    re.compile(r"\b(?:found|discovered|identified)\s+(?:all|every)\s+(?:application\s+)?(?:routes?|endpoints?|paths?|directories|files|content)\b"),
    re.compile(r"\b(?:fuzzing|ffuf|scan)\b[^.!?]{0,80}\b(?:complete|full\s+coverage|covered\s+all|found\s+all)\b"),
    re.compile(r"\b(?:no\s+hidden\s+content|no\s+hidden\s+(?:directories|files|endpoints|paths)|undiscovered\s+content\s+does\s+not\s+exist)\b"),
    re.compile(r"\bno\s+(?:exploitable\s+)?vulnerabilities\s+(?:exist|were\s+found|were\s+detected|found|detected)\b"),
)


def generate_ffuf_ai_assessment(finding: dict) -> list[str]:
    prompt = build_ffuf_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    lines = lines or list(FALLBACK_LINES)
    return _guard_truthfulness_response(lines, finding)


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
            "- Phrase discovered paths, files, directories, parameters, and virtual hosts as fuzzing observations and follow-up candidates, not confirmed risk.",
            "- Do not infer that a parameter is injectable or vulnerable from a differing response.",
            "- Do not infer that a directory is sensitive, a file contains sensitive data, or authentication bypass exists.",
            "- Do not infer complete discovery coverage or that undiscovered content does not exist.",
            "- Do not claim compromise.",
            "- Do not recommend exploitation.",
            "- Do not claim the target is safe, secure, insecure, or vulnerable from ffuf evidence alone.",
            "- Zero discoveries means no paths were discovered with the selected wordlist/profile.",
            "- Zero discoveries does not imply a static site, no hidden content, no vulnerabilities, no exploitable paths, or resistance to injection.",
            "- If there are zero ffuf response observations, do not fill Potential Risks with security conclusions. State that no matching response observations were recorded and preserve uncertainty.",
            "- For zero-observation runs, explicitly say coverage is bounded by the selected wordlist, target/FUZZ position, runtime, response filtering, and execution conditions.",
            "- For zero-observation runs, recommend further discovery only when justified by the assessment context.",
            "- Explain what the hidden-content observations suggest and what follow-up actions are reasonable.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Mention uncertainty clearly when evidence is limited.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Facts",
            "Hidden Content Notes",
            "Interpretation",
            "Potential Risks",
            "Limitations / Uncertainty",
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
        f"- ffuf response observations during this fuzzing run: {int(finding.get('finding_count') or len(results) or 0)}",
        f"- Wordlist entries: {int(metadata.get('wordlist_count') or 0)}",
        f"- Fuzz URL: {_clean(metadata.get('fuzz_url') or 'not supplied')}",
        f"- Status codes: {_clean(_format_status_codes(summary.get('status_codes') or {}))}",
        f"- Redirects: {int(summary.get('redirect_count') or 0)}",
        f"- Forbidden/auth-gated responses: {int(summary.get('forbidden_count') or 0)}",
        f"- Server-error responses: {int(summary.get('server_error_count') or 0)}",
        "- Evidence boundary: ffuf response observations do not prove vulnerability, exploitability, sensitive exposure, authentication bypass, or complete discovery coverage.",
    ]
    if not results:
        lines.append("- Empty-run interpretation: ffuf recorded no matching response observations during this run.")
        lines.append("- Empty-run boundary: This does not establish that hidden content does not exist, and it does not establish security or vulnerability absence.")
        lines.append("- Empty-run limitation: Coverage is bounded by the selected wordlist, target/FUZZ position, runtime, response filtering, and execution conditions.")
        lines.append("- Empty-run recommendation boundary: Further discovery may be appropriate only if justified by the assessment context.")
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


def _guard_truthfulness_response(lines: list[str], finding: dict | None = None) -> list[str]:
    if _contains_unsupported_ffuf_claim(lines):
        if _is_explicit_zero_observation_finding(finding or {}):
            return list(ZERO_OBSERVATION_TRUTHFULNESS_FALLBACK_LINES)
        return list(TRUTHFULNESS_FALLBACK_LINES)
    return lines


def _is_explicit_zero_observation_finding(finding: dict) -> bool:
    if finding.get("status") not in {"completed", "complete"}:
        return False
    results = finding.get("ffuf_results")
    if not isinstance(results, list) or results:
        return False
    try:
        return int(finding.get("finding_count") or 0) == 0
    except (TypeError, ValueError):
        return False


def _contains_unsupported_ffuf_claim(lines: list[str]) -> bool:
    for sentence in _claim_sentences(lines):
        if _is_evidence_scoped_statement(sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_FFUF_CLAIM_PATTERNS):
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
