import re

from app.services.ai_client import ask_ai
from app.services.bbot_summary import build_bbot_recon_summary, build_bbot_recon_summary_from_observations
from app.services.investigation_store import get_investigation
from app.services.observation_store import get_investigation_observations, get_user_observations
from app.services.target_normalizer import normalize_target_key

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
    "AI recon assessment unavailable.",
    "Use the deterministic BBOT Recon Summary for next actions.",
]
UNSUPPORTED_CLAIM_FALLBACK_LINES = [
    "Executive Summary",
    "- The reconnaissance AI assessment was withheld because the generated response contained an unsupported security conclusion.",
    "",
    "Observed Facts",
    "- The deterministic Recon Summary remains the source of truth for observed domains, URLs, DNS records, IP addresses, technologies, certificates, and email addresses.",
    "",
    "Interpretation",
    "- Reconnaissance discovery can identify items for follow-up, but it does not prove vulnerabilities, compromise, ownership, active services, or sensitive data exposure.",
    "",
    "Limitations",
    "- Limited or empty reconnaissance output must not be interpreted as a clean attack surface or absence of vulnerabilities.",
    "",
    "Confidence",
    "High confidence that the withheld wording was not supported by the supplied reconnaissance evidence.",
    "",
    "Recommended Next Actions",
    "- Review the deterministic Recon Summary and validate observed assets with authorized follow-up checks.",
]
FORBIDDEN_TERMS = (
    "scanner",
    "module",
    "scan name",
    "stdout",
    "stderr",
    "json",
    "ansible",
    "dependency installation",
    "implementation detail",
    "internal id",
    "observation store",
)
SPECULATIVE_PHRASES = (
    "appears to",
    "suggests",
    "may indicate",
    "potentially vulnerable",
    "potential exposure",
    "likely vulnerable",
    "possible compromise",
)
UNSUPPORTED_RECON_CLAIM_PATTERNS = (
    re.compile(r"\b(?:target|application|app|server|host|subdomains?|domains?|urls?|assets?|technology|technologies)\b[^.!?]{0,80}\b(?:is|are|was|were|appears|seems|looks)\s+(?:to\s+be\s+)?(?:insecure|vulnerable|compromised)\b"),
    re.compile(r"\b(?:target|application|app|server|host|subdomains?|domains?|urls?|assets?|technology|technologies)\b[^.!?]{0,80}\bexposes?\s+vulnerabilities\b"),
    re.compile(r"\b(?:compromise|exploitation|breach)\s+(?:was\s+)?(?:observed|detected|identified|confirmed)\b"),
    re.compile(r"\b(?:active|running|live)\s+services?\s+(?:were\s+)?(?:observed|detected|identified|confirmed)\b"),
    re.compile(r"\b(?:sensitive\s+data|secrets?|credentials?)\s+(?:were\s+)?(?:observed|detected|identified|exposed|leaked)\b"),
    re.compile(r"\b(?:ip|ip address|address)\b[^.!?]{0,80}\b(?:belongs\s+to|is\s+owned\s+by|owned\s+by)\b"),
    re.compile(r"\b(?:attack\s+surface|target)\s+(?:is|was|appears|seems|looks)\s+(?:clean|secure|safe)\b"),
    re.compile(r"\bno\s+vulnerabilities\b"),
)
EVIDENCE_SCOPED_RECON_MARKERS = (
    "does not establish",
    "does not prove",
    "not evidence of",
    "insufficient evidence",
    "evidence is limited",
    "further validation",
    "warrant further investigation",
)
ALLOWED_OBSERVATION_TYPES = {
    "subdomain": "DNS names",
    "dns_record": "DNS records",
    "ip_address": "IP addresses",
    "url": "URLs",
    "technology": "Technologies",
    "certificate": "Certificates",
    "email": "Email addresses",
    "social_profile": "Social profiles",
    "open_port": "Open ports",
    "finding": "Findings",
}


def generate_bbot_ai_assessment(
    user_id,
    investigation_id=None,
    target=None,
    observations=None,
    recon_summary=None,
) -> list[str]:
    supplied_observations = observations is not None
    observations = list(observations) if supplied_observations else _load_bbot_observations(int(user_id), investigation_id=investigation_id, target=target)
    summary = recon_summary or (
        build_bbot_recon_summary_from_observations(observations, target=target)
        if supplied_observations
        else build_bbot_recon_summary(user_id=user_id, investigation_id=investigation_id, target=target)
    )
    investigation = get_investigation(str(investigation_id), int(user_id)) if investigation_id else None

    if not observations:
        return [
            "Executive Summary",
            "- Available reconnaissance evidence is insufficient to assess the target beyond the provided scope.",
            "",
            "Observed Facts",
            "- No normalized reconnaissance observations are available for this target.",
            "",
            "Observed Assets",
            "- None observed.",
            "",
            "Potential Risks",
            "- Evidence is limited because there is not enough information to identify concrete exposure patterns.",
            "- No vulnerability or compromise conclusion can be drawn from the absence of normalized reconnaissance observations.",
            "",
            "Limitations",
            "- Limited reconnaissance output does not prove the target is secure or that no vulnerabilities exist.",
            "",
            "Confidence",
            "Low",
            "",
            "Recommended Next Actions",
            "- Continue reconnaissance using additional evidence sources.",
        ]

    prompt = build_bbot_ai_assessment_prompt(
        observations=observations,
        recon_summary=summary,
        investigation=investigation,
        target=target,
    )
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    cleaned_response = str(response or "").strip()
    if not cleaned_response:
        return list(FALLBACK_LINES)

    return _sanitize_response_lines(cleaned_response.splitlines())


def build_bbot_ai_assessment_prompt(
    observations: list[dict],
    recon_summary: str,
    investigation: dict | None = None,
    target: str | None = None,
) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing reconnaissance notes for another security consultant.",
            "",
            "Rules:",
            "- Only use the supplied normalized evidence and deterministic Recon Summary.",
            "- Do not invent vulnerabilities.",
            "- Do not invent assets, findings, technologies, ports, or certificates.",
            "- Do not claim compromise.",
            "- Do not claim exploitation.",
            "- Do not infer target ownership from IP associations or DNS data.",
            "- Do not infer active services from discovered domains, URLs, or technology names alone.",
            "- Do not infer sensitive data exposure, breach, or insecure configuration from discovery evidence alone.",
            "- Technology identification is not vulnerability evidence.",
            "- Reconnaissance is not exploitation.",
            "- Never speculate.",
            "- Never infer compromise.",
            "- Do not recommend exploitation.",
            "- Never imply a vulnerability without explicit supporting evidence.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Use cautious validation language such as review, verify, consider, and prioritize.",
            "- If evidence is limited, say so.",
            "- If little or no evidence is available, do not say the target is secure, clean, or free of vulnerabilities.",
            "- Confidence must be High, Medium, or Low, based only on available evidence.",
            "- Confidence describes evidence completeness, not severity.",
            "- Recommended next actions must be practical and tied to observed evidence.",
            "- Discuss only consultant-facing evidence and avoid collection mechanics or platform internals.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Facts",
            "Observed Assets",
            "Interpretation",
            "Potential Risks",
            "Limitations",
            "Confidence",
            "Recommended Next Actions",
            "",
            "Investigation Target:",
            str(target or _target_from_observations(observations) or "unknown"),
            "",
            "Investigation Context",
            _format_investigation_context(investigation),
            "",
            "Deterministic Recon Summary",
            _sanitize_recon_summary(recon_summary),
            "",
            "Normalized Evidence",
            _format_observations(observations),
        ]
    )


def _load_bbot_observations(user_id: int, investigation_id: str | None, target: str | None) -> list[dict]:
    if investigation_id:
        observations = get_investigation_observations(str(investigation_id), user_id)
    else:
        observations = get_user_observations(user_id)

    target_key = normalize_target_key(target)
    filtered = [observation for observation in observations if observation.get("source") == "bbot"]
    if target_key is not None:
        filtered = [
            observation
            for observation in filtered
            if (observation.get("target_key") or normalize_target_key(observation.get("target"))) == target_key
        ]
    return filtered


def _format_investigation_context(investigation: dict | None) -> str:
    if investigation is None:
        return "- No additional investigation context supplied."

    lines = []
    if investigation.get("target"):
        lines.append(f"- Target: {investigation['target']}")
    if investigation.get("overall_risk"):
        lines.append(f"- Current risk rating: {investigation['overall_risk']}")
    if investigation.get("summary"):
        lines.append(f"- Existing summary: {_sanitize_text(str(investigation['summary']))}")
    return "\n".join(lines) if lines else "- No additional investigation context supplied."


def _format_observations(observations: list[dict]) -> str:
    grouped: dict[str, list[str]] = {}
    for observation in observations:
        observation_type = str(observation.get("observation_type") or "")
        label = ALLOWED_OBSERVATION_TYPES.get(observation_type)
        value = _sanitize_text(str(observation.get("value") or "").strip())
        if not label or not value:
            continue
        grouped.setdefault(label, [])
        if value.lower() not in {item.lower() for item in grouped[label]}:
            grouped[label].append(value)

    if not grouped:
        return "- No supported normalized evidence supplied."

    lines = [f"- Observation count: {sum(len(values) for values in grouped.values())}"]
    for label in sorted(grouped):
        lines.append(f"- {label}: {', '.join(grouped[label][:10])}")
    return "\n".join(lines)


def _target_from_observations(observations: list[dict]) -> str | None:
    for observation in observations:
        if observation.get("target"):
            return str(observation["target"])
    return None


def _is_unavailable_response(response: str) -> bool:
    normalized = str(response or "").strip()
    return any(normalized.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)


def _sanitize_recon_summary(recon_summary: str) -> str:
    sanitized_lines = []
    for line in str(recon_summary or "").splitlines():
        sanitized_line = _sanitize_text(line)
        if sanitized_line.strip():
            sanitized_lines.append(sanitized_line)
    return "\n".join(sanitized_lines) if sanitized_lines else "- No deterministic summary supplied."


def _sanitize_response_lines(lines: list[str]) -> list[str]:
    if _contains_unsupported_recon_claim(lines):
        return list(UNSUPPORTED_CLAIM_FALLBACK_LINES)
    sanitized_lines = []
    for line in lines:
        if _contains_forbidden_term(line):
            continue
        if _contains_unsupported_speculation(line):
            continue
        sanitized_lines.append(line)
    return sanitized_lines if sanitized_lines else list(FALLBACK_LINES)


def _sanitize_text(text: str) -> str:
    sanitized = str(text)
    replacements = {
        "BBOT Recon Summary": "Recon Summary",
        "BBOT recon summary": "Recon summary",
        "BBOT Recon": "Recon",
        "BBOT recon": "Recon",
        "BBOT identified": "Observed",
        "BBOT produced": "Observed",
        "BBOT": "Recon",
        "Observation Store": "evidence source",
        "JSON": "structured",
        "stdout": "output",
        "stderr": "error output",
    }
    for old, new in replacements.items():
        sanitized = sanitized.replace(old, new)
    return sanitized


def _contains_forbidden_term(text: str) -> bool:
    normalized = str(text or "").lower()
    return any(term in normalized for term in FORBIDDEN_TERMS)


def _contains_unsupported_speculation(text: str) -> bool:
    normalized = str(text or "").lower()
    if any(phrase in normalized for phrase in SPECULATIVE_PHRASES):
        return True
    if "vulnerable" in normalized and "confirmed" not in normalized:
        return True
    if "compromise" in normalized and "do not" not in normalized:
        return True
    return False


def _contains_unsupported_recon_claim(lines: list[str]) -> bool:
    for sentence in _claim_sentences(lines):
        if _is_evidence_scoped_recon_statement(sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_RECON_CLAIM_PATTERNS):
            return True
    return False


def _claim_sentences(lines: list[str]) -> list[str]:
    text = " ".join(str(line or "").strip() for line in lines)
    return [
        re.sub(r"\s+", " ", sentence).strip().lower()
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", text)
        if sentence.strip()
    ]


def _is_evidence_scoped_recon_statement(sentence: str) -> bool:
    return any(marker in sentence for marker in EVIDENCE_SCOPED_RECON_MARKERS)
