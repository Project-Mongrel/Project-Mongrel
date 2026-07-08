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
    "Metasploit AI assessment unavailable.",
    "Use the deterministic Metasploit validation result for observed evidence and limitations.",
]

_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|token|secret|api[_-]?key|access[_-]?key|session[_-]?token)\s*[:=]\s*\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
)


def generate_metasploit_ai_assessment(finding: dict) -> list[str]:
    prompt = build_metasploit_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)
    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)
    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return lines or list(FALLBACK_LINES)


def build_metasploit_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior security validation consultant preparing Metasploit validation notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied normalized Metasploit validation evidence.",
            "- Do not include raw console scripts, raw resource files, huge console dumps, credentials, secrets, or tokens.",
            "- Preserve the exact module, action, target, validation state, and provenance.",
            "- Repeat the supplied Validation State exactly; never translate or upgrade it to another state.",
            "- DETECTED means service, banner, or version metadata was observed only.",
            "- DETECTED must never be described as vulnerable, exploited, compromised, or VALIDATED.",
            "- Scanner evidence is not automatically proof of exploitation.",
            "- The phrase appears vulnerable remains scanner-reported validation evidence, not proof of full compromise.",
            "- VALIDATED must reflect actual observed validation evidence in the supplied normalized result.",
            "- NOT_REPRODUCED does not mean the target is secure.",
            "- INCONCLUSIVE remains inconclusive.",
            "- FAILED or BLOCKED does not mean the target is not vulnerable.",
            "- Do not invent CVEs, sessions, persistence, post-exploitation, data access, attacker access, compromise, or business impact.",
            "- Do not invent access, impact, or vulnerability from DETECTED metadata.",
            "- Use cautious language where impact depends on manual validation or target context.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Validation Facts",
            "Validation Outcome",
            "Potential Impact",
            "Recommended Next Actions",
            "Evidence Confidence / Limitations",
            "",
            "Normalized Metasploit Evidence:",
            _format_metasploit_evidence(finding),
        ]
    )


def _format_metasploit_evidence(finding: dict) -> str:
    evidence = finding.get("metasploit_evidence") or {}
    metadata = finding.get("metadata") or {}
    lines = [
        f"- Tool: Metasploit",
        f"- Module: {_clean(evidence.get('module') or metadata.get('module') or 'unknown')}",
        f"- Action: {_clean(evidence.get('action_type') or metadata.get('action_type') or 'unknown')}",
        f"- Target: {_clean(evidence.get('target') or finding.get('target') or 'unknown')}",
        f"- Port: {_clean(evidence.get('port') or metadata.get('port') or 'not supplied')}",
        f"- Validation State: {_clean(evidence.get('validation_state') or 'unknown')}",
        f"- Status: {_clean(finding.get('status') or 'unknown')}",
        f"- Risk Tier: {_clean(evidence.get('risk_tier') or metadata.get('risk_tier') or 'unknown')}",
        f"- Expected Effect: {_clean(evidence.get('expected_effect') or metadata.get('expected_effect') or 'unknown')}",
        f"- Scanner Message: {_clean(evidence.get('summary') or finding.get('summary') or 'none')}",
        f"- Evidence Confidence: {_clean(evidence.get('evidence_confidence') or 'unknown')}",
        f"- Proposal Reference: {_clean(metadata.get('proposal_id') or 'not supplied')}",
        f"- Artifact Reference: {_clean(metadata.get('artifact_ref') or 'not supplied')}",
    ]
    excerpt = _clean(evidence.get("raw_evidence_excerpt") or "")
    if excerpt:
        lines.append(f"- Normalized Evidence Excerpt: {excerpt}")
    for limitation in evidence.get("limitations") or []:
        lines.append(f"- Limitation: {_clean(limitation)}")
    return "\n".join(lines)


def _clean(value: object) -> str:
    text = str(value or "").replace("\n", " ").strip()[:500]
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("<REDACTED>", text)
    return text


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
