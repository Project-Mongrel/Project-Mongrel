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

TRUTHFULNESS_FALLBACK_LINES = [
    "Executive Summary",
    "The Metasploit AI assessment was withheld because the generated response contained an unsupported exploitation or security conclusion.",
    "",
    "Observed Validation Facts",
    "Use the deterministic Metasploit validation result for the approved module, action, target, port, validation state, and artifact/proposal provenance.",
    "",
    "Validation Outcome",
    "No stronger conclusion should be drawn than the normalized validation state supports.",
    "",
    "Potential Impact",
    "Do not infer compromise, shell access, vulnerability confirmation, vulnerability absence, persistence, privilege level, lateral movement, or data access unless explicitly present in the normalized evidence.",
    "",
    "Recommended Next Actions",
    "Review the normalized validation evidence and preserve the approval/artifact references before any follow-up testing.",
    "",
    "Evidence Confidence / Limitations",
    "Metasploit output is bounded to the approved module/action/options. Subprocess success, compatibility, failed validation, or network activity alone is not exploit proof.",
]

_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|token|secret|api[_-]?key|access[_-]?key|session[_-]?token)\s*[:=]\s*\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
)

EVIDENCE_SCOPED_MARKERS = (
    "metasploit reported",
    "validation state",
    "normalized evidence",
    "module completed without",
    "did not establish",
    "does not prove",
    "does not mean",
    "no conclusion",
    "insufficient",
    "inconclusive",
    "not proof",
    "not automatic proof",
    "bounded to the approved",
)

UNSUPPORTED_METASPLOIT_CLAIM_PATTERNS = (
    re.compile(r"\b(?:target|host|system|server|endpoint|service)\b[^.!?]{0,80}\b(?:is|was|has\s+been|appears|seems|looks)\s+(?:to\s+be\s+)?(?:compromised|owned|pwned|secure|safe)\b"),
    re.compile(r"\b(?:exploit|exploitation)\b[^.!?]{0,80}\b(?:succeeded|successful|worked|confirmed|was\s+successful)\b"),
    re.compile(r"\b(?:vulnerability|vulnerabilities|vuln)\b[^.!?]{0,80}\b(?:is|are|was|were|has\s+been|have\s+been)\s+(?:confirmed|proven|validated)\b"),
    re.compile(r"\b(?:shell|session|meterpreter|access)\b[^.!?]{0,80}\b(?:obtained|opened|established|gained|created)\b"),
    re.compile(r"\b(?:no|not)\s+(?:vulnerabilities|vulnerability|security\s+issues|risk)\b[^.!?]{0,80}\b(?:exist|found|detected|present)\b"),
    re.compile(r"\b(?:target|host|system|server|endpoint)\b[^.!?]{0,80}\b(?:is|was)\s+(?:not\s+vulnerable|secure|safe)\b[^.!?]{0,80}\b(?:failed|not\s+reproduced|blocked|timed\s+out)?\b"),
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
    return _guard_truthfulness_response(lines or list(FALLBACK_LINES), finding)


def build_metasploit_ai_assessment_prompt(finding: dict) -> str:
    state_specific_rules = _state_specific_rules(finding)
    return "\n".join(
        [
            "You are a senior security validation consultant preparing Metasploit validation notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied normalized Metasploit validation evidence.",
            "- Do not include raw console scripts, raw resource files, huge console dumps, credentials, secrets, or tokens.",
            "- Preserve the exact module, action, target, validation state, and provenance.",
            "- Repeat the supplied Validation State exactly; never translate or upgrade it to another state.",
            "- Distinguish subprocess success from validation success, exploit success, and session establishment.",
            "- Module compatibility or successful msfconsole exit does not confirm vulnerability or exploitability.",
            "- Network traffic or a target response is not proof that exploitation succeeded.",
            *state_specific_rules,
            "- Scanner evidence is not automatically proof of exploitation.",
            "- The phrase appears vulnerable remains scanner-reported validation evidence, not proof of full compromise.",
            "- VALIDATED must reflect actual observed validation evidence in the supplied normalized result.",
            "- SESSION_ESTABLISHED may be described only when the normalized evidence explicitly says a session was established.",
            "- NOT_REPRODUCED does not mean the target is secure.",
            "- INCONCLUSIVE remains inconclusive.",
            "- FAILED or BLOCKED does not mean the target is not vulnerable.",
            "- Failed validation, no session, or timeout does not prove vulnerability absence or target safety.",
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
        f"- Subprocess Success: {_bool_label(evidence.get('subprocess_success'))}",
        f"- Module Executed: {_bool_label(evidence.get('module_executed'))}",
        f"- Session Established: {_bool_label(evidence.get('session_established'))}",
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


def _bool_label(value: object) -> str:
    if value is True:
        return "True"
    if value is False:
        return "False"
    return "unknown"


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)


def _validation_state(finding: dict) -> str:
    return str((finding.get("metasploit_evidence") or {}).get("validation_state") or "").strip().upper()


def _state_specific_rules(finding: dict) -> list[str]:
    state = _validation_state(finding)
    if state == "DETECTED":
        return [
            "- DETECTED means service, banner, or version metadata was observed only.",
            "- DETECTED must never be described as vulnerable, exploited, compromised, or VALIDATED.",
            '- For DETECTED, say: "This action detected service/banner/key metadata only and did not validate a vulnerability condition."',
            '- For DETECTED, do not say "did not observe any vulnerabilities", "no vulnerabilities observed", or "no remediation required".',
            "- Do not infer that a connection is legitimate or unauthorized from an SSH key fingerprint or banner.",
            "- For DETECTED next actions, neutrally review exposure and authorization if relevant, correlate with Nmap or service inventory, and make no vulnerability conclusion from this result alone.",
        ]
    if state == "INCONCLUSIVE":
        return [
            "- INCONCLUSIVE means no conclusive validation evidence was parsed.",
            "- For INCONCLUSIVE, do not claim service, banner, version, or key metadata was observed.",
        ]
    if state == "SESSION_ESTABLISHED":
        return [
            "- SESSION_ESTABLISHED means the normalized evidence explicitly reported a session.",
            "- You may state that a session was established, but do not infer persistence, privilege level, lateral movement, data access, or broader compromise.",
        ]
    return []


def _unsafe_detected_output(lines: list[str]) -> bool:
    text = " ".join(lines).lower()
    forbidden = (
        "did not observe any vulnerabilities",
        "no vulnerabilities observed",
        "no remediation required",
        "legitimate connection",
        "unauthorized connection",
        "legitimate access",
        "unauthorized access",
    )
    return any(phrase in text for phrase in forbidden)


def _guard_truthfulness_response(lines: list[str], finding: dict) -> list[str]:
    if _validation_state(finding) == "DETECTED" and _unsafe_detected_output(lines):
        return _detected_assessment_lines(finding)
    if _contains_unsupported_metasploit_claim(lines, finding):
        return list(TRUTHFULNESS_FALLBACK_LINES)
    return lines


def _contains_unsupported_metasploit_claim(lines: list[str], finding: dict) -> bool:
    session_established = bool((finding.get("metasploit_evidence") or {}).get("session_established"))
    for sentence in _claim_sentences(lines):
        if _is_evidence_scoped_statement(sentence):
            continue
        if session_established and re.search(r"\b(?:shell|session|meterpreter)\b[^.!?]{0,80}\b(?:obtained|opened|established|created)\b", sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_METASPLOIT_CLAIM_PATTERNS):
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


def _detected_assessment_lines(finding: dict) -> list[str]:
    evidence = finding.get("metasploit_evidence") or {}
    module = _clean(evidence.get("module") or (finding.get("metadata") or {}).get("module") or "unknown")
    target = _clean(evidence.get("target") or finding.get("target") or "unknown")
    return [
        "Executive Summary",
        "This action detected service/banner/key metadata only and did not validate a vulnerability condition.",
        "",
        "Observed Validation Facts",
        f"Metasploit module {module} observed metadata for {target}.",
        "",
        "Validation Outcome",
        "Validation State: DETECTED. No vulnerability conclusion can be made from this result alone.",
        "",
        "Potential Impact",
        "The observed metadata identifies a service for authorized review; it does not establish access, exploitation, or compromise.",
        "",
        "Recommended Next Actions",
        "Review exposure and authorization if relevant, and correlate the metadata with Nmap or the service inventory.",
        "",
        "Evidence Confidence / Limitations",
        "Service, banner, or key metadata only; no vulnerability condition was validated.",
    ]
