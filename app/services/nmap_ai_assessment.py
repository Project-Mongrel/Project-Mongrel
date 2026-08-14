import re

from app.services.ai_client import ask_ai
from app.services.nmap_interpretation import is_nmap_assessment_inconclusive

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
    "Nmap AI assessment unavailable.",
    "Use the deterministic Nmap result for observed services, risk notes, and next actions.",
]

UNSUPPORTED_CLAIM_FALLBACK_LINES = [
    "Executive Summary",
    "- The Nmap AI assessment was withheld because the generated response contained an unsupported safety or vulnerability-absence claim.",
    "",
    "Observed Facts",
    "- The deterministic Nmap result remains the source of truth for observed host status, ports, services, and versions.",
    "",
    "Interpretation",
    "- Nmap evidence can identify observed exposure, but it does not prove that a target is safe or free of vulnerabilities.",
    "",
    "Limitations / Uncertainty",
    "- Absence of observed open ports or findings must not be interpreted as proof that no services or vulnerabilities exist.",
    "",
    "Confidence",
    "High confidence that the withheld wording was not supported by the supplied Nmap evidence.",
    "",
    "Recommended Next Actions",
    "- Review the deterministic Nmap result and validate observed services with authorized follow-up checks.",
]

UNSUPPORTED_SAFETY_CLAIM_PATTERNS = (
    re.compile(r"\b(?:the\s+)?(?:host|system|target)\s+(?:is|was|appears|seems|looks)\s+(?:to\s+be\s+)?(?:secure|safe)\b"),
    re.compile(r"\bno\s+(?:known\s+|significant\s+|confirmed\s+|exploitable\s+)?vulnerabilit(?:y|ies)\b"),
    re.compile(r"\bno\s+security\s+(?:issues|risks)\b"),
    re.compile(r"\bno\s+threats?\s+(?:were\s+)?(?:found|detected|identified)\b"),
    re.compile(r"\b(?:fully|completely)\s+protected\b"),
    re.compile(r"\b(?:the\s+)?(?:host|system|target)\s+(?:is|was|appears|seems|looks)\s+(?:to\s+be\s+)?not\s+vulnerable\b"),
    re.compile(r"\bnot\s+vulnerable\b"),
    re.compile(r"\bfree\s+of\s+vulnerabilities\b"),
    re.compile(r"\bfirewall\s+(?:is\s+)?protect(?:s|ing)\b"),
)

EVIDENCE_SCOPED_NEGATION_MARKERS = (
    "nmap did not report",
    "nmap did not identify",
    "nmap did not provide",
    "scan evidence is insufficient",
    "evidence is insufficient",
    "insufficient evidence",
    "not enough evidence",
    "cannot determine",
    "can't determine",
    "unable to determine",
    "does not prove",
    "doesn't prove",
    "not proof",
    "no vulnerability evidence",
    "without vulnerability evidence",
)


def generate_nmap_ai_assessment(finding: dict) -> list[str]:
    if is_nmap_assessment_inconclusive(finding):
        return _build_inconclusive_assessment_lines(finding)

    prompt = build_nmap_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    if _contains_unsupported_safety_claim(lines):
        return list(UNSUPPORTED_CLAIM_FALLBACK_LINES)
    return lines or list(FALLBACK_LINES)


def build_nmap_ai_assessment_prompt(finding: dict) -> str:
    inconclusive_rules = []
    if is_nmap_assessment_inconclusive(finding):
        inconclusive_rules = [
            "- This Nmap evidence is inconclusive because a reachable or assessable target was not established.",
            "- Do not describe this as a clean scan, low-risk result, or absence of vulnerabilities.",
            "- State that no conclusions about exposed services or vulnerabilities can be drawn from this run.",
            "- Confidence may be High only about the inconclusive scan state, not about target safety.",
        ]
    return "\n".join(
        [
            "You are a senior penetration tester preparing reconnaissance notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied observed Nmap evidence.",
            "- Do not invent vulnerabilities.",
            "- Do not invent assets, ports, services, CVEs, or findings.",
            "- Do not claim compromise.",
            "- Do not recommend exploitation.",
            "- Do not claim the target is safe or secure.",
            "- Do not claim a firewall is protecting the host from Nmap output alone.",
            "- Never contradict the supplied evidence.",
            "- Never say no open services were observed if open ports are supplied.",
            "- Observed Assets must include the target host or IP when supplied.",
            "- Observed Assets must include observed services when open ports are supplied.",
            "- Do not say a service is vulnerable unless explicit evidence supports it.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Include a distinct Interpretation section.",
            "- Include a distinct Limitations / Uncertainty section.",
            "- State only observed ports, services, and reachability; do not provide an overall low-risk verdict.",
            '- Do not say "no significant vulnerabilities" or infer vulnerability absence from a port scan.',
            "- If no open ports are supplied and the host is reachable, state that no open TCP services were observed by this scan.",
            "- Also state that this does not prove no services or vulnerabilities exist.",
            "- Treat service and version strings as identification evidence only, not vulnerability proof.",
            "- Mention uncertainty clearly when evidence is limited.",
            "- Confidence must be High, Medium, or Low and must reflect evidence completeness only.",
            "- Recommended next actions must map directly to observed evidence.",
            *inconclusive_rules,
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Facts",
            "Observed Assets",
            "Interpretation",
            "Potential Risks",
            "Limitations / Uncertainty",
            "Confidence",
            "Recommended Next Actions",
            "",
            "Observed Nmap Evidence:",
            _format_nmap_evidence(finding),
        ]
    )


def _format_nmap_evidence(finding: dict) -> str:
    lines = [
        f"- Target: {_clean(finding.get('target') or 'unknown')}",
        f"- Resolved IP: {_clean(finding.get('resolved_ip') or finding.get('ip_address') or 'not supplied')}",
        f"- Host status: {_clean(finding.get('host_status') or 'unknown')}",
        f"- Deterministic exposure risk from observed Nmap evidence: {_format_risk_for_evidence(finding)}",
    ]
    if is_nmap_assessment_inconclusive(finding):
        lines.extend(
            [
                "- Assessment result: inconclusive",
                "- Interpretation: target reachability or assessability was not established",
                "- Security conclusion: no conclusion about exposed ports, services, vulnerabilities, or posture can be made from this run",
            ]
        )
    risk_notes = finding.get("risk_notes") or []
    if risk_notes:
        lines.append("- Deterministic notes:")
        for note in risk_notes[:10]:
            lines.append(f"  - {_clean(note)}")

    open_ports = finding.get("open_ports") or []
    if open_ports:
        lines.append("- Open ports and services:")
        for open_port in open_ports[:20]:
            lines.append(_format_open_port(open_port))
        lines.append("- Observed assets derived from Nmap evidence:")
        lines.append(f"  - Host: {_clean(finding.get('target') or 'unknown')}")
        resolved_ip = _clean(finding.get("resolved_ip") or finding.get("ip_address") or "")
        if resolved_ip:
            lines.append(f"  - IP: {resolved_ip}")
        lines.append(f"  - Services: {_format_ports(open_ports)}")
    elif finding.get("filtered_ports"):
        lines.append("- Filtered ports:")
        for filtered_port in (finding.get("filtered_ports") or [])[:20]:
            lines.append(_format_filtered_port(filtered_port))
    elif is_nmap_assessment_inconclusive(finding):
        lines.append("- Open ports and services: not established by this scan")
    else:
        lines.append("- Open ports and services: none observed by this scan")

    comparison = finding.get("comparison") or {}
    if comparison:
        lines.append("- Comparison data:")
        lines.append(f"  - Summary: {_clean(comparison.get('summary') or 'not supplied')}")
        lines.append(f"  - New ports: {_format_ports(comparison.get('new_ports') or [])}")
        lines.append(f"  - Removed ports: {_format_ports(comparison.get('removed_ports') or [])}")
        if comparison.get("risk_changed") is not None:
            lines.append(f"  - Risk changed: {bool(comparison.get('risk_changed'))}")

    impact = finding.get("impact") or {}
    if impact:
        lines.append("- Impact assessment:")
        lines.append(f"  - Summary: {_clean(impact.get('summary') or 'not supplied')}")
        if impact.get("impact_level"):
            lines.append(f"  - Impact level: {_clean(impact.get('impact_level'))}")

    return "\n".join(lines)


def _format_open_port(open_port: dict) -> str:
    port = _clean(open_port.get("port") or "unknown")
    protocol = _clean(open_port.get("protocol") or "tcp")
    service = _clean(open_port.get("service") or "unknown")
    version = _clean(open_port.get("version") or "")
    version_suffix = f" version={version}" if version else ""
    line = f"  - {port}/{protocol} {service}{version_suffix}"
    intelligence = open_port.get("intelligence") or {}
    if isinstance(intelligence, dict):
        purpose = _clean(intelligence.get("purpose") or "")
        exposure = _clean(intelligence.get("exposure") or "")
        details = [detail for detail in (purpose, exposure) if detail]
        if details:
            line = f"{line} ({'; '.join(details)})"
    return line


def _format_filtered_port(filtered_port: dict) -> str:
    port = _clean(filtered_port.get("port") or "unknown")
    protocol = _clean(filtered_port.get("protocol") or "tcp")
    state = _clean(filtered_port.get("state") or "filtered")
    service = _clean(filtered_port.get("service") or "")
    service_suffix = f" {service}" if service else ""
    return f"  - {port}/{protocol} {state}{service_suffix}"


def _format_ports(open_ports: list[dict]) -> str:
    if not open_ports:
        return "none"
    return ", ".join(
        f"{_clean(open_port.get('port') or 'unknown')}/{_clean(open_port.get('protocol') or 'tcp')} "
        f"{_clean(open_port.get('service') or 'unknown')}"
        for open_port in open_ports[:10]
    )


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:500]


def _format_risk_for_evidence(finding: dict) -> str:
    risk_level = _clean(finding.get("risk_level") or "unknown")
    if risk_level.lower() == "low" and not (finding.get("open_ports") or []):
        return "low open-port exposure in this scan only; not a safety or vulnerability-absence verdict"
    if risk_level.lower() == "unknown":
        return "unknown"
    return f"{risk_level}; based on observed Nmap exposure only"


def _build_inconclusive_assessment_lines(finding: dict) -> list[str]:
    target = _clean(finding.get("target") or "unknown")
    host_status = _clean(finding.get("host_status") or "unknown")
    return [
        "Executive Summary",
        f"- The Nmap run did not establish a reachable or assessable target for {target}.",
        "- No conclusion about exposed services, vulnerabilities, or security posture can be drawn from this run.",
        "",
        "Observed Facts",
        f"- Target supplied: {target}",
        f"- Host status: {host_status}",
        "- Open services were not established by this evidence.",
        "",
        "Observed Assets",
        f"- {target}",
        "",
        "Potential Risks",
        "- Unknown. The target could not be meaningfully assessed by this Nmap run.",
        "",
        "Limitations / Uncertainty",
        "- This scan did not provide enough evidence to assess exposed services or vulnerability posture.",
        "",
        "Confidence",
        "High confidence that this scan result is inconclusive; no confidence is assigned to target safety.",
        "",
        "Recommended Next Actions",
        "- Verify DNS resolution, routing, VPN/interface selection, and authorization scope.",
        "- Re-run the scan after confirming the target can be reached from the scanner.",
    ]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)


def _contains_unsupported_safety_claim(lines: list[str]) -> bool:
    for sentence in _claim_sentences(lines):
        if _is_evidence_scoped_negation(sentence):
            continue
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_SAFETY_CLAIM_PATTERNS):
            return True
    return False


def _claim_sentences(lines: list[str]) -> list[str]:
    text = " ".join(str(line or "").strip() for line in lines)
    return [
        re.sub(r"\s+", " ", sentence).strip().lower()
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", text)
        if sentence.strip()
    ]


def _is_evidence_scoped_negation(sentence: str) -> bool:
    return any(marker in sentence for marker in EVIDENCE_SCOPED_NEGATION_MARKERS)
