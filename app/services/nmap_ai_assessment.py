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
            "- Never contradict the supplied evidence.",
            "- Never say no open services were observed if open ports are supplied.",
            "- Observed Assets must include the target host or IP when supplied.",
            "- Observed Assets must include observed services when open ports are supplied.",
            "- Do not say a service is vulnerable unless explicit evidence supports it.",
            "- Separate observed facts from potential risks and recommendations.",
            "- State only observed ports, services, and reachability; do not provide an overall low-risk verdict.",
            '- Do not say "no significant vulnerabilities" or infer vulnerability absence from a port scan.',
            "- If no open ports are supplied and the host is reachable, state that no open TCP services were observed by this scan.",
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
            "Potential Risks",
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
        f"- Risk level: {_clean(finding.get('risk_level') or 'unknown')}",
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
    line = f"  - {port}/{protocol} {service}"
    intelligence = open_port.get("intelligence") or {}
    if isinstance(intelligence, dict):
        purpose = _clean(intelligence.get("purpose") or "")
        exposure = _clean(intelligence.get("exposure") or "")
        details = [detail for detail in (purpose, exposure) if detail]
        if details:
            line = f"{line} ({'; '.join(details)})"
    return line


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
