from app.services.ai_client import ask_ai

FALLBACK_SUMMARY_LINES = [
    "Executive Summary",
    "- AI summary unavailable. Review the deterministic scan result for observed evidence.",
    "",
    "Observed Facts",
    "- Stored scan evidence is available but could not be summarized by AI.",
    "",
    "Observed Assets",
    "- Review the original scan result.",
    "",
    "Potential Risks",
    "- No additional risk claims were generated.",
    "- Absence of scanner findings must not be interpreted as proof that no vulnerabilities exist.",
    "",
    "Confidence",
    "Low",
    "",
    "Recommended Next Actions",
    "- Review the deterministic scan result and validate any observed services or findings.",
]

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


def generate_scan_ai_summary(finding: dict) -> list[str]:
    prompt = build_scan_ai_summary_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_SUMMARY_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_SUMMARY_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return lines or list(FALLBACK_SUMMARY_LINES)


def build_scan_ai_summary_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing reconnaissance notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied stored scan evidence.",
            "- Do not invent vulnerabilities.",
            "- Do not invent assets, ports, services, technologies, CVEs, or findings.",
            "- Do not claim compromise.",
            "- Never recommend exploitation.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Do not infer safety or absence of vulnerabilities from missing or empty scan findings.",
            "- If evidence is limited, say so clearly.",
            "- Confidence must be High, Medium, or Low and must reflect evidence completeness only.",
            "- Recommended next actions must map directly to observed evidence.",
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
            "Stored Scan Evidence:",
            _format_finding_evidence(finding),
        ]
    )


def _format_finding_evidence(finding: dict) -> str:
    lines = [
        f"- Tool: {finding.get('source') or 'unknown'}",
        f"- Target: {finding.get('target') or 'unknown'}",
        f"- Status: {finding.get('status') or 'unknown'}",
        f"- Risk level: {finding.get('risk_level') or 'unknown'}",
        f"- Finding count: {finding.get('finding_count', 0)}",
        f"- Summary: {_clean_text(finding.get('summary') or '')}",
    ]
    open_ports = finding.get("open_ports") or []
    if open_ports:
        lines.append("- Open ports:")
        for open_port in open_ports[:20]:
            lines.append(
                f"  - {open_port.get('port')}/{open_port.get('protocol', 'tcp')} {open_port.get('service') or 'unknown'}"
            )
    nuclei_findings = finding.get("nuclei_findings") or []
    if nuclei_findings:
        lines.append("- Findings:")
        for item in nuclei_findings[:20]:
            lines.append(
                f"  - {item.get('template_id') or item.get('name') or 'finding'} "
                f"severity={item.get('severity') or 'unknown'} host={item.get('host') or item.get('matched_at') or 'unknown'}"
            )
    observation_counts = finding.get("observation_counts") or {}
    if observation_counts:
        lines.append("- Observation counts:")
        for key, value in sorted(observation_counts.items()):
            lines.append(f"  - {key}: {value}")
    metadata = finding.get("metadata") or {}
    if metadata.get("observation_count") is not None:
        lines.append(f"- Observation count: {metadata.get('observation_count')}")
    return "\n".join(lines)


def _clean_text(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:1000]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
