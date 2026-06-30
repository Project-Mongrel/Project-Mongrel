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
    "Nuclei AI assessment unavailable.",
    "Use the deterministic Nuclei result for observed findings and next actions.",
]

CLEAN_SCAN_LIMITATION = "Nuclei only reports issues matched by the selected templates/profile."
CLEAN_SCAN_FACT = "No matching Nuclei findings were observed with the selected template/profile."


def generate_nuclei_ai_assessment(finding: dict) -> list[str]:
    prompt = build_nuclei_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return lines or list(FALLBACK_LINES)


def build_nuclei_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing reconnaissance notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied observed Nuclei evidence.",
            "- Do not invent vulnerabilities.",
            "- Do not invent assets, URLs, technologies, CVEs, templates, or findings.",
            "- Do not claim compromise.",
            "- Do not recommend exploitation.",
            "- Do not claim the target is safe or secure.",
            "- Do not say a finding is confirmed vulnerable unless the supplied evidence explicitly supports it.",
            "- Separate observed facts from potential risks and recommendations.",
            f'- For clean scans, say "{CLEAN_SCAN_FACT}"',
            f"- For clean scans, explain this limitation: {CLEAN_SCAN_LIMITATION}",
            '- State "No confirmed vulnerabilities were identified during reconnaissance" when appropriate.',
            "- Mention uncertainty clearly when evidence is limited.",
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
            "Observed Nuclei Evidence:",
            _format_nuclei_evidence(finding),
        ]
    )


def _format_nuclei_evidence(finding: dict) -> str:
    nuclei_findings = finding.get("nuclei_findings") or []
    metadata = finding.get("metadata") or {}
    severity_summary = finding.get("severity_summary") or {}
    finding_count = int(finding.get("finding_count") or len(nuclei_findings) or 0)
    lines = [
        f"- Target URL: {_clean(finding.get('target') or 'unknown')}",
        f"- Scan profile/templates: {_clean(metadata.get('scan_profile') or metadata.get('profile') or 'not supplied')}",
        f"- Elapsed time: {_clean(metadata.get('elapsed') or metadata.get('elapsed_seconds') or 'not supplied')}",
        f"- Finding count: {finding_count}",
        f"- Risk level: {_clean(finding.get('risk_level') or 'unknown')}",
    ]

    if severity_summary:
        lines.append("- Severity summary:")
        for severity, count in sorted(severity_summary.items()):
            lines.append(f"  - {_clean(severity)}: {int(count or 0)}")

    if not nuclei_findings:
        lines.append(f"- Clean scan observation: {CLEAN_SCAN_FACT}")
        lines.append(f"- Limitation: {CLEAN_SCAN_LIMITATION}")
        return "\n".join(lines)

    lines.append("- Matched findings/templates:")
    for item in nuclei_findings[:20]:
        lines.append(_format_finding(item))

    assets = _observed_assets(nuclei_findings)
    if assets:
        lines.append("- Observed assets:")
        for asset in assets[:20]:
            lines.append(f"  - {_clean(asset)}")

    technologies = _unique_values(nuclei_findings, "technology", "technologies")
    if technologies:
        lines.append(f"- Technologies: {', '.join(technologies[:20])}")

    cves = _extract_cves(nuclei_findings)
    if cves:
        lines.append(f"- CVEs: {', '.join(cves[:20])}")

    return "\n".join(lines)


def _format_finding(finding: dict) -> str:
    template_id = _clean(finding.get("template_id") or "unknown-template")
    severity = _clean(finding.get("severity") or "unknown")
    name = _clean(finding.get("name") or "unnamed finding")
    matched_at = _clean(finding.get("matched_at") or finding.get("host") or "unknown URL")
    line = f"  - {template_id} severity={severity} name={name} matched={matched_at}"
    tags = finding.get("tags") or []
    if tags:
        line = f"{line} tags={', '.join(_clean(tag) for tag in tags[:8])}"
    references = finding.get("references") or []
    if references:
        line = f"{line} references={', '.join(_clean(reference) for reference in references[:5])}"
    return line


def _observed_assets(nuclei_findings: list[dict]) -> list[str]:
    assets = []
    for finding in nuclei_findings:
        for key in ("host", "matched_at"):
            value = _clean(finding.get(key) or "")
            if value and value.lower() not in {asset.lower() for asset in assets}:
                assets.append(value)
    return assets


def _unique_values(nuclei_findings: list[dict], *keys: str) -> list[str]:
    values = []
    for finding in nuclei_findings:
        for key in keys:
            raw_value = finding.get(key)
            candidates = raw_value if isinstance(raw_value, list) else [raw_value]
            for candidate in candidates:
                value = _clean(candidate or "")
                if value and value.lower() not in {item.lower() for item in values}:
                    values.append(value)
    return values


def _extract_cves(nuclei_findings: list[dict]) -> list[str]:
    cves = []
    for finding in nuclei_findings:
        for value in [finding.get("template_id"), finding.get("name"), *(finding.get("tags") or [])]:
            text = _clean(value or "")
            for part in text.replace("_", "-").split():
                normalized = part.strip(".,;:()[]").upper()
                if normalized.startswith("CVE-") and normalized not in cves:
                    cves.append(normalized)
    return cves


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:500]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
