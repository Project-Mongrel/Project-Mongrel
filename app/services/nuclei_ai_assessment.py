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

CLEAN_SCAN_LIMITATION = (
    "The assessment is limited to the templates that were executed and should not be interpreted as confirmation "
    "that the target is free of vulnerabilities."
)
CLEAN_SCAN_FACT = "No matching Nuclei findings were observed using the selected template/profile."


def generate_nuclei_ai_assessment(finding: dict) -> list[str]:
    prompt = build_nuclei_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    lines = lines or list(FALLBACK_LINES)
    return _guard_partial_timeout_response(finding, lines)


def build_nuclei_ai_assessment_prompt(finding: dict) -> str:
    metadata = finding.get("metadata") or {}
    nuclei_findings = finding.get("nuclei_findings") or []
    finding_count = int(finding.get("finding_count") or len(nuclei_findings) or 0)
    is_partial = metadata.get("partial") is True or metadata.get("timed_out") is True
    clean_scan_rules = (
        [
            f'- For clean scans, say "{CLEAN_SCAN_FACT}"',
            f"- For clean scans, explain this limitation: {CLEAN_SCAN_LIMITATION}",
        ]
        if not is_partial and finding_count <= 0 and not nuclei_findings
        else []
    )
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
            *clean_scan_rules,
            "- If the scan is partial or timed out, state that the assessment did not complete.",
            "- If partial or timed out findings are present, acknowledge the retained findings and never say no findings were observed.",
            "- For partial or timed out scans, explain that additional templates may not have executed.",
            "- Zero matches means only that no selected templates matched; it does not establish that no exploitable vulnerabilities exist.",
            "- Mention uncertainty clearly when evidence is limited.",
            "- Confidence must describe assessment quality based on the executed template set, not target security.",
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
    is_partial = metadata.get("partial") is True or metadata.get("timed_out") is True
    if is_partial:
        lines.extend(
            [
                "- Scan completion: partial/incomplete",
                f"- Timeout state: {'timed out' if metadata.get('timed_out') is True else 'partial'}",
                f"- Timeout reason: {_clean(metadata.get('timeout_reason') or 'Execution time limit reached')}",
                "- Partial limitation: additional selected templates may not have executed before termination.",
                "- Partial interpretation: absence of additional findings must not be interpreted as confirmation that no vulnerabilities exist.",
            ]
        )

    if severity_summary:
        lines.append("- Severity summary:")
        for severity, count in sorted(severity_summary.items()):
            lines.append(f"  - {_clean(severity)}: {int(count or 0)}")

    if not nuclei_findings and finding_count <= 0:
        lines.append(f"- Clean scan observation: {CLEAN_SCAN_FACT}")
        lines.append(f"- Limitation: {CLEAN_SCAN_LIMITATION}")
        return "\n".join(lines)
    if not nuclei_findings:
        lines.append("- Matched findings/templates: retained finding count was supplied, but individual finding details were not available in this record.")
        if is_partial:
            lines.append("- Retained findings: findings were collected before timeout, but detail records were not supplied to this AI prompt.")
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


def _guard_partial_timeout_response(finding: dict, lines: list[str]) -> list[str]:
    metadata = finding.get("metadata") or {}
    finding_count = int(finding.get("finding_count") or len(finding.get("nuclei_findings") or []) or 0)
    is_partial = metadata.get("partial") is True or metadata.get("timed_out") is True
    if not is_partial or finding_count <= 0:
        return lines

    retained_label = f"{finding_count} {'observation' if finding_count == 1 else 'observations'}"
    prefix = [
        "Executive Summary",
        f"- The scan reached the configured execution time limit before completion. {retained_label} were collected before termination.",
        "- Because the assessment is partial, the absence of additional findings should not be interpreted as confirmation that no vulnerabilities exist.",
        "- Additional selected templates may not have executed before timeout.",
        "",
    ]
    filtered = [line for line in lines if not _contradicts_partial_findings(line)]
    return prefix + filtered


def _contradicts_partial_findings(line: str) -> bool:
    lowered = str(line or "").lower()
    contradictory_phrases = (
        "no matching nuclei findings were observed",
        "no matching findings were observed",
        "no findings were observed",
        "no findings were detected",
        "zero matches",
    )
    return any(phrase in lowered for phrase in contradictory_phrases)


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
