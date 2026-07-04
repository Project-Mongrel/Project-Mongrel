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
    "Gitleaks AI assessment unavailable.",
    "Use the deterministic Gitleaks result for redacted secret-exposure evidence and next actions.",
]


def generate_gitleaks_ai_assessment(finding: dict) -> list[str]:
    prompt = build_gitleaks_ai_assessment_prompt(finding)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)
    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)
    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return lines or list(FALLBACK_LINES)


def build_gitleaks_ai_assessment_prompt(finding: dict) -> str:
    return "\n".join(
        [
            "You are a senior penetration tester preparing secret-exposure notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied redacted Gitleaks evidence.",
            "- Never include or infer raw secret values.",
            "- Do not validate, use, or test credentials.",
            "- Do not claim compromise.",
            "- Treat detections as secret-exposure evidence, not proof of account access.",
            "- Recommend rotation/revocation and repository cleanup when detections exist.",
            "- Separate observed facts from potential risks and recommendations.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed Redacted Facts",
            "Potential Risks",
            "Recommended Next Actions",
            "Confidence",
            "Evidence Limitations",
            "",
            "Observed Gitleaks Evidence:",
            _format_gitleaks_evidence(finding),
        ]
    )


def _format_gitleaks_evidence(finding: dict) -> str:
    evidence = finding.get("gitleaks_evidence") or {}
    summary = finding.get("gitleaks_summary") or {}
    lines = [
        f"- Scope: {_clean(evidence.get('scan_root') or finding.get('target') or 'unknown')}",
        f"- Status: {_clean(finding.get('status') or 'unknown')}",
        f"- Secret finding count: {int(summary.get('finding_count') or 0)}",
        f"- Affected files count: {int(summary.get('affected_files_count') or 0)}",
        f"- Rule summary: {_format_counts(summary.get('rule_summary') or {})}",
        f"- Provider summary: {_format_counts(summary.get('provider_summary') or {})}",
        f"- Severity summary: {_format_counts(summary.get('severity_summary') or {})}",
    ]
    findings = evidence.get("findings") or []
    if findings:
        lines.append("- Redacted findings:")
        for item in findings[:30]:
            lines.append(
                "  - "
                f"rule={_clean(item.get('rule_id') or 'unknown')} "
                f"file={_clean(item.get('file_path') or 'unknown')} "
                f"line={_clean(item.get('line_number') or 'unknown')} "
                f"provider={_clean(item.get('provider') or 'unknown')} "
                f"severity={_clean(item.get('severity') or 'unknown')} "
                f"fingerprint={_clean(item.get('fingerprint') or 'not supplied')} "
                f"secret={_clean(item.get('redacted_secret_preview') or '<REDACTED>')}"
            )
    else:
        lines.append("- Redacted findings: none recorded")
    for limitation in evidence.get("limitations") or []:
        lines.append(f"- Limitation: {_clean(limitation)}")
    return "\n".join(lines)


def _format_counts(counts: dict) -> str:
    return ", ".join(f"{_clean(key)}={int(value or 0)}" for key, value in sorted(counts.items())) if counts else "none"


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:500]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
