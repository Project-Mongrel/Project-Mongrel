import re
from collections import Counter
from urllib.parse import urlsplit

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
TRUTHFULNESS_FALLBACK_LINES = [
    "Executive Summary",
    "- The Nuclei AI assessment was withheld because the generated response contained an unsupported security conclusion.",
    "",
    "Observed Findings",
    "- Use the deterministic Nuclei result for scanner-reported template matches and severities.",
    "",
    "Interpretation",
    "- Nuclei template matches are evidence of scanner observations; they do not automatically prove compromise, exploitability, or confirmed vulnerability.",
    "",
    "Limitations",
    "- Empty or clean Nuclei output means no selected templates matched; it does not prove target security or absence of vulnerabilities.",
    "",
    "Recommended Next Actions",
    "- Manually validate relevant findings and preserve the original scanner severity when prioritizing follow-up.",
]

CLEAN_SCAN_LIMITATION = (
    "The assessment is limited to the templates that were executed and should not be interpreted as confirmation "
    "that the target is free of vulnerabilities."
)
CLEAN_SCAN_FACT = "No matching Nuclei findings were observed using the selected template/profile."
EVIDENCE_SCOPED_MARKERS = (
    "does not establish",
    "does not prove",
    "should not be interpreted as",
    "did not assess",
    "does not assess",
    "not evidence of",
    "insufficient evidence",
    "cannot determine",
    "no selected templates matched",
    "no matching nuclei findings",
    "scanner did not report",
    "nuclei did not report",
)
UNSUPPORTED_NUCLEI_CLAIM_PATTERNS = (
    re.compile(r"\b(?:target|site|system|application|app|host)\b[^.!?]{0,80}\b(?:is|are|was|were|appears|seems|looks)\s+(?:safe|secure|clean)\b"),
    re.compile(r"\bno\s+(?:exploitable\s+)?vulnerabilities\s+(?:exist|were\s+found|were\s+detected|detected|found)\b"),
    re.compile(r"\b(?:free\s+of|without)\s+vulnerabilities\b"),
    re.compile(r"\bnot\s+indicative\s+of\s+(?:a\s+)?compromised\s+system\b"),
    re.compile(r"\b(?:no\s+)?compromise\s+(?:was\s+)?(?:detected|observed|identified|found)\b"),
    re.compile(r"\b(?:graphql|alias\s+batching|batching)\b[^.!?]{0,100}\b(?:exploitable|confirmed\s+vulnerab|can\s+be\s+exploited)\b"),
    re.compile(r"\b(?:missing|deprecated)\s+(?:security\s+)?headers?\b[^.!?]{0,100}\b(?:confirmed\s+vulnerab|required\s+by\s+browsers?)\b"),
    re.compile(r"\bx-xss-protection\b[^.!?]{0,100}\b(?:proves?|enables?|causes?|directly\s+enables?)\s+xss\b"),
)


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
    lines = _guard_partial_timeout_response(finding, lines)
    return _guard_truthfulness_response(finding, lines)


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
            "- Never claim or imply findings are not indicative of a compromised system; Nuclei did not assess compromise.",
            "- Do not recommend exploitation.",
            "- Do not claim the target is safe or secure.",
            "- Do not say a finding is confirmed vulnerable unless the supplied evidence explicitly supports it.",
            "- Preserve scanner-reported severity exactly; do not upgrade, downgrade, or summarize severities that are not present.",
            "- Do not invent scan-profile labels unless execution metadata explicitly supplies them.",
            "- Missing security headers are contextual configuration observations, not automatically confirmed vulnerabilities or universally required by browsers.",
            "- A deprecated X-XSS-Protection header does not prove or directly enable XSS.",
            "- GraphQL alias batching or similar template findings must preserve the scanner's actual meaning and must not automatically become exploitable vulnerability claims.",
            "- Nuclei tags are scanner template metadata only. A tag such as 'vuln' does not establish vulnerability, exploitability, impact, or compromise.",
            "- Use the supplied Template counts exactly; do not recalculate repeated template totals from the total finding count.",
            "- Keep host and explicit matched-at values separate. Do not present external matched-at URLs as target assets unless the host field also identifies them as target assets.",
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

    template_counts = _template_counts(nuclei_findings)
    lines.append("- Template counts:")
    for template_id, count in sorted(template_counts.items()):
        lines.append(f"  - {_clean(template_id)}={int(count)}")

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
    host = _clean(finding.get("host") or "unknown host")
    matched_at = _clean(finding.get("matched_at") or "")
    matched_source = _clean(finding.get("matched_surface_source") or "")
    matcher = _clean(finding.get("matcher_name") or "")
    line = f"  - {template_id} severity={severity} name={name} host={host}"
    if matched_at:
        provenance = f" source={matched_source}" if matched_source else ""
        line = f"{line} matched-at={matched_at}{provenance}"
    if matcher:
        line = f"{line} matcher={matcher}"
    tags = finding.get("tags") or []
    if tags:
        line = f"{line} template_tags_metadata_only={', '.join(_clean(tag) for tag in tags[:8])}"
    references = finding.get("references") or []
    if references:
        line = f"{line} references={', '.join(_clean(reference) for reference in references[:5])}"
    return line


def _observed_assets(nuclei_findings: list[dict]) -> list[str]:
    assets = []
    for finding in nuclei_findings:
        value = _clean(finding.get("host") or "")
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


def _guard_truthfulness_response(finding: dict, lines: list[str]) -> list[str]:
    if _contains_unsupported_nuclei_claim(finding, lines) or _is_incomplete_nuclei_response(lines):
        return _deterministic_nuclei_fallback(finding)
    return lines


def _contains_unsupported_nuclei_claim(finding: dict, lines: list[str]) -> bool:
    sentences = _claim_sentences(lines)
    all_info = _all_recorded_severities_are_info(finding)
    profile_supplied = bool((finding.get("metadata") or {}).get("scan_profile") or (finding.get("metadata") or {}).get("profile"))
    template_counts = _template_counts(finding.get("nuclei_findings") or [])
    external_matched_hosts = _external_matched_at_hosts(finding.get("nuclei_findings") or [])
    for sentence in sentences:
        if _is_evidence_scoped_statement(sentence):
            continue
        if all_info and re.search(r"\blow\s+and\s+info(?:rmational)?\b|\blow\s+and\s+informational\b", sentence):
            return True
        if all_info and re.search(r"\b(?:vulnerabilities|vulnerability|exploitable|exploitability|exploited)\b", sentence):
            return True
        if _contradicts_template_counts(sentence, template_counts):
            return True
        if _claims_external_matched_at_as_asset(sentence, external_matched_hosts):
            return True
        if not profile_supplied and re.search(r"\bfast\s+(?:scan|profile)\b", sentence):
            return True
        if any(pattern.search(sentence) for pattern in UNSUPPORTED_NUCLEI_CLAIM_PATTERNS):
            return True
    return False


def _template_counts(nuclei_findings: list[dict]) -> Counter:
    return Counter(
        str(item.get("template_id") or item.get("name") or "unknown-template").strip() or "unknown-template"
        for item in nuclei_findings
        if isinstance(item, dict)
    )


def _contradicts_template_counts(sentence: str, template_counts: Counter) -> bool:
    if not template_counts:
        return False
    lowered = str(sentence or "").lower()
    for template_id, count in template_counts.items():
        terms = {
            str(template_id).lower(),
            str(template_id).lower().replace("-", " "),
        }
        if template_id == "http-missing-security-headers":
            terms.update({"missing security headers", "http missing security headers"})
        if not any(term and term in lowered for term in terms):
            continue
        numbers = {int(value) for value in re.findall(r"\b\d+\b", lowered)}
        if numbers and any(number != int(count) for number in numbers):
            return True
    return False


def _is_incomplete_nuclei_response(lines: list[str]) -> bool:
    nonempty = [str(line or "").strip() for line in lines if str(line or "").strip()]
    if not nonempty:
        return True
    headings = {"Executive Summary", "Observed Facts", "Observed Assets", "Potential Risks", "Confidence", "Recommended Next Actions"}
    present = {line.rstrip(":") for line in nonempty if line.rstrip(":") in headings}
    if present and nonempty[-1].rstrip(":") in headings:
        return True
    return bool(present) and "Executive Summary" in present and "Confidence" not in present and "Recommended Next Actions" not in present


def _external_matched_at_hosts(nuclei_findings: list[dict]) -> set[str]:
    hosts: set[str] = set()
    for item in nuclei_findings:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "").lower().strip()
        matched = str(item.get("matched_at") or "").strip()
        try:
            netloc = urlsplit(matched).hostname or ""
        except ValueError:
            netloc = ""
        netloc = netloc.lower().strip()
        if netloc and host and netloc != host:
            hosts.add(netloc)
    return hosts


def _claims_external_matched_at_as_asset(sentence: str, external_hosts: set[str]) -> bool:
    lowered = str(sentence or "").lower()
    if not any(host in lowered for host in external_hosts):
        return False
    return bool(re.search(r"\b(?:target|observed|assessment)\s+assets?\b|\bassets?\s+(?:observed|include|includes|were)\b", lowered))


def _deterministic_nuclei_fallback(finding: dict) -> list[str]:
    nuclei_findings = [item for item in (finding.get("nuclei_findings") or []) if isinstance(item, dict)]
    finding_count = int(finding.get("finding_count") or len(nuclei_findings) or 0)
    severity_summary = finding.get("severity_summary") if isinstance(finding.get("severity_summary"), dict) else {}
    template_counts = _template_counts(nuclei_findings)
    severities = sorted(
        {
            str(item.get("severity") or "info").upper()
            for item in nuclei_findings
            if str(item.get("severity") or "").strip()
        }
    )
    if not severities and severity_summary:
        severities = [str(key).upper() for key, value in sorted(severity_summary.items()) if int(value or 0) > 0]
    assets = _observed_assets(nuclei_findings)
    metadata = finding.get("metadata") or {}
    is_partial = metadata.get("partial") is True or metadata.get("timed_out") is True
    matched_examples = []
    for item in nuclei_findings[:6]:
        matched = _clean(item.get("matched_at") or "")
        source = _clean(item.get("matched_surface_source") or "")
        template = _clean(item.get("template_id") or item.get("name") or "template")
        if matched:
            matched_examples.append(f"{template}: matched-at {matched}" + (f" ({source})" if source else ""))
    counts_text = ", ".join(f"{_clean(template)}={int(count)}" for template, count in sorted(template_counts.items())) or "none"
    return [
        "Executive Summary",
        f"- Nuclei stored {finding_count} scanner-reported template match(es). Template counts: {counts_text}.",
        *([f"- {finding_count} {'observation' if finding_count == 1 else 'observations'} were collected before termination."] if is_partial else []),
        *(["- Scan completion: partial/incomplete; additional selected templates may not have executed before termination."] if is_partial else []),
        "",
        "Observed Facts",
        "- Scanner severities preserved exactly: " + (", ".join(severities) if severities else "none recorded") + ".",
        "- Tags such as 'vuln' are scanner template metadata only; they do not establish vulnerability, exploitability, impact, or compromise.",
        *( [ "- Explicit match provenance: " + "; ".join(matched_examples) + "." ] if matched_examples else [] ),
        "",
        "Observed Assets",
        "- Host/target values observed in stored evidence: " + (", ".join(assets[:10]) if assets else "none normalized") + ".",
        "- External matched-at URLs are match provenance, not automatically target assets.",
        "",
        "Potential Risks",
        "- Missing security headers and exposure/detection templates are contextual scanner observations requiring review; INFO severity is not upgraded.",
        "",
        "Confidence",
        "Medium for reporting stored Nuclei template counts and severities; lower for business impact or exploitability because those are not established by template matches alone.",
        "",
        "Recommended Next Actions",
        "- Review the deterministic Nuclei result by template and matcher, validate any relevant configuration observations manually, and preserve scanner severity when prioritizing follow-up.",
    ]


def _claim_sentences(lines: list[str]) -> list[str]:
    text = " ".join(str(line or "").strip() for line in lines)
    return [
        re.sub(r"\s+", " ", sentence).strip().lower()
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", text)
        if sentence.strip()
    ]


def _is_evidence_scoped_statement(sentence: str) -> bool:
    return any(marker in sentence for marker in EVIDENCE_SCOPED_MARKERS)


def _all_recorded_severities_are_info(finding: dict) -> bool:
    nuclei_findings = finding.get("nuclei_findings") or []
    severities = [str(item.get("severity") or "info").lower() for item in nuclei_findings]
    severity_summary = finding.get("severity_summary") or {}
    for severity, count in severity_summary.items():
        if int(count or 0) > 0:
            severities.append(str(severity or "info").lower())
    return bool(severities) and set(severities) <= {"info", "informational"}


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
