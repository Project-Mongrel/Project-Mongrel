import re
from datetime import UTC, datetime

from app.services.ai_client import ask_ai
from app.services.findings_store import get_user_scan_runs
from app.services.icon_helper import icon, section_label
from app.services.target_normalizer import normalize_target_key

AI_UNAVAILABLE_RESPONSES = {
    "AI integration is not configured yet.",
    "Unsupported AI provider.",
    "Ollama base URL is not configured.",
    "AI request timed out.",
    "Unable to connect to Ollama server.",
    "AI request failed.",
    "Malformed Ollama response.",
    "Empty AI response.",
    "Mongrel generated internal reasoning but no final answer. Try rephrasing the question.",
}

_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(password|token|secret|api[_-]?key|access[_-]?key|session[_-]?token)\s*[:=]\s*\S+"),
)


def generate_markdown_report(
    user_id: int,
    target: str | None = None,
    include_ai_assessment: bool = False,
    report_id: str | None = None,
    investigation_name: str | None = None,
    ai_assessment_lines: list[str] | None = None,
) -> str:
    scan_runs = _filter_scan_runs(get_user_scan_runs(user_id), target)
    report_target = target or _infer_report_target(scan_runs)
    generated_at = datetime.now(UTC)
    readable_report_id = report_id or generate_report_id(generated_at=generated_at)
    highest_risk = _highest_risk(scan_runs).upper()

    lines = [
        "# Project Mongrel",
        section_label("security", "Security Assessment Report"),
        "",
        "Report ID:",
        readable_report_id,
        "",
        *_format_investigation_name(investigation_name),
        "Target / Scope:",
        str(report_target or "Multiple targets"),
        "",
        "Generated:",
        _format_human_timestamp(generated_at),
        "",
        "Overall Risk:",
        highest_risk,
        "",
        "## Executive Summary",
        *_format_executive_summary(scan_runs, report_target),
        "",
        f"## {section_label('statistics', 'Assessment Statistics')}",
        *_format_assessment_statistics(scan_runs, generated_at),
        "",
        f"## {section_label('saved', 'Scan Sources Used')}",
        *_format_scan_sources(scan_runs),
        "",
        f"## {section_label('risk', 'Risk Overview')}",
        *_format_risk_overview(scan_runs),
        "",
        f"## {section_label('observation', 'Technical Findings')}",
        *_format_technical_findings(scan_runs),
        "",
        f"## {section_label('completed', 'Clean Scan Notes')}",
        *_format_clean_scan_notes(scan_runs),
        "",
        f"## {section_label('security', 'Recommendations')}",
        *_format_recommendations(scan_runs),
    ]
    if include_ai_assessment:
        lines.extend(["", f"## {section_label('mongrel_ai', 'Executive Assessment')}", *(ai_assessment_lines or format_report_ai_assessment(scan_runs, report_target))])

    lines.extend(["", f"## {section_label('saved', 'Appendix / Scan History')}", *_format_scan_history(scan_runs)])
    return "\n".join(lines)


def build_report_ai_assessment_prompt(scan_runs: list[dict], target: str | None = None) -> str:
    lines = [
        "Create a concise AI assessment for a Project Mongrel Markdown security report.",
        "",
        "Rules:",
        "- Only use the provided scan history and findings.",
        "- Do not invent vulnerabilities.",
        "- Do not invent ports.",
        "- Do not invent services.",
        "- Do not invent CVEs.",
        "- Treat TShark evidence as packet metadata only; do not infer exploitation, compromise, vulnerability, ownership, authentication success, successful TLS handshakes, or completed HTTP transactions from packet observations alone.",
        "- Treat TShark correlation confidence as packet-to-validation attribution confidence, not exploitability or compromise confidence.",
        "- Treat Gitleaks evidence as redacted secret-pattern detection only; do not infer validity, current usability, ownership, unauthorized access, compromise, exfiltration, repository security, or absence of secrets.",
        "- Treat Prowler evidence as scanner-reported cloud check output only; PASS does not prove account/resource security, FAIL does not prove exploitability, compromise, data exposure, or compliance failure, and severity/compliance mappings remain check-specific scanner metadata.",
        "- If evidence is missing, say it is unknown from the available scan history.",
        "- Give context-aware recommendations based on the supplied services and findings.",
        "- Never recommend closing ports blindly.",
        "- Avoid absolute statements such as close all open ports.",
        "- For administrative services, prefer reviewing whether the service is required, restricting access to trusted networks, disabling it if unnecessary, and confirming secure configuration.",
        "",
        "Assess:",
        "- Overall risk",
        "- Most important findings",
        "- Likely business/security impact",
        "- Recommended priority actions",
        "- Observed risk level from supplied evidence, without inferring safety from absence of findings",
        "",
        f"Target: {target or _infer_report_target(scan_runs) or 'All targets'}",
        f"Scan count: {len(scan_runs)}",
        f"Highest deterministic risk: {_highest_risk(scan_runs).upper()}",
        "",
        "Stored scan history:",
    ]
    if not scan_runs:
        lines.append("No scan history is available.")
        return "\n".join(lines)

    for index, scan_run in enumerate(scan_runs, start=1):
        lines.extend(_format_scan_run_for_ai_prompt(index, scan_run))

    return "\n".join(lines)


def build_report_metadata(
    scan_runs: list[dict],
    target: str | None = None,
    include_ai_assessment: bool = False,
    report_id: str | None = None,
    investigation_name: str | None = None,
) -> dict:
    report_target = target or _infer_report_target(scan_runs) or "Multiple targets"
    report_type = "ai_assessment" if include_ai_assessment else "deterministic"
    highest_risk = _highest_risk(scan_runs)
    scan_count = len(scan_runs)
    source_count = len({scan_run.get("source") for scan_run in scan_runs if scan_run.get("source")})
    finding_count = sum(_finding_count(scan_run) for scan_run in scan_runs)
    title = "Executive Assessment Report" if include_ai_assessment else "Deterministic Report"
    metadata = {
        "report_id": report_id or generate_report_id(),
        "target": report_target,
        "report_type": report_type,
        "title": title,
        "summary": (
            f"{report_target} report generated from {scan_count} scan run(s), "
            f"{source_count} source(s), and {finding_count} finding(s)."
        ),
        "overall_risk": highest_risk,
        "source_count": source_count,
        "scan_count": scan_count,
        "finding_count": finding_count,
    }
    if investigation_name:
        metadata["investigation_name"] = investigation_name

    return metadata


def generate_report_id(existing_report_count: int = 0, generated_at: datetime | None = None) -> str:
    timestamp = generated_at or datetime.now(UTC)
    return f"PM-{timestamp.astimezone(UTC):%Y%m%d}-{existing_report_count + 1:04d}"


def format_report_ai_assessment(scan_runs: list[dict], target: str | None) -> list[str]:
    if not scan_runs:
        return ["AI assessment unavailable: no scan history is available."]

    prompt = build_report_ai_assessment_prompt(scan_runs, target)
    try:
        assessment = ask_ai(prompt, path="standalone_ai_report")
    except Exception as exc:
        return [f"AI assessment unavailable: {exc}", "", "The deterministic report remains based on persisted scan history."]

    if _is_ai_unavailable_response(assessment):
        return [
            f"AI assessment unavailable: {assessment}",
            "",
            "The deterministic report remains based on persisted scan history.",
        ]

    return [assessment]


def _is_ai_unavailable_response(response: str) -> bool:
    normalized = str(response or "").strip()
    return normalized in AI_UNAVAILABLE_RESPONSES


def _format_scan_run_for_ai_prompt(index: int, scan_run: dict) -> list[str]:
    lines = [
        f"{index}. Source: {_source_label(scan_run.get('source'))}",
        f"   Target: {scan_run.get('target') or 'unknown'}",
        f"   Risk Level: {str(scan_run.get('risk_level') or 'unknown').upper()}",
        f"   Finding Count: {_finding_count(scan_run)}",
        f"   Status: {scan_run.get('status') or 'findings'}",
        f"   Summary: {scan_run.get('summary') or 'none'}",
    ]
    if scan_run.get("source") in {"nmap", "nmap_xml"}:
        open_ports = scan_run.get("open_ports") or []
        lines.append("   Open Ports:")
        lines.extend(
            f"   - {port.get('port')}/{port.get('protocol')} {port.get('service')}" for port in open_ports[:20]
        )
        if not open_ports:
            lines.append("   - none")
    if scan_run.get("source") == "nuclei":
        nuclei_findings = scan_run.get("nuclei_findings") or []
        lines.append("   Nuclei Findings:")
        for finding in nuclei_findings[:20]:
            lines.append(
                f"   - {finding.get('name') or finding.get('template_id') or 'Unnamed finding'} "
                f"({str(finding.get('severity') or 'info').upper()})"
            )
        if not nuclei_findings:
            lines.append("   - none")
    if scan_run.get("source") == "prowler":
        evidence = scan_run.get("prowler_evidence") or {}
        summary = scan_run.get("prowler_summary") or {}
        lines.extend(
            [
                f"   Provider: {scan_run.get('provider') or evidence.get('provider') or 'unknown'}",
                f"   Context: {scan_run.get('cloud_context') or evidence.get('cloud_context') or scan_run.get('target') or 'unknown'}",
                f"   Failed Checks: {int(summary.get('failed_count') or 0)}",
                f"   Passed Checks: {int(summary.get('passed_count') or 0)}",
                f"   Highest Scanner-Reported Severity: {summary.get('highest_severity') or 'none'}",
                "   Boundary: PASS/FAIL are check-specific scanner results; they do not prove cloud/account/resource security, exploitability, compromise, data exposure, or organization-wide compliance.",
                "   Prowler Checks:",
            ]
        )
        for finding in (evidence.get("findings") or [])[:20]:
            lines.append(
                f"   - {finding.get('status') or 'unknown'} {finding.get('check_id') or 'check'} "
                f"severity={finding.get('severity') or 'unknown'} service={finding.get('service') or 'unknown'}"
            )
        if not evidence.get("findings"):
            lines.append("   - none")
    if scan_run.get("source") == "metasploit":
        evidence = scan_run.get("metasploit_evidence") or {}
        metadata = scan_run.get("metadata") or {}
        lines.extend(
            [
                f"   Module: {evidence.get('module') or metadata.get('module') or 'unknown'}",
                f"   Action: {evidence.get('action_type') or metadata.get('action_type') or 'unknown'}",
                f"   Validation State: {evidence.get('validation_state') or 'unknown'}",
                f"   Evidence: {evidence.get('summary') or scan_run.get('summary') or 'none'}",
                f"   Provenance: proposal={metadata.get('proposal_id') or 'not supplied'} artifact={metadata.get('artifact_ref') or 'not supplied'}",
            ]
        )
    if scan_run.get("source") == "gitleaks":
        evidence = scan_run.get("gitleaks_evidence") or {}
        summary = scan_run.get("gitleaks_summary") or {}
        lines.extend(
            [
                f"   Gitleaks Findings: {int(summary.get('finding_count') or evidence.get('finding_count') or 0)}",
                f"   Affected Files: {int(summary.get('affected_files_count') or evidence.get('affected_files_count') or 0)}",
                "   Boundary: redacted secret-pattern detection only; validity, usability, ownership, access, compromise, exfiltration, and repository security are not established.",
                "   Gitleaks Redacted Findings:",
            ]
        )
        for finding in (evidence.get("findings") or [])[:20]:
            lines.append(
                f"   - rule={finding.get('rule_id') or 'unknown'} file={finding.get('file_path') or 'unknown'} "
                f"line={finding.get('line_number') or 'unknown'} fingerprint={finding.get('fingerprint') or finding.get('secret_hash') or 'not supplied'}"
            )
        if not evidence.get("findings"):
            lines.append("   - none; no matches were reported within the scanned scope/rules")

    return lines


def _filter_scan_runs(scan_runs: list[dict], target: str | None) -> list[dict]:
    target_key = normalize_target_key(target)
    if target_key is None:
        return scan_runs

    return [
        scan_run
        for scan_run in scan_runs
        if (scan_run.get("target_key") or normalize_target_key(scan_run.get("target"))) == target_key
    ]


def _infer_report_target(scan_runs: list[dict]) -> str | None:
    target_groups: dict[str, str] = {}
    for scan_run in scan_runs:
        target = scan_run.get("target")
        if not target:
            continue
        target_key = scan_run.get("target_key") or normalize_target_key(target) or str(target)
        target_groups.setdefault(target_key, _display_target(scan_run))
    unique_targets = sorted(target_groups.values())
    if len(unique_targets) == 1:
        return unique_targets[0]

    return "Multiple targets" if unique_targets else None


def _format_executive_summary(scan_runs: list[dict], target: str | None) -> list[str]:
    if not scan_runs:
        return ["No scan history is available for this user or target."]

    highest_risk = _highest_risk(scan_runs)
    total_findings = sum(_finding_count(scan_run) for scan_run in scan_runs)
    clean_scans = len([scan_run for scan_run in scan_runs if _is_clean_scan(scan_run)])
    return [
        (
            f"{target or 'The selected scope'} has {len(scan_runs)} recorded scan run(s), "
            f"{total_findings} finding(s), and an overall risk level of {highest_risk.upper()}."
        ),
        f"Clean scan results recorded: {clean_scans}.",
    ]


def _format_scan_sources(scan_runs: list[dict]) -> list[str]:
    if not scan_runs:
        return ["- None"]

    sources = sorted({_source_label(scan_run.get("source")) for scan_run in scan_runs})
    return [f"- {source} {_source_icon(source)}".rstrip() for source in sources]


def _format_risk_overview(scan_runs: list[dict]) -> list[str]:
    if not scan_runs:
        return ["No risk data available."]

    counts: dict[str, int] = {}
    for scan_run in scan_runs:
        risk_level = str(scan_run.get("risk_level") or "unknown").upper()
        counts[risk_level] = counts.get(risk_level, 0) + 1

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    lines = [f"- Highest Risk: {_highest_risk(scan_runs).upper()}"]
    lines.extend(f"- {risk}: {counts[risk]}" for risk in order if risk in counts)
    return lines


def _format_technical_findings(scan_runs: list[dict]) -> list[str]:
    finding_lines: list[str] = []
    nmap_runs = [scan_run for scan_run in scan_runs if scan_run.get("source") in {"nmap", "nmap_xml"} and not _is_clean_scan(scan_run)]
    finding_lines.extend(_format_deduplicated_nmap_findings(nmap_runs))

    for scan_run in scan_runs:
        if _is_clean_scan(scan_run):
            continue

        source = scan_run.get("source")
        if source in {"nmap", "nmap_xml"}:
            continue
        elif source == "nuclei":
            finding_lines.extend(_format_nuclei_findings(scan_run))
        elif source == "prowler":
            finding_lines.extend(_format_prowler_findings(scan_run))
        elif source == "metasploit":
            finding_lines.extend(_format_metasploit_findings(scan_run))
        elif source == "bbot":
            finding_lines.append(f"- BBOT reconnaissance observation for {scan_run.get('target') or 'unknown target'}.")
        elif source == "httpx":
            finding_lines.extend(_format_httpx_observations(scan_run))
        elif source == "katana":
            finding_lines.extend(_format_katana_observations(scan_run))
        elif source == "playwright":
            finding_lines.extend(_format_playwright_observations(scan_run))
        elif source == "ffuf":
            finding_lines.extend(_format_ffuf_observations(scan_run))
        elif source == "testssl":
            finding_lines.extend(_format_testssl_observations(scan_run))
        elif source == "gitleaks":
            finding_lines.extend(_format_gitleaks_observations(scan_run))
        elif source == "tshark":
            finding_lines.extend(_format_tshark_observations(scan_run))
        else:
            finding_lines.append(f"- {_source_label(source)} finding for {scan_run.get('target') or 'unknown target'}.")

    return finding_lines or ["No technical findings were recorded."]


def _format_deduplicated_nmap_findings(scan_runs: list[dict]) -> list[str]:
    if not scan_runs:
        return []

    latest_by_signature: dict[tuple[object, ...], dict] = {}
    duplicate_counts: dict[tuple[object, ...], int] = {}
    for scan_run in reversed(scan_runs):
        signature = _nmap_signature(scan_run)
        if signature in latest_by_signature:
            duplicate_counts[signature] = duplicate_counts.get(signature, 0) + 1
            continue
        latest_by_signature[signature] = scan_run

    lines: list[str] = []
    for signature, scan_run in reversed(list(latest_by_signature.items())):
        lines.extend(_format_nmap_findings(scan_run))
        if duplicate_counts.get(signature, 0):
            lines.append("  - Previous matching Nmap scan found; no port changes detected.")
    return lines


def _format_nmap_findings(scan_run: dict) -> list[str]:
    open_ports = scan_run.get("open_ports") or []
    if not open_ports:
        if str(scan_run.get("assessment_result") or "").lower() == "inconclusive":
            return [
                f"- Nmap did not establish an assessable target state for {scan_run.get('target') or 'unknown target'}.",
                "  - No conclusion about exposed ports or vulnerabilities can be drawn from that run.",
            ]
        return [f"- Nmap found no open ports on {scan_run.get('target') or 'unknown target'}."]

    lines = [f"- Nmap identified {len(open_ports)} open port(s) on {scan_run.get('target') or 'unknown target'}:"]
    lines.extend(f"  - {port.get('port')}/{port.get('protocol')} {port.get('service')}" for port in open_ports)
    return lines


def _format_nuclei_findings(scan_run: dict) -> list[str]:
    nuclei_findings = scan_run.get("nuclei_findings") or []
    if not nuclei_findings:
        return [f"- Nuclei recorded {scan_run.get('finding_count', 0)} finding(s)."]

    lines = [f"- Nuclei reported {len(nuclei_findings)} scanner finding(s) on {scan_run.get('target') or 'unknown target'}:"]
    for finding in nuclei_findings[:10]:
        name = finding.get("name") or finding.get("template_id") or "Unnamed finding"
        severity = str(finding.get("severity") or "info").upper()
        template = finding.get("template_id") or "unknown-template"
        lines.append(f"  - {name} (scanner severity: {severity}) - template={template}")
    if len(nuclei_findings) > 10:
        lines.append(f"  - ...and {len(nuclei_findings) - 10} more finding(s).")
    return lines


def _format_prowler_findings(scan_run: dict) -> list[str]:
    evidence = scan_run.get("prowler_evidence") or {}
    summary = scan_run.get("prowler_summary") or {}
    provider = str(scan_run.get("provider") or evidence.get("provider") or "unknown").upper()
    cloud_context = scan_run.get("cloud_context") or evidence.get("cloud_context") or scan_run.get("target") or "unknown"
    findings = evidence.get("findings") or []
    failed = [finding for finding in findings if str(finding.get("status") or "").upper() == "FAIL"]
    lines = [
        f"- Prowler cloud posture summary:",
        f"  - Provider: {provider}",
        f"  - Context: {cloud_context}",
        f"  - Total checks/findings parsed: {int(summary.get('finding_count') or evidence.get('finding_count') or len(findings))}",
        f"  - Failed checks: {int(summary.get('failed_count') or len(failed))}",
        f"  - Passed checks: {int(summary.get('passed_count') or 0)}",
        f"  - Highest scanner-reported severity: {summary.get('highest_severity') or 'none'}",
        "  - Top failed services: " + (", ".join(summary.get("top_failed_services") or []) or "none"),
        "  - Limitation: PASS results are specific check passes, not proof that the resource/account is secure, hardened, vulnerability-free, or compliant.",
        "  - Limitation: FAIL results are scanner-reported failed checks, not confirmed exploitability, compromise, attacker access, data exposure, or organization-wide non-compliance.",
        "  - Limitation: Prowler severity and compliance mappings are scanner metadata for specific checks, not proof of business impact or regulatory status.",
        "  - Failed-check evidence:",
    ]
    if not failed:
        lines.append("    - None recorded.")
        return lines
    for finding in failed[:10]:
        lines.append(
            f"    - {finding.get('status') or 'unknown'} {finding.get('check_id') or 'check'} "
            f"severity={finding.get('severity') or 'unknown'} service={finding.get('service') or 'unknown'} "
            f"region={finding.get('region') or 'unknown'} title={finding.get('check_title') or 'unknown'}"
        )
    if len(failed) > 10:
        lines.append(f"    - ...and {len(failed) - 10} more failed check(s).")
    return lines


def _format_metasploit_findings(scan_run: dict) -> list[str]:
    evidence = scan_run.get("metasploit_evidence") or {}
    metadata = scan_run.get("metadata") or {}
    lines = [
        "- Metasploit controlled validation summary:",
        f"  - Target: {_clean(evidence.get('target') or scan_run.get('target') or 'unknown')}",
        f"  - Module: {_clean(evidence.get('module') or metadata.get('module') or 'unknown')}",
        f"  - Action: {_clean(evidence.get('action_type') or metadata.get('action_type') or 'unknown')}",
        f"  - Validation State: {_clean(evidence.get('validation_state') or 'unknown')}",
        f"  - Subprocess Success: {_bool_label(evidence.get('subprocess_success'))}",
        f"  - Module Executed: {_bool_label(evidence.get('module_executed'))}",
        f"  - Session Established: {_bool_label(evidence.get('session_established'))}",
        f"  - Evidence: {_clean(evidence.get('summary') or scan_run.get('summary') or 'none')}",
        f"  - Proposal Reference: {_clean(metadata.get('proposal_id') or 'not supplied')}",
        f"  - Artifact Reference: {_clean(metadata.get('artifact_ref') or 'not supplied')}",
        "  - Limitation: Validation output is bounded to the approved module/action/options.",
        "  - Limitation: Subprocess success, target response, network evidence, or module compatibility alone is not exploit success.",
        "  - Limitation: Failed, blocked, or not reproduced validation does not mean the target is secure.",
        "  - Limitation: Session, persistence, privilege level, lateral movement, or data access is not inferred unless explicitly present in normalized evidence.",
    ]
    excerpt = _clean(evidence.get("raw_evidence_excerpt") or "")
    if excerpt:
        lines.append(f"  - Normalized evidence excerpt: {excerpt}")
    return lines


def _format_httpx_observations(scan_run: dict) -> list[str]:
    services = scan_run.get("httpx_services") or []
    if not services:
        return [
            f"- httpx recorded no usable structured response observations for {scan_run.get('target') or 'unknown target'}.",
            "  - No conclusion about host availability, web application existence, vulnerabilities, or security posture can be drawn from that result.",
        ]
    lines = [f"- httpx reported {len(services)} HTTP response/URL observation(s) on {scan_run.get('target') or 'unknown target'}:"]
    for service in services[:10]:
        detail = f"  - {_clean(service.get('url') or service.get('host') or 'unknown')} status={_clean(service.get('status_code') or 'unknown')}"
        if service.get("title"):
            detail = f"{detail} title={_clean(service.get('title'))}"
        if service.get("web_server"):
            detail = f"{detail} server={_clean(service.get('web_server'))}"
        if service.get("technologies"):
            detail = f"{detail} technologies={', '.join(_clean(value) for value in (service.get('technologies') or [])[:5])}"
        lines.append(detail)
    lines.append("  - Limitation: httpx fingerprinting metadata is not proof of vulnerability, compromise, application health, or full service availability.")
    return lines


def _format_katana_observations(scan_run: dict) -> list[str]:
    observations = scan_run.get("katana_observations") or []
    summary = scan_run.get("katana_summary") or {}
    if not observations:
        return [
            f"- Katana recorded no usable structured crawl observations for {scan_run.get('target') or 'unknown target'}.",
            "  - No conclusion about forms, endpoints, parameters, scripts, hidden content, vulnerabilities, or coverage can be drawn from that result.",
        ]

    target = scan_run.get("target") or "unknown target"
    lines = [f"- Katana recorded {len(observations)} URL/endpoint crawl observation(s) for {target}:"]
    lines.append(
        "  - crawl-summary: "
        f"hosts={int(summary.get('host_count') or 0)} "
        f"scripts={int(summary.get('javascript_count') or 0)} "
        f"parameters={int(summary.get('query_parameter_count') or 0)} "
        f"forms={int(summary.get('form_count') or 0)} "
        f"max_depth={int(summary.get('max_depth') or 0)}"
    )
    for observation in observations[:10]:
        detail = f"  - {_clean(observation.get('url') or 'unknown')} type={_clean(observation.get('endpoint_type') or 'url')}"
        if observation.get("status_code"):
            detail = f"{detail} status={_clean(observation.get('status_code'))}"
        if observation.get("depth") is not None:
            detail = f"{detail} depth={_clean(observation.get('depth'))}"
        if observation.get("query_parameters"):
            detail = f"{detail} params_observed={', '.join(_clean(value) for value in (observation.get('query_parameters') or [])[:5])}"
        if observation.get("forms"):
            detail = f"{detail} forms_observed={len(observation.get('forms') or [])}"
        lines.append(detail)
    lines.append("  - Limitation: Katana crawl observations do not prove vulnerability, exploitability, sensitive exposure, ownership, public availability at all times, or complete coverage.")
    return lines


def _format_playwright_observations(scan_run: dict) -> list[str]:
    observation = scan_run.get("playwright_observation") or {}
    if not observation:
        return [
            f"- Playwright recorded no usable structured browser-state observation for {scan_run.get('target') or 'unknown target'}.",
            "  - No conclusion about application behavior, vulnerabilities, authentication strength, or security posture can be drawn from that result.",
        ]

    target = scan_run.get("target") or observation.get("requested_url") or "unknown target"
    lines = [f"- Playwright recorded passive browser-state observation for {target}:"]
    detail = (
        f"  - final={_clean(observation.get('final_url') or 'unknown')} "
        f"status={_clean(observation.get('status_code') or 'not observed')} "
        f"load={_clean(observation.get('load_status') or 'unknown')} "
        f"title={_clean(observation.get('title') or 'not observed')}"
    )
    lines.append(detail)
    lines.append(
        "  - returned-state counts: "
        f"forms={int(observation.get('forms_count') or 0)} "
        f"inputs={int(observation.get('inputs_count') or 0)} "
        f"links={int(observation.get('links_count') or 0)}"
    )
    lines.append(
        "  - console/network/page issues: "
        f"{int(observation.get('console_issue_count') or 0)} console / "
        f"{int(observation.get('network_issue_count') or 0)} network / "
        f"{int(observation.get('page_error_count') or 0)} page errors"
    )
    status_code = observation.get("status_code")
    if status_code == 429 or str(status_code) == "429":
        lines.append("  - Limitation: HTTP 429 was observed as a rate-limited response; cause is unknown from Playwright evidence.")
    if status_code in {401, 403, 429} or str(status_code) in {"401", "403", "429"} or str(observation.get("load_status") or "").lower() in {"domcontentloaded", "timeout", "failed", "navigation_failed"}:
        lines.append("  - Limitation: Restricted or partial browser state limited visibility into the application.")
    lines.append("  - Limitation: Passive Playwright observation does not test XSS, SQL injection, CSRF, authentication flaws, vulnerability absence, or complete application behavior.")
    return lines


def _format_ffuf_observations(scan_run: dict) -> list[str]:
    results = scan_run.get("ffuf_results") or []
    summary = scan_run.get("ffuf_summary") or {}
    if not results:
        return [
            f"- ffuf recorded no usable structured fuzzing response observations for {scan_run.get('target') or 'unknown target'}.",
            "  - No conclusion about hidden content, endpoints, directories, files, parameters, virtual hosts, vulnerabilities, or coverage can be drawn from that result.",
        ]

    target = scan_run.get("target") or "unknown target"
    lines = [f"- ffuf recorded {len(results)} fuzzing response observation(s) for {target}:"]
    status_codes = summary.get("status_codes") or {}
    lines.append(
        "  - fuzz-summary: "
        f"statuses={_clean(', '.join(f'{code}:{count}' for code, count in sorted(status_codes.items())) or 'none')} "
        f"redirects={int(summary.get('redirect_count') or 0)} "
        f"forbidden={int(summary.get('forbidden_count') or 0)} "
        f"server_errors={int(summary.get('server_error_count') or 0)}"
    )
    for result in results[:10]:
        detail = f"  - {_clean(result.get('path') or result.get('url') or 'unknown')} status={_clean(result.get('status_code') or 'unknown')} classification={_clean(result.get('classification') or 'observed')}"
        if result.get("content_length") is not None:
            detail = f"{detail} length={_clean(result.get('content_length'))}"
        if result.get("input_word"):
            detail = f"{detail} word={_clean(result.get('input_word'))}"
        lines.append(detail)
    lines.append("  - Limitation: ffuf response observations do not prove vulnerability, exploitability, sensitive exposure, authentication bypass, or complete discovery coverage.")
    return lines


def _format_testssl_observations(scan_run: dict) -> list[str]:
    evidence = scan_run.get("testssl_evidence") or {}
    if not evidence:
        return [
            f"- testssl.sh recorded no usable structured TLS evidence for {scan_run.get('target') or 'unknown target'}.",
            "  - No conclusion about TLS security, vulnerabilities, ciphers, or configuration quality can be drawn from that result.",
        ]

    target = scan_run.get("target") or evidence.get("target") or "unknown target"
    protocols = evidence.get("protocols") or []
    items = _notable_testssl_items(evidence)
    lines = [f"- testssl.sh recorded TLS scanner evidence for {target}:"]
    lines.append(
        "  - Protocol observations: "
        + (", ".join(_clean(item.get("name") or item.get("id")) for item in protocols[:10]) if protocols else "none extracted")
    )
    if evidence.get("weak_protocols"):
        lines.append("  - Weak/deprecated observations: " + "; ".join(_clean(item) for item in (evidence.get("weak_protocols") or [])[:10]))
    lines.append(f"  - Notable scanner-reported TLS findings: {len(items)}")
    for item in items[:10]:
        lines.append(f"    - {_clean(item.get('id') or 'finding')} severity={_clean(item.get('severity') or 'info')} finding={_clean(item.get('finding') or '')}")
    lines.append("  - Limitation: testssl.sh evidence is TLS scanner output only; preserve scanner severity/uncertainty and validate potential findings in context.")
    return lines


def _format_gitleaks_observations(scan_run: dict) -> list[str]:
    evidence = scan_run.get("gitleaks_evidence") or {}
    summary = scan_run.get("gitleaks_summary") or {}
    findings = evidence.get("findings") or []
    target = scan_run.get("target") or evidence.get("scan_root") or "unknown target"
    finding_count = int(summary.get("finding_count") or evidence.get("finding_count") or len(findings))
    lines = [
        f"- Gitleaks reported {finding_count} redacted potential secret-pattern match(es) for {target}:",
        f"  - Affected files: {int(summary.get('affected_files_count') or evidence.get('affected_files_count') or 0)}",
        "  - Rules: " + _format_count_summary(summary.get("rule_summary") or evidence.get("rule_summary") or {}),
        "  - Providers: " + _format_count_summary(summary.get("provider_summary") or evidence.get("provider_summary") or {}),
        "  - Severity: " + _format_count_summary(summary.get("severity_summary") or evidence.get("severity_summary") or {}),
        "  - Limitation: Gitleaks evidence is redacted secret-pattern detection only; validity, current usability, ownership, unauthorized access, compromise, exfiltration, and repository security were not established.",
    ]
    if finding_count <= 0:
        lines.append("  - Limitation: no matches were reported within the scanned scope/rules; this does not prove no secrets exist.")
    for item in findings[:10]:
        detail = (
            f"    - rule={_clean(item.get('rule_id') or 'unknown')} file={_clean(item.get('file_path') or 'unknown')} "
            f"line={_clean(item.get('line_number') or 'unknown')} provider={_clean(item.get('provider') or 'unknown')} "
            f"secret={_clean(item.get('redacted_secret_preview') or '<REDACTED>')}"
        )
        if item.get("fingerprint") or item.get("secret_hash"):
            detail = f"{detail} fingerprint={_clean(item.get('fingerprint') or item.get('secret_hash'))}"
        if item.get("commit"):
            detail = f"{detail} commit={_clean(item.get('commit'))}"
        lines.append(detail)
    return lines


def _format_tshark_observations(scan_run: dict) -> list[str]:
    evidence = scan_run.get("tshark_evidence") or scan_run.get("normalized_evidence") or scan_run
    target = scan_run.get("target") or (evidence.get("source_file") or {}).get("name") or "unknown target"
    packet_count = int(evidence.get("packet_count") or 0)
    lines = [
        f"- TShark recorded packet metadata for {target}:",
        f"  - Packet count: {packet_count}",
        f"  - Byte count: {int(evidence.get('byte_count') or 0)}",
        "  - Protocols: " + (", ".join(f"{_clean(item.get('protocol'))}={int(item.get('packet_count') or 0)}" for item in (evidence.get("observed_protocols") or [])[:10]) or "none recorded"),
    ]
    if packet_count <= 0:
        lines.append("  - Limitation: no packet metadata was observed in this normalized evidence; this does not prove no traffic occurred.")
    conversations = evidence.get("observed_conversations") or []
    if conversations:
        lines.append("  - Conversations:")
        for item in conversations[:5]:
            lines.append(
                f"    - {_clean(item.get('src') or 'unknown')}:{_clean(item.get('src_port') or '')} -> "
                f"{_clean(item.get('dst') or 'unknown')}:{_clean(item.get('dst_port') or '')} "
                f"{_clean(item.get('transport') or 'unknown')} packets={int(item.get('packet_count') or 0)}"
            )
    dns = evidence.get("dns_observations") or []
    if dns:
        lines.append("  - DNS capture-window observations:")
        for item in dns[:5]:
            lines.append(f"    - query={_clean(item.get('query_name') or 'n/a')} capture_response={_clean(item.get('response_name') or item.get('response_address') or 'n/a')}")
    http = evidence.get("http_observations") or []
    if http:
        lines.append("  - HTTP metadata:")
        for item in http[:5]:
            lines.append(
                f"    - request={_clean(item.get('method') or 'not observed')} host={_clean(item.get('host') or 'n/a')} "
                f"uri={_clean(item.get('uri') or 'n/a')} response_status={_clean(item.get('response_code') or 'not observed')}"
            )
    tls = evidence.get("tls_observations") or []
    if tls:
        lines.append("  - TLS metadata:")
        for item in tls[:5]:
            lines.append(f"    - sni={_clean(item.get('sni') or 'n/a')} version={_clean(item.get('version') or 'n/a')} handshake_success=not established by stored metadata")
    lines.append("  - Limitation: packet activity, DNS, TCP, TLS, HTTP, and endpoints do not prove exploitation, compromise, ownership, authentication success, vulnerability, successful TLS handshakes, or completed HTTP transactions unless explicit normalized evidence supports that exact claim.")
    return lines


def _format_clean_scan_notes(scan_runs: list[dict]) -> list[str]:
    clean_scans = [scan_run for scan_run in scan_runs if _is_clean_scan(scan_run)]
    if not clean_scans:
        return ["No clean scan results were recorded."]

    return _format_deduplicated_clean_scan_notes(clean_scans)


def _format_recommendations(scan_runs: list[dict]) -> list[str]:
    if not scan_runs:
        return ["- Run authorized Nmap and Nuclei scans before generating a final report."]

    recommendations = [
        "- Prioritize remediation for high and medium risk findings.",
        "- Validate automated findings manually before making production changes.",
        "- Re-scan after remediation to confirm exposure has changed.",
    ]
    sources = {scan_run.get("source") for scan_run in scan_runs}
    if sources.intersection({"nmap", "nmap_xml"}):
        recommendations.append("- Review exposed services and restrict administrative ports to trusted networks.")
    if "nuclei" in sources:
        recommendations.append("- Manually validate matched Nuclei findings before remediation planning.")
    if "prowler" in sources:
        recommendations.append("- Review Prowler FAIL checks with the cloud owner and validate risk in the authorized cloud context without treating FAIL as exploitability, compromise, data exposure, or organization-wide non-compliance.")
    if "metasploit" in sources:
        recommendations.append("- Review Metasploit validation state, session evidence, and proposal/artifact provenance with the owner; do not treat failed validation as proof that the target is secure.")
    if "testssl" in sources:
        recommendations.append("- Review testssl.sh-reported TLS protocols, cipher observations, certificate metadata, and potential findings with the service owner.")
    if "gitleaks" in sources:
        recommendations.append("- Review Gitleaks potential secret matches with the owner; rotate or revoke only after confirmation, and avoid placing raw secret values in reports or prompts.")
    if "tshark" in sources:
        recommendations.append("- Review TShark packet metadata with capture scope, interface, duration, truncation, and protocol visibility limits before drawing network conclusions.")
    if any(_is_clean_scan(scan_run) for scan_run in scan_runs):
        recommendations.append("- Treat clean scans as point-in-time evidence, not proof that no vulnerabilities exist.")
    recommendations.extend(_format_finding_aware_recommendations(scan_runs))
    return recommendations


def _format_scan_history(scan_runs: list[dict]) -> list[str]:
    if not scan_runs:
        return ["No historical scan runs found."]

    lines = []
    grouped_runs: dict[str, list[dict]] = {}
    for scan_run in scan_runs:
        grouped_runs.setdefault(_source_label(scan_run.get("source")), []).append(scan_run)

    for source_label in sorted(grouped_runs):
        lines.append(section_label(_source_icon_key(source_label), f"{source_label} History"))
        for scan_run in grouped_runs[source_label]:
            lines.extend(
                [
                    _format_short_history_timestamp(scan_run.get("created_at")),
                    f"   - Target: {scan_run.get('target') or 'unknown'}",
                    f"   - Risk Level: {str(scan_run.get('risk_level') or 'unknown').upper()}",
                    f"   - Findings: {_finding_count(scan_run)}",
                    f"   - Status: {scan_run.get('status') or 'findings'}",
                ]
            )
        lines.append("")
    return lines


def _display_target(scan_run: dict) -> str:
    target = str(scan_run.get("target") or "unknown")
    target_key = scan_run.get("target_key") or normalize_target_key(target)
    if target_key and target_key != target and "(" in target and ")" in target:
        return str(target_key)

    return target


def _format_investigation_name(investigation_name: str | None) -> list[str]:
    if not investigation_name:
        return []

    return ["Investigation:", investigation_name, ""]


def _format_assessment_statistics(scan_runs: list[dict], generated_at: datetime) -> list[str]:
    risk_counts = _risk_counts(scan_runs)
    risk_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    lines = [
        f"- Tools Used: {', '.join(sorted({_source_label(scan_run.get('source')) for scan_run in scan_runs})) if scan_runs else 'None'}",
        f"- Scan Runs: {len(scan_runs)}",
        f"- Findings: {sum(_finding_count(scan_run) for scan_run in scan_runs)}",
        f"- Clean Scans: {len([scan_run for scan_run in scan_runs if _is_clean_scan(scan_run)])}",
        f"- Highest Risk: {_highest_risk(scan_runs).upper()}",
        "- Risk Counts: "
        + (", ".join(f"{risk}: {risk_counts[risk]}" for risk in risk_order if risk in risk_counts) or "None"),
        f"- Generated: {_format_human_timestamp(generated_at)}",
    ]
    return lines


def _format_human_timestamp(value: object) -> str:
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError:
            return value
    else:
        return "unknown"

    return timestamp.astimezone(UTC).strftime("%d %b %Y %H:%M UTC")


def _format_short_history_timestamp(value: object) -> str:
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError:
            return value
    else:
        return "unknown"

    return timestamp.astimezone(UTC).strftime("%d %b %H:%M")


def _format_deduplicated_clean_scan_notes(clean_scans: list[dict]) -> list[str]:
    lines: list[str] = []
    index = 0
    while index < len(clean_scans):
        current = clean_scans[index]
        group = [current]
        index += 1
        while index < len(clean_scans) and _clean_scan_signature(clean_scans[index]) == _clean_scan_signature(current):
            group.append(clean_scans[index])
            index += 1

        if len(group) > 1 and current.get("source") == "nuclei":
            lines.extend(
                [
                    f"{_number_word(len(group))} consecutive Nuclei scans completed with no matching findings.",
                    "",
                    "Latest:",
                    _format_human_timestamp(group[-1].get("created_at")),
                    "",
                    "Previous:",
                    _format_human_timestamp(group[-2].get("created_at")),
                ]
            )
        else:
            lines.append(
                f"- {_source_label(current.get('source'))} clean result for {current.get('target') or 'unknown target'}: "
                f"{_format_clean_scan_summary(current)}"
            )

        if index < len(clean_scans):
            lines.append("")

    return lines


def _clean_scan_signature(scan_run: dict) -> tuple[str, str, str]:
    return (
        str(scan_run.get("source") or ""),
        str(scan_run.get("target_key") or normalize_target_key(scan_run.get("target")) or scan_run.get("target") or ""),
        str(scan_run.get("summary") or ""),
    )


def _format_clean_scan_summary(scan_run: dict) -> str:
    summary = str(scan_run.get("summary") or "No matching findings were identified.")
    metadata = scan_run.get("metadata") or {}
    if (
        scan_run.get("source") == "nuclei"
        and "fast scan profile" in summary.lower()
        and not (metadata.get("scan_profile") or metadata.get("profile"))
    ):
        return "No matching Nuclei findings were observed using the selected template/profile."
    return summary


def _number_word(value: int) -> str:
    words = {2: "Two", 3: "Three", 4: "Four", 5: "Five"}
    return words.get(value, str(value))


def _clean(value: object) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()[:800]
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("<REDACTED>", text)
    return text


def _format_count_summary(counts: dict) -> str:
    return ", ".join(f"{_clean(key)}={int(value or 0)}" for key, value in sorted(counts.items())) if counts else "none"


def _bool_label(value: object) -> str:
    if value is True:
        return "True"
    if value is False:
        return "False"
    return "unknown"


def _format_finding_aware_recommendations(scan_runs: list[dict]) -> list[str]:
    recommendations = []
    ports = {
        str(open_port.get("port")): str(open_port.get("service") or "").lower()
        for scan_run in scan_runs
        for open_port in (scan_run.get("open_ports") or [])
    }
    services = set(ports.values())

    if "22" in ports or "ssh" in services:
        recommendations.append("- SSH: restrict access to trusted IPs or VPN, disable password login, and require key-based authentication.")
    if "445" in ports or "139" in ports or any("smb" in service or "microsoft-ds" in service for service in services):
        recommendations.append("- SMB: block internet exposure, disable SMBv1, and restrict share permissions.")
    if {"80", "443"}.intersection(ports) or any(service in {"http", "https"} for service in services):
        recommendations.append("- HTTP/HTTPS: review security headers, TLS configuration, and exposed admin panels.")
    if {"3306", "5432", "1433", "27017", "6379"}.intersection(ports):
        recommendations.append("- Databases: restrict network access, require authentication, and keep database services patched.")
    if any(_is_clean_scan(scan_run) for scan_run in scan_runs):
        recommendations.append("- Clean Nuclei: treat the result as point-in-time evidence that no selected templates matched, not proof that no vulnerabilities exist.")
    if any(scan_run.get("source") == "prowler" for scan_run in scan_runs):
        recommendations.append("- Prowler: treat PASS/FAIL as check-specific scanner results requiring cloud-context validation; do not infer broad account security or compliance status.")
    if any(scan_run.get("source") == "metasploit" for scan_run in scan_runs):
        recommendations.append("- Metasploit: preserve proposal/artifact provenance and manually validate scope before follow-up testing.")

    return recommendations


def _nmap_signature(scan_run: dict) -> tuple[object, ...]:
    target = scan_run.get("target_key") or normalize_target_key(scan_run.get("target")) or scan_run.get("target")
    ports = tuple(
        sorted(
            (
                str(open_port.get("port") or ""),
                str(open_port.get("protocol") or ""),
                str(open_port.get("service") or ""),
            )
            for open_port in (scan_run.get("open_ports") or [])
        )
    )
    return (target, ports)


def _risk_counts(scan_runs: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for scan_run in scan_runs:
        risk_level = str(scan_run.get("risk_level") or "unknown").upper()
        counts[risk_level] = counts.get(risk_level, 0) + 1
    return counts


def _highest_risk(scan_runs: list[dict]) -> str:
    order = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    highest = "unknown"
    for scan_run in scan_runs:
        risk_level = str(scan_run.get("risk_level") or "unknown").lower()
        if order.get(risk_level, 0) > order.get(highest, 0):
            highest = risk_level
    return highest


def _is_clean_scan(scan_run: dict) -> bool:
    return scan_run.get("status") == "clean" or _finding_count(scan_run) == 0 and scan_run.get("source") == "nuclei"


def _finding_count(scan_run: dict) -> int:
    if scan_run.get("finding_count") is not None:
        return int(scan_run.get("finding_count") or 0)
    if isinstance(scan_run.get("prowler_evidence"), dict):
        return int((scan_run.get("prowler_evidence") or {}).get("finding_count") or len((scan_run.get("prowler_evidence") or {}).get("findings") or []))
    if isinstance(scan_run.get("metasploit_evidence"), dict):
        return 1 if (scan_run.get("metasploit_evidence") or {}).get("validation_state") in {"VALIDATED", "SESSION_ESTABLISHED"} else 0
    if scan_run.get("source") == "tshark":
        evidence = scan_run.get("tshark_evidence") or scan_run.get("normalized_evidence") or scan_run
        return int(evidence.get("packet_count") or 0)
    if isinstance(scan_run.get("testssl_evidence"), dict):
        return len(_notable_testssl_items(scan_run.get("testssl_evidence") or {}))
    if isinstance(scan_run.get("gitleaks_evidence"), dict):
        evidence = scan_run.get("gitleaks_evidence") or {}
        return int(evidence.get("finding_count") or len(evidence.get("findings") or []))
    if isinstance(scan_run.get("nuclei_findings"), list):
        return len(scan_run.get("nuclei_findings") or [])
    if isinstance(scan_run.get("open_ports"), list):
        return len(scan_run.get("open_ports") or [])
    return 0


def _source_label(source: object) -> str:
    labels = {
        "nmap": "Nmap",
        "nmap_xml": "Nmap XML Upload",
        "nuclei": "Nuclei",
        "bbot": "BBOT",
        "prowler": "Prowler",
        "metasploit": "Metasploit",
        "testssl": "testssl.sh",
        "gitleaks": "Gitleaks",
        "tshark": "TShark",
    }
    return labels.get(str(source), str(source or "Unknown"))


def _source_icon(source_label: str) -> str:
    return icon(_source_icon_key(source_label))


def _source_icon_key(source_label: str) -> str:
    normalized = source_label.lower()
    if normalized.startswith("nmap"):
        return "nmap"
    if normalized.startswith("nuclei"):
        return "nuclei"
    if normalized.startswith("bbot"):
        return "bbot"
    if normalized.startswith("prowler"):
        return "observation"
    if normalized.startswith("metasploit"):
        return "observation"
    if normalized.startswith("testssl"):
        return "observation"
    return "observation"


def _notable_testssl_items(evidence: dict) -> list[dict]:
    items = (evidence.get("vulnerabilities") or []) + (evidence.get("notable_findings") or []) + (evidence.get("cipher_findings") or [])
    return [item for item in items if _is_notable_testssl_item(item)]


def _is_notable_testssl_item(item: dict) -> bool:
    severity = str(item.get("severity") or "").upper()
    finding = str(item.get("finding") or "").lower()
    if severity in {"HIGH", "CRITICAL", "MEDIUM", "LOW", "WARN", "WARNING"}:
        return True
    return not any(term in finding for term in ("not vulnerable", "not offered", "not supported", "no vulnerability"))
