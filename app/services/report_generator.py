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
        "- Whether the target appears clean, low risk, medium risk, high risk, or critical based on available evidence",
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
        assessment = ask_ai(prompt)
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
        return [f"- Nmap found no open ports on {scan_run.get('target') or 'unknown target'}."]

    lines = [f"- Nmap identified {len(open_ports)} open port(s) on {scan_run.get('target') or 'unknown target'}:"]
    lines.extend(f"  - {port.get('port')}/{port.get('protocol')} {port.get('service')}" for port in open_ports)
    return lines


def _format_nuclei_findings(scan_run: dict) -> list[str]:
    nuclei_findings = scan_run.get("nuclei_findings") or []
    if not nuclei_findings:
        return [f"- Nuclei recorded {scan_run.get('finding_count', 0)} finding(s)."]

    lines = [f"- Nuclei identified {len(nuclei_findings)} finding(s) on {scan_run.get('target') or 'unknown target'}:"]
    for finding in nuclei_findings[:10]:
        name = finding.get("name") or finding.get("template_id") or "Unnamed finding"
        severity = str(finding.get("severity") or "info").upper()
        template = finding.get("template_id") or "unknown-template"
        lines.append(f"  - {name} ({severity}) - {template}")
    if len(nuclei_findings) > 10:
        lines.append(f"  - ...and {len(nuclei_findings) - 10} more finding(s).")
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
        recommendations.append("- Patch or reconfigure affected services identified by Nuclei.")
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
                    f"{_number_word(len(group))} consecutive Nuclei Fast Scans completed with no findings.",
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
                f"{current.get('summary') or 'No matching findings were identified.'}"
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


def _number_word(value: int) -> str:
    words = {2: "Two", 3: "Three", 4: "Four", 5: "Five"}
    return words.get(value, str(value))


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
        recommendations.append("- Clean Nuclei: treat the result as point-in-time evidence, not proof that no issues exist.")

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
    return "observation"
