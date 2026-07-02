from datetime import UTC, datetime


def generate_assessment_markdown_report(context: dict) -> str:
    assessment = context.get("assessment") or {}
    targets = context.get("targets") or []
    scans = context.get("scans") or []
    findings = context.get("findings") or []

    lines = [
        "# Assessment Report",
        "",
        f"Assessment Name: {_clean(assessment.get('name') or 'Untitled assessment')}",
        f"Status: {_clean(assessment.get('status') or 'unknown').title()}",
        f"Created: {_format_timestamp(assessment.get('created_at'))}",
        f"Last Updated: {_format_timestamp(assessment.get('updated_at'))}",
        "Primary Target(s):",
        *_format_targets(targets),
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        *_format_executive_summary(context),
        "",
        "---",
        "",
        "## Assessment Overview",
        "",
        *_format_assessment_overview(context),
        "",
        "---",
        "",
        "## Scan Summary",
        "",
        *_format_scan_summary(scans),
        "",
        "---",
        "",
        "## Observed Assets",
        "",
        *_format_observed_assets(targets, findings),
        "",
        "---",
        "",
        "## Key Findings",
        "",
        *_format_key_findings(scans),
        "",
        "---",
        "",
        "## Assessment History",
        "",
        *_format_assessment_history(scans),
        "",
        "---",
        "",
        "## Recommended Next Actions",
        "",
        *_format_recommended_next_actions(scans),
        "",
        "---",
        "",
        "## Evidence Limitations",
        "",
        "- Only completed and partial tools are represented in the scan summary.",
        "- Absence of findings is not evidence of security.",
        "- Additional assessment activities may be required.",
    ]
    return "\n".join(lines).strip()


def _format_targets(targets: list[dict]) -> list[str]:
    if not targets:
        return ["- Not set"]
    return [f"- {_clean(target.get('address') or 'unknown')}" for target in targets]


def _format_executive_summary(context: dict) -> list[str]:
    targets = context.get("targets") or []
    scans = context.get("scans") or []
    represented_scans = _represented_scans(scans)
    highest_risk = _highest_risk(represented_scans)
    target_text = ", ".join(_clean(target.get("address") or "unknown") for target in targets) or "the configured scope"

    if not represented_scans:
        return [
            f"No completed or partial assessment scans are recorded for {target_text}.",
            "The assessment report is limited until scan evidence is collected.",
        ]

    return [
        (
            f"{target_text} has {len(represented_scans)} completed or partial assessment scan(s) "
            f"with highest recorded risk of {highest_risk.upper()}."
        ),
        "This report is based only on stored assessment evidence.",
    ]


def _format_assessment_overview(context: dict) -> list[str]:
    targets = context.get("targets") or []
    scans = context.get("scans") or []
    represented_scans = _represented_scans(scans)
    tools = ", ".join(sorted({str(scan.get("tool") or "unknown").upper() for scan in represented_scans})) or "None completed or partial"
    status = _clean((context.get("assessment") or {}).get("status") or "unknown").title()
    return [
        f"- Scope: {', '.join(_clean(target.get('address') or 'unknown') for target in targets) or 'No primary target configured.'}",
        f"- Completed activities: {tools}",
        f"- Current assessment status: {status}",
    ]


def _format_scan_summary(scans: list[dict]) -> list[str]:
    completed = _represented_scans(scans)
    if not completed:
        return ["No completed or partial scans are recorded yet."]

    lines: list[str] = []
    for tool in ("nmap", "bbot", "nuclei", "httpx"):
        tool_scans = [scan for scan in completed if str(scan.get("tool") or "").lower() == tool]
        if not tool_scans:
            continue
        latest = tool_scans[-1]
        finding = latest.get("finding") or {}
        lines.extend(
            [
                f"### {_tool_label(tool)}",
                "",
                "Scan status",
                str(latest.get("status") or "unknown").title(),
                "",
                "Summary",
                _scan_summary(latest),
                "",
                "Risk",
                _scan_risk(latest),
                "",
                "Key observations",
                *_scan_observations(latest, finding),
                "",
            ]
        )
    return _strip_trailing_blank(lines)


def _format_observed_assets(targets: list[dict], findings: list[dict]) -> list[str]:
    assets = _collect_assets(targets, findings)
    lines: list[str] = []
    for title, values in [
        ("Domains", assets["domains"]),
        ("Hosts", assets["hosts"]),
        ("Services", assets["services"]),
        ("Technologies", assets["technologies"]),
        ("URLs", assets["urls"]),
        ("Other observed assets", assets["other"]),
    ]:
        lines.append(f"{title}")
        lines.extend(_format_values(values))
        lines.append("")
    return _strip_trailing_blank(lines)


def _format_key_findings(scans: list[dict]) -> list[str]:
    completed = _represented_scans(scans)
    if not completed:
        return ["No key findings are available because no completed or partial scans are recorded."]

    lines: list[str] = []
    for scan in completed:
        finding = scan.get("finding") or {}
        tool = _tool_label(scan.get("tool"))
        open_ports = finding.get("open_ports") or []
        nuclei_findings = finding.get("nuclei_findings") or []
        observation_counts = finding.get("observation_counts") or {}
        httpx_services = finding.get("httpx_services") or {}

        if open_ports:
            lines.append(f"- {tool}: {len(open_ports)} open service(s) observed.")
        elif nuclei_findings:
            lines.append(f"- {tool}: {len(nuclei_findings)} matched finding(s) observed.")
        elif httpx_services:
            lines.append(f"- {tool}: {len(httpx_services)} HTTP service/URL observation(s) recorded.")
        elif observation_counts:
            total = sum(int(value or 0) for value in observation_counts.values())
            lines.append(f"- {tool}: {total} reconnaissance observation(s) recorded.")
        elif str(scan.get("tool") or "").lower() == "nuclei":
            lines.append("- Nuclei: no matching findings were observed with the selected template/profile.")
    return lines or ["No evidence-backed key findings were recorded."]


def _format_assessment_history(scans: list[dict]) -> list[str]:
    completed = _represented_scans(scans)
    if not completed:
        return ["No completed or partial scans are recorded yet."]
    return [
        (
            f"- {_format_timestamp(scan.get('completed_at') or scan.get('created_at'))}: "
            f"{_tool_label(scan.get('tool'))} {str(scan.get('status') or 'unknown').title()}"
            f"{_risk_suffix(scan)}"
        )
        for scan in completed
    ]


def _format_recommended_next_actions(scans: list[dict]) -> list[str]:
    completed = _represented_scans(scans)
    if not completed:
        return [
            "- Run authorized Nmap, BBOT, and Nuclei scans for the assessment scope.",
            "- Add notes or artifacts that define scope and testing constraints.",
        ]

    actions = []
    findings = [scan.get("finding") or {} for scan in completed]
    open_ports = [port for finding in findings for port in (finding.get("open_ports") or [])]
    services = {str(port.get("service") or "").lower() for port in open_ports}
    nuclei_findings = [item for finding in findings for item in (finding.get("nuclei_findings") or [])]
    observation_counts = [finding.get("observation_counts") or {} for finding in findings]
    httpx_services = [service for finding in findings for service in (finding.get("httpx_services") or [])]

    if open_ports:
        actions.append("- Validate externally exposed services and confirm each service is authorized.")
    if {"http", "https"}.intersection(services):
        actions.append("- Enumerate identified web applications and review security headers, TLS, and exposed admin paths.")
    if "ssh" in services or any(str(port.get("port")) == "22" for port in open_ports):
        actions.append("- Review SSH exposure, authentication policy, and network access restrictions.")
    if nuclei_findings:
        actions.append("- Manually validate matched Nuclei findings before remediation planning.")
    if any(counts.get("subdomain") or counts.get("url") for counts in observation_counts):
        actions.append("- Review discovered domains and URLs for unexpected internet-facing exposure.")
    if any(counts.get("technology") for counts in observation_counts):
        actions.append("- Review detected technologies and versions against current advisories.")
    if httpx_services:
        actions.append("- Validate observed HTTP services, redirects, page titles, and technology fingerprints against intended exposure.")

    return actions or ["- Continue assessment with additional authorized scans and manual validation."]


def _represented_scans(scans: list[dict]) -> list[dict]:
    return [scan for scan in scans if str(scan.get("status") or "").lower() in {"completed", "partial"}]


def _scan_summary(scan: dict) -> str:
    finding = scan.get("finding") or {}
    summary = finding.get("summary")
    if summary:
        return _clean(summary)

    tool = str(scan.get("tool") or "").lower()
    if tool == "nuclei":
        return "No matching Nuclei findings were observed with the selected template/profile."
    if tool == "bbot":
        counts = finding.get("observation_counts") or {}
        total = sum(int(value or 0) for value in counts.values())
        return f"{total} reconnaissance observation(s) recorded." if counts else "Reconnaissance completed."
    if tool == "nmap":
        open_ports = finding.get("open_ports") or []
        return f"{len(open_ports)} open service(s) observed." if open_ports else "No open TCP services were observed by this scan."
    if tool == "httpx":
        services = finding.get("httpx_services") or []
        return f"{len(services)} HTTP service/URL observation(s) recorded." if services else "httpx completed with no structured HTTP observations."
    return "Completed scan evidence recorded."


def _scan_risk(scan: dict) -> str:
    return _clean(scan.get("risk") or (scan.get("finding") or {}).get("risk_level") or "unknown").upper()


def _scan_observations(scan: dict, finding: dict) -> list[str]:
    open_ports = finding.get("open_ports") or []
    if open_ports:
        return [f"- {_clean(port.get('port'))}/{_clean(port.get('protocol') or 'tcp')} {_clean(port.get('service') or 'unknown')}" for port in open_ports[:10]]

    nuclei_findings = finding.get("nuclei_findings") or []
    if nuclei_findings:
        return [
            f"- {_clean(item.get('name') or item.get('template_id') or 'Matched finding')} ({_clean(item.get('severity') or 'info').upper()})"
            for item in nuclei_findings[:10]
        ]

    counts = finding.get("observation_counts") or {}
    if counts:
        return [f"- {_count_label(key)}: {int(value or 0)}" for key, value in sorted(counts.items()) if int(value or 0) > 0]

    httpx_services = finding.get("httpx_services") or []
    if httpx_services:
        lines = []
        for service in httpx_services[:10]:
            detail = f"- {_clean(service.get('url') or service.get('host') or 'unknown')} status={_clean(service.get('status_code') or 'unknown')}"
            if service.get("title"):
                detail = f"{detail} title={_clean(service.get('title'))}"
            if service.get("web_server"):
                detail = f"{detail} server={_clean(service.get('web_server'))}"
            if service.get("technologies"):
                detail = f"{detail} technologies={', '.join(_clean(value) for value in service.get('technologies')[:5])}"
            if service.get("redirect_location") or service.get("final_url"):
                detail = f"{detail} redirect={_clean(service.get('redirect_location') or service.get('final_url'))}"
            lines.append(detail)
        return lines

    if str(scan.get("tool") or "").lower() == "nuclei":
        return ["- No matching findings were observed with the selected template/profile."]
    return ["- No additional structured observations are linked to this scan."]


def _collect_assets(targets: list[dict], findings: list[dict]) -> dict[str, list[str]]:
    assets = {"domains": [], "hosts": [], "services": [], "technologies": [], "urls": [], "other": []}
    for target in targets:
        address = _clean(target.get("address") or "")
        if not address:
            continue
        if _looks_like_url(address):
            assets["urls"].append(address)
        elif _looks_like_ip(address):
            assets["hosts"].append(address)
        else:
            assets["domains"].append(address)

    for finding in findings:
        target = _clean(finding.get("target") or "")
        if target and _looks_like_ip(target):
            assets["hosts"].append(target)
        elif target and _looks_like_url(target):
            assets["urls"].append(target)
        elif target:
            assets["domains"].append(target)

        for port in finding.get("open_ports") or []:
            service = _clean(port.get("service") or "")
            if service:
                assets["services"].append(f"{_clean(port.get('port'))}/{_clean(port.get('protocol') or 'tcp')} {service}")

        for item in finding.get("nuclei_findings") or []:
            for key in ("matched_at", "host", "url"):
                value = _clean(item.get(key) or "")
                if value:
                    assets["urls" if _looks_like_url(value) else "hosts"].append(value)
            for technology in _as_list(item.get("technology")) + _as_list(item.get("technologies")):
                assets["technologies"].append(_clean(technology))

        for service in finding.get("httpx_services") or []:
            value = _clean(service.get("url") or service.get("host") or "")
            if value:
                assets["urls" if _looks_like_url(value) else "hosts"].append(value)
            if service.get("web_server"):
                assets["services"].append(_clean(service.get("web_server")))
            status_code = service.get("status_code")
            if status_code is not None:
                assets["services"].append(f"HTTP {status_code}")
            for technology in service.get("technologies") or []:
                assets["technologies"].append(_clean(technology))

        counts = finding.get("observation_counts") or {}
        for key, value in sorted(counts.items()):
            if int(value or 0) > 0:
                assets["other"].append(f"{_count_label(key)}: {int(value or 0)}")

    return {key: _unique(values) for key, values in assets.items()}


def _format_values(values: list[str]) -> list[str]:
    return [f"- {value}" for value in values[:20]] if values else ["- None recorded"]


def _highest_risk(scans: list[dict]) -> str:
    order = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    highest = "unknown"
    for scan in scans:
        risk = str(scan.get("risk") or (scan.get("finding") or {}).get("risk_level") or "unknown").lower()
        if order.get(risk, 0) > order.get(highest, 0):
            highest = risk
    return highest


def _risk_suffix(scan: dict) -> str:
    risk = scan.get("risk") or (scan.get("finding") or {}).get("risk_level")
    return f" - Risk: {str(risk).upper()}" if risk else ""


def _tool_label(tool: object) -> str:
    labels = {"nmap": "Nmap", "bbot": "BBOT", "nuclei": "Nuclei", "httpx": "httpx"}
    return labels.get(str(tool or "").lower(), _clean(tool or "Unknown"))


def _count_label(key: object) -> str:
    labels = {
        "subdomain": "Subdomains",
        "url": "URLs",
        "ip_address": "IP addresses",
        "dns_record": "DNS records",
        "technology": "Technologies",
        "certificate": "Certificates",
        "email": "Email addresses",
        "raw_event": "Raw events",
    }
    return labels.get(str(key), str(key).replace("_", " ").title())


def _format_timestamp(value: object) -> str:
    if isinstance(value, datetime):
        return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value).astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            return value
    return "Not available"


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:700]


def _unique(values: list[str]) -> list[str]:
    seen = set()
    unique_values = []
    for value in values:
        cleaned = _clean(value)
        key = cleaned.lower()
        if cleaned and key not in seen:
            seen.add(key)
            unique_values.append(cleaned)
    return unique_values


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _looks_like_url(value: str) -> bool:
    return value.lower().startswith(("http://", "https://"))


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _strip_trailing_blank(lines: list[str]) -> list[str]:
    while lines and lines[-1] == "":
        lines.pop()
    return lines
