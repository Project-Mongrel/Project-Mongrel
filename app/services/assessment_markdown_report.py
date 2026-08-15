import json
from datetime import UTC, datetime


def generate_assessment_markdown_report(context: dict) -> str:
    assessment = context.get("assessment") or {}
    targets = context.get("targets") or []
    scans = context.get("scans") or []
    artifacts = context.get("artifacts") or []
    scans = _attach_tshark_artifacts(scans, artifacts)
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
    for tool in ("nmap", "bbot", "nuclei", "httpx", "katana", "playwright", "ffuf", "testssl", "gitleaks", "prowler", "metasploit", "tshark"):
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
        katana_observations = finding.get("katana_observations") or {}
        playwright_observation = finding.get("playwright_observation") or {}
        ffuf_results = finding.get("ffuf_results") or {}
        testssl_evidence = finding.get("testssl_evidence") or {}
        gitleaks_evidence = finding.get("gitleaks_evidence") or {}
        prowler_evidence = finding.get("prowler_evidence") or {}
        metasploit_evidence = finding.get("metasploit_evidence") or {}
        tshark_evidence = scan.get("tshark_evidence") or finding.get("tshark_evidence") or {}

        if open_ports:
            lines.append(f"- {tool}: {len(open_ports)} open service(s) observed.")
        elif nuclei_findings:
            lines.append(f"- {tool}: {len(nuclei_findings)} matched finding(s) observed.")
        elif httpx_services:
            lines.append(f"- {tool}: {len(httpx_services)} HTTP response/URL observation(s) recorded.")
        elif katana_observations:
            lines.append(f"- {tool}: {len(katana_observations)} crawled URL/endpoint observation(s) recorded.")
        elif playwright_observation:
            lines.append(f"- {tool}: passive browser observation recorded for {playwright_observation.get('final_url') or playwright_observation.get('requested_url') or 'target'}.")
        elif ffuf_results:
            lines.append(f"- {tool}: {len(ffuf_results)} hidden-content path observation(s) recorded.")
        elif testssl_evidence:
            notable = _notable_testssl_items(testssl_evidence)
            lines.append(f"- {tool}: TLS configuration evidence recorded with {len(notable)} notable finding(s).")
        elif gitleaks_evidence:
            lines.append(f"- {tool}: {int(gitleaks_evidence.get('finding_count') or 0)} redacted secret-exposure finding(s) recorded.")
        elif prowler_evidence:
            lines.append(f"- {tool}: {int(prowler_evidence.get('finding_count') or 0)} scanner-reported cloud posture check(s) recorded.")
        elif metasploit_evidence:
            lines.append(f"- {tool}: validation state {metasploit_evidence.get('validation_state') or 'unknown'} recorded.")
        elif tshark_evidence:
            lines.append(f"- {tool}: {int(tshark_evidence.get('packet_count') or 0)} packet metadata observation(s) recorded.")
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
            "- Run authorized Nmap, BBOT, Nuclei, httpx, Katana, Playwright, ffuf, testssl.sh, and Gitleaks scans for the assessment scope.",
            "- Add notes or artifacts that define scope and testing constraints.",
        ]

    actions = []
    findings = [scan.get("finding") or {} for scan in completed]
    open_ports = [port for finding in findings for port in (finding.get("open_ports") or [])]
    services = {str(port.get("service") or "").lower() for port in open_ports}
    nuclei_findings = [item for finding in findings for item in (finding.get("nuclei_findings") or [])]
    observation_counts = [finding.get("observation_counts") or {} for finding in findings]
    httpx_services = [service for finding in findings for service in (finding.get("httpx_services") or [])]
    katana_observations = [observation for finding in findings for observation in (finding.get("katana_observations") or [])]
    playwright_observations = [finding.get("playwright_observation") for finding in findings if finding.get("playwright_observation")]
    ffuf_results = [result for finding in findings for result in (finding.get("ffuf_results") or [])]
    testssl_evidence = [finding.get("testssl_evidence") for finding in findings if finding.get("testssl_evidence")]
    gitleaks_evidence = [finding.get("gitleaks_evidence") for finding in findings if finding.get("gitleaks_evidence")]
    prowler_evidence = [finding.get("prowler_evidence") for finding in findings if finding.get("prowler_evidence")]
    tshark_evidence = [scan.get("tshark_evidence") for scan in completed if scan.get("tshark_evidence")]

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
        actions.append("- Validate observed HTTP responses, redirects, page titles, headers, and technology fingerprints against intended exposure.")
    if katana_observations:
        actions.append("- Review Katana-observed URLs, JavaScript files, forms, and query parameters to prioritize manual validation.")
    if playwright_observations:
        actions.append("- Review returned browser-state forms, links, console issues, and network failures before deeper manual testing.")
    if ffuf_results:
        actions.append("- Review ffuf-observed response paths and status codes as follow-up candidates before manual validation.")
    if testssl_evidence:
        actions.append("- Review TLS protocols, certificate expiry, cipher observations, and testssl.sh-reported misconfigurations with the service owner.")
    if gitleaks_evidence:
        actions.append("- Rotate or revoke detected secrets, remove them from repositories/artifacts, and review commit history for exposure.")
    if prowler_evidence:
        actions.append("- Review Prowler FAIL checks with the cloud owner and validate risk in the authorized cloud context.")
    metasploit_evidence = [finding.get("metasploit_evidence") for finding in findings if finding.get("metasploit_evidence")]
    if metasploit_evidence:
        actions.append("- Review Metasploit validation evidence and preserve proposal/artifact provenance before follow-up testing.")
    if tshark_evidence:
        actions.append("- Review TShark PCAP metadata for unexpected endpoints, DNS names, HTTP hosts, and TLS SNI values without treating packet activity as proof of compromise.")

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
        return f"{len(services)} HTTP response/URL observation(s) recorded." if services else "httpx completed with no usable structured HTTP response observations."
    if tool == "katana":
        observations = finding.get("katana_observations") or []
        return f"{len(observations)} crawled URL/endpoint observation(s) recorded." if observations else "Katana completed with no structured crawl observations."
    if tool == "playwright":
        observation = finding.get("playwright_observation") or {}
        return "Passive browser observation recorded." if observation else "Playwright completed with no structured browser observation."
    if tool == "ffuf":
        results = finding.get("ffuf_results") or []
        return f"{len(results)} hidden-content path observation(s) recorded." if results else "ffuf completed with no structured hidden-content observations."
    if tool == "testssl":
        evidence = finding.get("testssl_evidence") or {}
        return "TLS configuration evidence recorded." if evidence else "testssl.sh completed with no structured TLS evidence."
    if tool == "gitleaks":
        evidence = finding.get("gitleaks_evidence") or {}
        return f"{int(evidence.get('finding_count') or 0)} redacted secret-exposure finding(s) recorded." if evidence else "Gitleaks completed with no structured secret findings."
    if tool == "prowler":
        evidence = finding.get("prowler_evidence") or {}
        return f"{int(evidence.get('finding_count') or 0)} scanner-reported cloud posture check(s) recorded." if evidence else "Prowler completed with no structured cloud posture evidence."
    if tool == "metasploit":
        evidence = finding.get("metasploit_evidence") or {}
        return f"Metasploit validation state {evidence.get('validation_state') or 'unknown'} recorded." if evidence else "Metasploit completed with no structured validation evidence."
    if tool == "tshark":
        evidence = scan.get("tshark_evidence") or finding.get("tshark_evidence") or {}
        return f"TShark normalized {int(evidence.get('packet_count') or 0)} packet metadata observation(s)." if evidence else "TShark completed with no normalized PCAP evidence."
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
        lines = [
            "- Limitation: httpx response metadata is not proof of vulnerability, compromise, application health, or full service availability."
        ]
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

    katana_observations = finding.get("katana_observations") or []
    if katana_observations:
        summary = finding.get("katana_summary") or {}
        lines = [
            f"- URLs/endpoints observed during crawl: {len(katana_observations)}",
            f"- Unique hosts: {int(summary.get('host_count') or len(_unique([_clean(item.get('host') or '') for item in katana_observations])))}",
            f"- JavaScript files observed during crawl: {int(summary.get('javascript_count') or len([item for item in katana_observations if item.get('endpoint_type') == 'javascript']))}",
            f"- Query parameters observed during crawl: {int(summary.get('query_parameter_count') or len(_unique([_clean(parameter) for item in katana_observations for parameter in (item.get('query_parameters') or [])])))}",
            f"- Forms/actions observed during crawl: {int(summary.get('form_count') or sum(len(item.get('forms') or []) for item in katana_observations))}",
            f"- Max observed crawl depth: {int(summary.get('max_depth') or max([int(item.get('depth') or 0) for item in katana_observations] or [0]))}",
            "- Limitation: Katana crawl observations do not prove vulnerability, exploitability, sensitive exposure, ownership, public availability at all times, or complete coverage.",
        ]
        for observation in katana_observations[:10]:
            detail = f"- {_clean(observation.get('url') or 'unknown')} type={_clean(observation.get('endpoint_type') or 'url')}"
            if observation.get("method"):
                detail = f"{detail} method={_clean(observation.get('method'))}"
            if observation.get("status_code"):
                detail = f"{detail} status={_clean(observation.get('status_code'))}"
            if observation.get("depth") is not None:
                detail = f"{detail} depth={_clean(observation.get('depth'))}"
            if observation.get("query_parameters"):
                detail = f"{detail} params={', '.join(_clean(value) for value in observation.get('query_parameters')[:5])}"
            if observation.get("forms"):
                detail = f"{detail} forms={len(observation.get('forms') or [])}"
            lines.append(detail)
        return lines

    playwright_observation = finding.get("playwright_observation") or {}
    if playwright_observation:
        lines = [
            f"- Requested URL: {_clean(playwright_observation.get('requested_url') or 'unknown')}",
            f"- Final URL: {_clean(playwright_observation.get('final_url') or 'unknown')}",
            f"- Title: {_clean(playwright_observation.get('title') or 'not observed')}",
            f"- Load status: {_clean(playwright_observation.get('load_status') or 'unknown')}",
            f"- Status code: {_clean(playwright_observation.get('status_code') or 'not observed')}",
            f"- Forms/inputs observed in returned state: {int(playwright_observation.get('forms_count') or 0)} forms / {int(playwright_observation.get('inputs_count') or 0)} inputs",
            f"- Links observed in returned state: {int(playwright_observation.get('links_count') or 0)}",
            (
                f"- Console/network summary: {int(playwright_observation.get('console_issue_count') or 0)} console / "
                f"{int(playwright_observation.get('network_issue_count') or 0)} network / "
                f"{int(playwright_observation.get('page_error_count') or 0)} page errors"
            ),
            f"- Screenshot/artifact metadata: {'present' if playwright_observation.get('screenshot') else 'not captured'}",
            "- Limitation: Passive Playwright observation does not test XSS, SQL injection, CSRF, authentication flaws, vulnerability absence, or complete application behavior.",
        ]
        status_code = playwright_observation.get("status_code")
        if status_code == 429 or str(status_code) == "429":
            lines.append("- Limitation: HTTP 429 was observed as a rate-limited response; cause is unknown from Playwright evidence.")
        if status_code in {401, 403, 429} or str(status_code) in {"401", "403", "429"} or str(playwright_observation.get("load_status") or "").lower() in {"domcontentloaded", "timeout", "failed", "navigation_failed"}:
            lines.append("- Limitation: Restricted or partial browser state limited visibility into the application.")
        for limitation in playwright_observation.get("limitations") or []:
            lines.append(f"- Limitation: {_clean(limitation)}")
        return lines

    ffuf_results = finding.get("ffuf_results") or []
    if ffuf_results:
        summary = finding.get("ffuf_summary") or {}
        status_codes = summary.get("status_codes") or {}
        lines = [
            f"- Target/base URL: {_clean(finding.get('target') or 'unknown')}",
            f"- ffuf response observations: {len(ffuf_results)}",
            "- Status codes: " + (", ".join(f"{_clean(code)}={int(count or 0)}" for code, count in sorted(status_codes.items())) if status_codes else "none"),
            f"- Redirects: {int(summary.get('redirect_count') or 0)}",
            f"- Forbidden/auth-gated responses: {int(summary.get('forbidden_count') or 0)}",
            f"- Server-error responses: {int(summary.get('server_error_count') or 0)}",
            "- Limitation: Conservative bounded wordlist discovery only. ffuf response observations are not confirmed vulnerabilities, exploitability, sensitive exposure, authentication bypass, or complete discovery coverage.",
        ]
        for result in ffuf_results[:10]:
            detail = f"- {_clean(result.get('url') or result.get('path') or 'unknown')} status={_clean(result.get('status_code') or 'unknown')}"
            if result.get("content_length") is not None:
                detail = f"{detail} length={_clean(result.get('content_length'))}"
            if result.get("words") is not None:
                detail = f"{detail} words={_clean(result.get('words'))}"
            if result.get("lines") is not None:
                detail = f"{detail} lines={_clean(result.get('lines'))}"
            if result.get("classification"):
                detail = f"{detail} classification={_clean(result.get('classification'))}"
            if result.get("redirect_location"):
                detail = f"{detail} redirect={_clean(result.get('redirect_location'))}"
            lines.append(detail)
        return lines

    testssl_evidence = finding.get("testssl_evidence") or {}
    if testssl_evidence:
        cert = testssl_evidence.get("certificate") or {}
        protocols = testssl_evidence.get("protocols") or []
        notable = _notable_testssl_items(testssl_evidence)
        lines = [
            f"- Status: {_clean(testssl_evidence.get('scan_status') or 'completed').title()}",
            f"- Certificate subject/CN: {_clean(cert.get('subject') or cert.get('common_name') or 'not extracted')}",
            f"- Certificate issuer: {_clean(cert.get('issuer') or 'not extracted')}",
            f"- Certificate expiry: {_clean(cert.get('not_after') or (testssl_evidence.get('expiry') or {}).get('not_after') or 'not extracted')}",
            "- Protocols: " + (", ".join(_clean(item.get("name") or item.get("id")) for item in protocols[:10]) if protocols else "none extracted"),
            "- Weak/deprecated items: " + ("; ".join(_clean(item) for item in (testssl_evidence.get("weak_protocols") or [])[:10]) if testssl_evidence.get("weak_protocols") else "none recorded"),
            f"- Notable TLS findings: {len(notable)}",
            "- Limitation: TLS configuration evidence only; this does not establish overall site security.",
        ]
        for item in notable[:10]:
            lines.append(f"- {_clean(item.get('id') or 'finding')} severity={_clean(item.get('severity') or 'info')} finding={_clean(item.get('finding') or '')}")
        headers = testssl_evidence.get("security_headers") or []
        if headers:
            lines.append("- Security header evidence: " + "; ".join(_clean(item.get("id") or item.get("finding")) for item in headers[:8]))
        return lines

    gitleaks_evidence = finding.get("gitleaks_evidence") or {}
    if gitleaks_evidence:
        summary = finding.get("gitleaks_summary") or {}
        lines = [
            f"- Scope: {_clean(gitleaks_evidence.get('scan_root') or finding.get('target') or 'unknown')}",
            f"- Secret findings: {int(summary.get('finding_count') or gitleaks_evidence.get('finding_count') or 0)}",
            f"- Affected files: {int(summary.get('affected_files_count') or gitleaks_evidence.get('affected_files_count') or 0)}",
            "- Rules: " + _format_count_summary(summary.get("rule_summary") or gitleaks_evidence.get("rule_summary") or {}),
            "- Providers: " + _format_count_summary(summary.get("provider_summary") or gitleaks_evidence.get("provider_summary") or {}),
            "- Severity: " + _format_count_summary(summary.get("severity_summary") or gitleaks_evidence.get("severity_summary") or {}),
            "- Limitation: Secret values are redacted. Detections are not proof of compromise.",
        ]
        for item in (gitleaks_evidence.get("findings") or [])[:10]:
            lines.append(
                f"- {_clean(item.get('rule_id') or 'unknown')} file={_clean(item.get('file_path') or 'unknown')} "
                f"line={_clean(item.get('line_number') or 'unknown')} provider={_clean(item.get('provider') or 'unknown')} "
                f"secret={_clean(item.get('redacted_secret_preview') or '<REDACTED>')}"
            )
        return lines

    prowler_evidence = finding.get("prowler_evidence") or {}
    if prowler_evidence:
        summary = finding.get("prowler_summary") or {}
        provider = _clean(finding.get("provider") or prowler_evidence.get("provider") or "unknown").upper()
        cloud_context = _clean(finding.get("cloud_context") or prowler_evidence.get("cloud_context") or finding.get("target") or "unknown")
        checks = prowler_evidence.get("findings") or []
        failed = [item for item in checks if str(item.get("status") or "").upper() == "FAIL"]
        lines = [
            f"- Provider: {provider}",
            f"- Context: {cloud_context}",
            f"- Total checks/findings parsed: {int(summary.get('finding_count') or prowler_evidence.get('finding_count') or len(checks))}",
            f"- Failed checks: {int(summary.get('failed_count') or len(failed))}",
            f"- Passed checks: {int(summary.get('passed_count') or 0)}",
            f"- Highest scanner-reported severity: {_clean(summary.get('highest_severity') or 'none')}",
            "- Top failed services: " + (", ".join(_clean(value) for value in (summary.get("top_failed_services") or [])[:10]) or "none"),
            "- Limitation: FAIL results are scanner-reported failed checks, not confirmed exploitability or compromise.",
        ]
        for item in failed[:10]:
            lines.append(
                f"- {_clean(item.get('status') or 'unknown')} {_clean(item.get('check_id') or 'check')} "
                f"severity={_clean(item.get('severity') or 'unknown')} service={_clean(item.get('service') or 'unknown')} "
                f"region={_clean(item.get('region') or 'unknown')} title={_clean(item.get('check_title') or 'unknown')}"
            )
        return lines

    metasploit_evidence = finding.get("metasploit_evidence") or {}
    if metasploit_evidence:
        metadata = finding.get("metadata") or {}
        lines = [
            f"- Target: {_clean(metasploit_evidence.get('target') or finding.get('target') or 'unknown')}",
            f"- Module: {_clean(metasploit_evidence.get('module') or metadata.get('module') or 'unknown')}",
            f"- Action: {_clean(metasploit_evidence.get('action_type') or metadata.get('action_type') or 'unknown')}",
            f"- Validation State: {_clean(metasploit_evidence.get('validation_state') or 'unknown')}",
            f"- Evidence: {_clean(metasploit_evidence.get('summary') or finding.get('summary') or 'none')}",
            f"- Proposal Reference: {_clean(metadata.get('proposal_id') or 'not supplied')}",
            f"- Artifact Reference: {_clean(metadata.get('artifact_ref') or 'not supplied')}",
            "- Limitation: Failed, blocked, or not reproduced validation does not mean the target is secure.",
        ]
        excerpt = _clean(metasploit_evidence.get("raw_evidence_excerpt") or "")
        if excerpt:
            lines.append(f"- Normalized evidence excerpt: {excerpt}")
        return lines

    tshark_evidence = scan.get("tshark_evidence") or finding.get("tshark_evidence") or {}
    if tshark_evidence:
        return _format_tshark_observations(tshark_evidence)

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

        for observation in finding.get("katana_observations") or []:
            value = _clean(observation.get("url") or observation.get("host") or "")
            if value:
                assets["urls" if _looks_like_url(value) else "hosts"].append(value)
            endpoint_type = _clean(observation.get("endpoint_type") or "")
            if endpoint_type:
                assets["services"].append(f"Katana {endpoint_type}")
            if observation.get("endpoint_type") == "javascript" and value:
                assets["other"].append(f"JavaScript: {value}")
            for parameter in observation.get("query_parameters") or []:
                assets["other"].append(f"Query parameter: {_clean(parameter)}")
            for form in observation.get("forms") or []:
                action = _clean(form.get("action") or "")
                if action:
                    assets["other"].append(f"Form action: {action}")

        playwright_observation = finding.get("playwright_observation") or {}
        for key in ("requested_url", "final_url"):
            value = _clean(playwright_observation.get(key) or "")
            if value:
                assets["urls"].append(value)
        for link in playwright_observation.get("link_samples") or []:
            assets["urls"].append(_clean(link))
        if playwright_observation.get("title"):
            assets["other"].append(f"Page title: {_clean(playwright_observation.get('title'))}")
        if int(playwright_observation.get("forms_count") or 0) > 0:
            assets["other"].append(f"Forms: {int(playwright_observation.get('forms_count') or 0)}")

        for result in finding.get("ffuf_results") or []:
            value = _clean(result.get("url") or "")
            if value:
                assets["urls"].append(value)
            status_code = result.get("status_code")
            if status_code is not None:
                assets["services"].append(f"ffuf HTTP {status_code}")
            classification = _clean(result.get("classification") or "")
            if classification:
                assets["other"].append(f"ffuf {classification}: {_clean(result.get('path') or value)}")

        testssl_evidence = finding.get("testssl_evidence") or {}
        if testssl_evidence:
            host = _clean(testssl_evidence.get("host") or "")
            if host:
                assets["hosts"].append(host)
            port = testssl_evidence.get("port")
            if port:
                assets["services"].append(f"TLS {port}")
            for protocol in testssl_evidence.get("protocols") or []:
                name = _clean(protocol.get("name") or protocol.get("id") or "")
                if name:
                    assets["services"].append(f"TLS protocol: {name}")
            cert = testssl_evidence.get("certificate") or {}
            if cert.get("issuer"):
                assets["other"].append(f"Certificate issuer: {_clean(cert.get('issuer'))}")
            if cert.get("not_after"):
                assets["other"].append(f"Certificate expiry: {_clean(cert.get('not_after'))}")

        gitleaks_evidence = finding.get("gitleaks_evidence") or {}
        if gitleaks_evidence:
            scan_root = _clean(gitleaks_evidence.get("scan_root") or finding.get("target") or "")
            if scan_root:
                assets["other"].append(f"Gitleaks scope: {scan_root}")
            for item in gitleaks_evidence.get("findings") or []:
                file_path = _clean(item.get("file_path") or "")
                rule_id = _clean(item.get("rule_id") or "secret")
                if file_path:
                    assets["other"].append(f"Gitleaks {rule_id}: {file_path}")

        prowler_evidence = finding.get("prowler_evidence") or {}
        if prowler_evidence:
            provider = _clean(finding.get("provider") or prowler_evidence.get("provider") or "")
            cloud_context = _clean(finding.get("cloud_context") or prowler_evidence.get("cloud_context") or finding.get("target") or "")
            if provider:
                assets["other"].append(f"Prowler provider: {provider.upper()}")
            if cloud_context:
                assets["other"].append(f"Prowler context: {cloud_context}")
            for item in prowler_evidence.get("findings") or []:
                service = _clean(item.get("service") or "")
                status = _clean(item.get("status") or "")
                check_id = _clean(item.get("check_id") or "check")
                if service:
                    assets["services"].append(f"Prowler {status} {check_id} {service}")

        metasploit_evidence = finding.get("metasploit_evidence") or {}
        if metasploit_evidence:
            target_value = _clean(metasploit_evidence.get("target") or finding.get("target") or "")
            if target_value:
                assets["hosts"].append(target_value)
            module = _clean(metasploit_evidence.get("module") or "")
            state = _clean(metasploit_evidence.get("validation_state") or "")
            if module:
                assets["services"].append(f"Metasploit {state} {module}".strip())
            proposal_id = _clean((finding.get("metadata") or {}).get("proposal_id") or "")
            if proposal_id:
                assets["other"].append(f"Metasploit proposal: {proposal_id}")

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
    labels = {"nmap": "Nmap", "bbot": "BBOT", "nuclei": "Nuclei", "httpx": "httpx", "katana": "Katana", "playwright": "Playwright", "ffuf": "ffuf", "testssl": "testssl.sh", "gitleaks": "Gitleaks", "prowler": "Prowler", "metasploit": "Metasploit", "tshark": "TShark"}
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


def _notable_testssl_items(evidence: dict) -> list[dict]:
    items = (evidence.get("vulnerabilities") or []) + (evidence.get("notable_findings") or []) + (evidence.get("cipher_findings") or [])
    return [item for item in items if _is_notable_testssl_item(item)]


def _is_notable_testssl_item(item: dict) -> bool:
    severity = str(item.get("severity") or "").upper()
    finding = str(item.get("finding") or "").lower()
    if severity in {"HIGH", "CRITICAL", "MEDIUM", "LOW", "WARN", "WARNING"}:
        return True
    return not any(term in finding for term in ("not vulnerable", "not offered", "not supported", "no vulnerability"))


def _format_count_summary(counts: dict) -> str:
    return ", ".join(f"{_clean(key)}={int(value or 0)}" for key, value in sorted(counts.items())) if counts else "none"


def _attach_tshark_artifacts(scans: list[dict], artifacts: list[dict]) -> list[dict]:
    evidence_by_scan: dict[int, dict] = {}
    for artifact in artifacts:
        if str(artifact.get("artifact_type") or "") != "tshark_normalized_evidence":
            continue
        scan_id = artifact.get("scan_id")
        if scan_id is None:
            continue
        try:
            content = json.loads(str(artifact.get("content") or "{}"))
        except json.JSONDecodeError:
            continue
        if isinstance(content, dict):
            evidence_by_scan[int(scan_id)] = content
    enriched = []
    for scan in scans:
        scan_id = scan.get("id")
        if scan_id is not None and int(scan_id) in evidence_by_scan:
            enriched.append({**scan, "tshark_evidence": evidence_by_scan[int(scan_id)]})
        else:
            enriched.append(scan)
    return enriched


def _format_tshark_observations(evidence: dict) -> list[str]:
    source_file = evidence.get("source_file") or {}
    truncation = evidence.get("truncation") or {}
    lines = [
        f"- Source file: {_clean(source_file.get('name') or 'uploaded capture')}",
        f"- Packet count: {int(evidence.get('packet_count') or 0)}",
        f"- Byte count: {int(evidence.get('byte_count') or 0)}",
        f"- Capture start: {_clean(evidence.get('capture_start') or 'not available')}",
        f"- Capture end: {_clean(evidence.get('capture_end') or 'not available')}",
        "- Protocols: " + (", ".join(f"{_clean(item.get('protocol'))}={int(item.get('packet_count') or 0)}" for item in (evidence.get("observed_protocols") or [])[:10]) or "none recorded"),
        "- Limitation: packet activity is not automatically malicious; a connection is not compromise; a DNS query is not exfiltration.",
        "- Limitation: encrypted traffic limits visibility, and absence from a capture proves nothing about absence from the network.",
    ]
    endpoints = evidence.get("observed_endpoints") or []
    if endpoints:
        lines.append("- Endpoints:")
        for item in endpoints[:10]:
            lines.append(f"  - {_clean(item.get('address') or 'unknown')} packets={int(item.get('packet_count') or 0)}")
    conversations = evidence.get("observed_conversations") or []
    if conversations:
        lines.append("- Conversations:")
        for item in conversations[:10]:
            lines.append(
                f"  - {_clean(item.get('src') or 'unknown')}:{_clean(item.get('src_port') or '')} -> "
                f"{_clean(item.get('dst') or 'unknown')}:{_clean(item.get('dst_port') or '')} "
                f"{_clean(item.get('transport') or 'unknown')} packets={int(item.get('packet_count') or 0)}"
            )
    dns_observations = evidence.get("dns_observations") or []
    if dns_observations:
        lines.append("- DNS metadata:")
        for item in dns_observations[:10]:
            lines.append(f"  - query={_clean(item.get('query_name') or 'n/a')} response={_clean(item.get('response_name') or item.get('response_address') or 'n/a')}")
    http_observations = evidence.get("http_observations") or []
    if http_observations:
        lines.append("- HTTP metadata:")
        for item in http_observations[:10]:
            lines.append(
                f"  - {_clean(item.get('method') or 'HTTP')} host={_clean(item.get('host') or 'n/a')} "
                f"uri={_clean(item.get('uri') or 'n/a')} status={_clean(item.get('response_code') or 'n/a')}"
            )
    tls_observations = evidence.get("tls_observations") or []
    if tls_observations:
        lines.append("- TLS metadata:")
        for item in tls_observations[:10]:
            lines.append(f"  - sni={_clean(item.get('sni') or 'n/a')} version={_clean(item.get('version') or 'n/a')}")
    active_truncation = [key for key, value in sorted(truncation.items()) if value is True]
    if active_truncation:
        lines.append("- Truncation: " + ", ".join(_clean(value) for value in active_truncation))
    for warning in evidence.get("parser_warnings") or []:
        lines.append(f"- Parser warning: {_clean(warning)}")
    return lines
