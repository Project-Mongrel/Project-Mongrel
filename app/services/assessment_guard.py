CORE_TOOLS = ("nmap", "bbot", "nuclei", "httpx", "katana")
LOCKED_TOOL_LIMITATIONS = (
    "Playwright not run",
    "ffuf not run",
    "testssl.sh not run",
    "Gitleaks not run",
    "ScoutSuite/Prowler not run",
    "Metasploit validation not run",
    "TShark not run",
)
SECURE_PREAMBLE = "Based on the evidence collected in this assessment, I cannot conclude the target is secure."


def build_assessment_guard(context: dict, question: object | None = None) -> dict:
    scans = context.get("scans") or []
    status_by_tool = _status_by_tool(scans)
    completed_tools = _tools_with_status(status_by_tool, "completed")
    partial_tools = _tools_with_status(status_by_tool, "partial")
    failed_tools = _tools_with_status(status_by_tool, "failed")
    represented_tools = sorted(set(completed_tools + partial_tools))
    missing_core_tools = [tool for tool in CORE_TOOLS if tool not in status_by_tool]
    observed_assets = collect_observed_assets(context)

    return {
        "completed_tools": completed_tools,
        "partial_tools": partial_tools,
        "failed_tools": failed_tools,
        "represented_tools": represented_tools,
        "missing_core_tools": missing_core_tools,
        "locked_tool_limitations": list(LOCKED_TOOL_LIMITATIONS),
        "observed_assets": observed_assets,
        "is_secure_question": is_secure_question(question),
        "secure_preamble": SECURE_PREAMBLE,
        "is_complete": not missing_core_tools and not failed_tools and not partial_tools,
        "limitations": build_guard_limitations(missing_core_tools, partial_tools, failed_tools),
    }


def build_guard_prompt_section(context: dict, question: object | None = None) -> str:
    guard = build_assessment_guard(context, question=question)
    lines = [
        "Assessment Guardrails:",
        f"- Completed tools: {_join_or_none(guard['completed_tools'])}",
        f"- Partial tools: {_join_or_none(guard['partial_tools'])}",
        f"- Failed tools: {_join_or_none(guard['failed_tools'])}",
        f"- Represented evidence tools: {_join_or_none(guard['represented_tools'])}",
        f"- Missing core tools: {_join_or_none(guard['missing_core_tools'])}",
        f"- Assessment complete relative to current core tools: {guard['is_complete']}",
        f"- Observed hosts/targets: {_join_or_none(guard['observed_assets']['hosts'])}",
        f"- Observed services: {_join_or_none(guard['observed_assets']['services'])}",
        f"- Observed URLs: {_join_or_none(guard['observed_assets']['urls'])}",
        f"- Observed asset summary: {guard['observed_assets']['summary']}",
        "- Mandatory limitations:",
    ]
    lines.extend(f"  - {limitation}" for limitation in guard["limitations"])
    lines.append("- Locked-tool limitations:")
    lines.extend(f"  - {limitation}" for limitation in guard["locked_tool_limitations"])
    lines.extend(
        [
            "- Never state or imply that the target is secure or safe.",
            "- Never treat no findings or a clean Nuclei result as proof of security.",
            "- Completed and partial scans are represented evidence; failed and missing tools are limitations.",
        ]
    )
    if guard["is_secure_question"]:
        lines.append(f"- Secure/safe question preamble: {SECURE_PREAMBLE}")
    return "\n".join(lines)


def build_guard_limitations(missing_core_tools: list[str], partial_tools: list[str], failed_tools: list[str]) -> list[str]:
    limitations = []
    if missing_core_tools:
        limitations.append("Core tools not run: " + ", ".join(missing_core_tools))
    if partial_tools:
        limitations.append("Partial evidence from: " + ", ".join(partial_tools))
    if failed_tools:
        limitations.append("Failed scans: " + ", ".join(failed_tools))
    limitations.append("Absence of findings is not evidence of security.")
    return limitations


def is_secure_question(question: object) -> bool:
    normalized = str(question or "").lower()
    return any(term in normalized for term in ("secure", "safe"))


def collect_observed_assets(context: dict) -> dict[str, list[str] | str]:
    hosts = []
    services = []
    urls = []
    for target in context.get("targets") or []:
        address = str(target.get("address") or "").strip()
        if address:
            hosts.append(address)
    for finding in context.get("findings") or []:
        target = str(finding.get("target") or "").strip()
        if target:
            hosts.append(target)
        for open_port in finding.get("open_ports") or []:
            port = str(open_port.get("port") or "unknown").strip()
            protocol = str(open_port.get("protocol") or "tcp").strip()
            service = str(open_port.get("service") or "unknown").strip()
            services.append(f"{port}/{protocol} {service}")
        for item in finding.get("nuclei_findings") or []:
            for key in ("matched_at", "host", "url"):
                value = str(item.get(key) or "").strip()
                if value:
                    urls.append(value)
        for service in finding.get("httpx_services") or []:
            value = str(service.get("url") or service.get("host") or "").strip()
            if value:
                urls.append(value)
            status_code = service.get("status_code")
            if status_code is not None:
                services.append(f"http {status_code}")
            for technology in service.get("technologies") or []:
                cleaned = str(technology or "").strip()
                if cleaned:
                    services.append(f"technology: {cleaned}")
        for observation in finding.get("katana_observations") or []:
            value = str(observation.get("url") or observation.get("host") or "").strip()
            if value:
                urls.append(value)
            endpoint_type = str(observation.get("endpoint_type") or "").strip()
            if endpoint_type:
                services.append(f"katana {endpoint_type}")
            for parameter in observation.get("query_parameters") or []:
                cleaned = str(parameter or "").strip()
                if cleaned:
                    services.append(f"query parameter: {cleaned}")
        counts = finding.get("observation_counts") or {}
        for key, value in sorted(counts.items()):
            if int(value or 0) > 0:
                services.append(f"{key}: {int(value or 0)}")

    hosts = _unique(hosts)
    services = _unique(services)
    urls = _unique(urls)
    summary_parts = []
    if hosts:
        summary_parts.append(f"{len(hosts)} host/target value(s)")
    if services:
        summary_parts.append(f"{len(services)} service/observation value(s)")
    if urls:
        summary_parts.append(f"{len(urls)} URL value(s)")
    return {
        "hosts": hosts,
        "services": services,
        "urls": urls,
        "summary": ", ".join(summary_parts) if summary_parts else "none observed in supplied evidence",
    }


def _status_by_tool(scans: list[dict]) -> dict[str, set[str]]:
    statuses: dict[str, set[str]] = {}
    for scan in scans:
        tool = str(scan.get("tool") or "").strip().lower()
        status = str(scan.get("status") or "").strip().lower()
        if not tool or not status:
            continue
        statuses.setdefault(tool, set()).add(status)
    return statuses


def _tools_with_status(status_by_tool: dict[str, set[str]], status: str) -> list[str]:
    return sorted(tool for tool, statuses in status_by_tool.items() if status in statuses)


def _join_or_none(values: list[str]) -> str:
    return ", ".join(values) if values else "none"


def _unique(values: list[str]) -> list[str]:
    seen = set()
    results = []
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(value)
    return results
