from app.services.ai_client import ask_ai
from app.services.assessment_guard import SECURE_PREAMBLE, build_guard_prompt_section, is_secure_question
from app.services.assessment_scan_selection import select_latest_scans

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

FALLBACK_ANSWER = "Assessment AI is unavailable. Review the assessment dashboard, scan history, and stored findings for next steps."
FALLBACK_REPORT = (
    "Assessment AI report unavailable. Review the assessment dashboard, scan history, and stored findings for next steps."
)
ASSESSMENT_AI_REPORT_NUM_PREDICT = 1536


def answer_assessment_question(question: str, context: dict) -> str:
    prompt = build_assessment_ai_prompt(question, context)
    try:
        response = ask_ai(prompt)
    except Exception:
        return FALLBACK_ANSWER

    if _is_unavailable_response(response):
        return FALLBACK_ANSWER

    answer = str(response or "").strip()
    if not answer:
        return FALLBACK_ANSWER
    if is_secure_question(question) and "cannot conclude" not in answer.lower():
        answer = f"{SECURE_PREAMBLE}\n\n" + answer
    return answer


def generate_assessment_ai_report(context: dict) -> str:
    prompt = build_assessment_ai_report_prompt(context)
    try:
        response = ask_ai(prompt, num_predict=ASSESSMENT_AI_REPORT_NUM_PREDICT)
    except Exception:
        return FALLBACK_REPORT

    if _is_unavailable_response(response):
        return FALLBACK_REPORT

    report = str(response or "").strip()
    return _sanitize_assessment_ai_report(report, context) if report else FALLBACK_REPORT


def build_assessment_ai_prompt(question: str, context: dict) -> str:
    return "\n".join(
        [
            "You are Mongrel.",
            "",
            "You are analysing ONE authorised security assessment.",
            "",
            "Rules:",
            "- Answer ONLY using evidence supplied.",
            "- Never invent findings.",
            "- Never assume vulnerabilities.",
            "- Never claim exploitation.",
            '- Never say the target is "safe" or "secure".',
            "- Treat Metasploit execution status, validation state, and session evidence as separate facts.",
            "- Do not infer exploit success, compromise, shell access, vulnerability confirmation, or vulnerability absence from Metasploit subprocess success, compatibility, failed validation, or no session.",
            "- Treat TShark evidence as packet metadata only; do not infer exploitation, compromise, vulnerability, ownership, authentication success, successful TLS handshakes, or completed HTTP transactions from packet observations alone.",
            "- Treat testssl.sh results as TLS configuration evidence only.",
            "- Do not invent TLS vulnerabilities or claim overall site security from TLS evidence alone.",
            "- Preserve testssl.sh severity, scanner wording, and uncertainty exactly; 'potentially VULNERABLE' remains potential scanner evidence requiring validation.",
            "- Treat Gitleaks detections as redacted secret-exposure evidence only.",
            "- Never include raw secret values or infer hidden secret values.",
            "- Do not infer Gitleaks-detected values are valid, active, usable, owned by the target, or evidence of access, compromise, exfiltration, or repository security posture.",
            "- Treat Prowler evidence as scanner-reported cloud check results only; PASS does not prove account/resource security, and FAIL does not prove exploitability, compromise, attacker access, data exposure, or compliance failure.",
            "- Preserve Prowler severity and compliance mappings as check-specific scanner metadata, not business impact or organization-wide regulatory conclusions.",
            "- If evidence is missing, say so.",
            "- If evidence is insufficient, recommend the next assessment step.",
            f"- For secure/safe questions, start with: {SECURE_PREAMBLE}",
            "- For secure/safe questions, explain observed evidence, unassessed areas, whether confirmed vulnerabilities were found, and recommended next steps.",
            "- Keep the answer concise and consultant-focused.",
            "- Do not use evidence from other assessments.",
            "",
            build_guard_prompt_section(context, question=question),
            "",
            "Assessment Evidence:",
            _format_assessment_context(context),
            "",
            "User question:",
            str(question or "").strip(),
            "",
            "Answer:",
        ]
    )


def build_assessment_ai_report_prompt(context: dict) -> str:
    return "\n".join(
        [
            "You are Mongrel.",
            "",
            "You are preparing a professional AI Assessment Report for ONE authorised security assessment.",
            "",
            "Rules:",
            "- Evidence-only.",
            "- Answer ONLY using evidence supplied.",
            "- Never invent vulnerabilities.",
            "- Never invent findings.",
            "- Never assume vulnerabilities.",
            "- Never claim exploitation.",
            '- Never state a target is "safe".',
            "- Treat Metasploit execution status, validation state, and session evidence as separate facts.",
            "- Do not infer exploit success, compromise, shell access, vulnerability confirmation, or vulnerability absence from Metasploit subprocess success, compatibility, failed validation, or no session.",
            "- Treat TShark evidence as packet metadata only; do not infer exploitation, compromise, vulnerability, ownership, authentication success, successful TLS handshakes, or completed HTTP transactions from packet observations alone.",
            "- Never imply a clean Nuclei scan means the target is secure.",
            "- Describe Nuclei matches as template matches/observations with their stored severity; do not relabel INFO matches as issues or confirmed vulnerabilities.",
            "- Playwright is passive browser-state evidence and cannot establish that hidden content is absent.",
            "- The latest authoritative same-tool scan wins; do not merge metadata from older runs.",
            "- A failed tool without structured evidence supplies failure/coverage state only, not clean or completed scanner evidence.",
            "- If evidence is missing, explain what has not yet been assessed.",
            "- Include completed and partial scans as represented evidence, clearly labeling partial evidence as partial.",
            "- Base conclusions only on Nmap, BBOT, Nuclei, httpx, Katana, Playwright, ffuf, testssl.sh, Gitleaks, Prowler, Metasploit, TShark, assessment history, artifacts, and notes in the supplied context.",
            "- testssl.sh evidence supports TLS configuration assessment only; do not claim overall site security from TLS evidence alone.",
            "- Preserve testssl.sh severity, scanner wording, and uncertainty exactly; do not turn potential TLS findings into confirmed exploitability.",
            "- Gitleaks evidence is redacted secret-pattern detection only; do not claim validity, current usability, ownership, access, compromise, exfiltration, repository security, or absence of secrets from Gitleaks output alone.",
            "- Prowler evidence is scanner-reported cloud check output only; do not claim cloud/account/resource security, exploitability, compromise, data exposure, organization-wide compliance/non-compliance, or absence of misconfigurations from Prowler output alone.",
            "- Preserve Prowler PASS/FAIL, severity, resource/service/region metadata, and compliance mappings as check-specific scanner evidence.",
            "- Keep the report concise and consultant-focused.",
            "- Return final answer only.",
            "",
            build_guard_prompt_section(context),
            "",
            "Required report structure:",
            "✦ Assessment AI Report",
            "Executive Summary",
            "Assessment Overview",
            "Completed Activities",
            "Observed Assets",
            "Key Findings",
            "Potential Risks",
            "Recommended Next Actions",
            "Confidence",
            "Evidence Limitations",
            "",
            "Assessment Evidence:",
            _format_assessment_context(context),
            "",
            "Report:",
        ]
    )


def _format_assessment_context(context: dict) -> str:
    assessment = context.get("assessment") or {}
    lines = [
        f"- Assessment name: {_clean(assessment.get('name') or 'unknown')}",
        f"- Assessment status: {_clean(assessment.get('status') or 'unknown')}",
    ]
    if assessment.get("description"):
        lines.append(f"- Description: {_clean(assessment['description'])}")

    targets = context.get("targets") or []
    if targets:
        lines.append("- Targets:")
        for target in targets[:10]:
            lines.append(f"  - {_clean(target.get('address') or 'unknown')} type={_clean(target.get('target_type') or 'unknown')}")
    else:
        lines.append("- Targets: none supplied")

    scans = select_latest_scans(context.get("scans") or [])
    if scans:
        lines.append("- Scan history:")
        for scan in scans[:20]:
            lines.append(_format_scan(scan))
        represented_tools = sorted(
            {
                str(scan.get("tool") or "unknown").lower()
                for scan in scans
                if str(scan.get("status") or "").lower() in {"completed", "partial"}
            }
        )
        missing_tools = [tool for tool in ("nmap", "bbot", "nuclei", "httpx", "katana", "playwright", "ffuf", "testssl", "gitleaks") if tool not in represented_tools]
        lines.append("- Represented tools:")
        lines.append("  - " + (", ".join(represented_tools) if represented_tools else "none"))
        lines.append("- Missing or not represented:")
        lines.append("  - " + (", ".join(missing_tools) if missing_tools else "none"))
    else:
        lines.append("- Scan history: no scans recorded")

    findings = _findings_for_latest_scans(scans, context.get("findings") or [])
    if findings:
        lines.append("- Stored findings:")
        for finding in findings[:20]:
            lines.extend(_format_finding(finding))
    else:
        lines.append("- Stored findings: none linked")

    artifacts = context.get("artifacts") or []
    if artifacts:
        lines.append("- Artifacts:")
        for artifact in artifacts[:20]:
            lines.append(
                f"  - {_clean(artifact.get('artifact_type') or 'artifact')} title={_clean(artifact.get('title') or 'untitled')} "
                f"content={_clean(artifact.get('content') or '')}"
            )
    else:
        lines.append("- Artifacts: none recorded")

    notes = context.get("notes") or []
    if notes:
        lines.append("- Notes:")
        for note in notes[:20]:
            lines.append(f"  - {_clean(note.get('note_type') or 'manual')}: {_clean(note.get('content') or '')}")
    else:
        lines.append("- Notes: none recorded")

    return "\n".join(lines)


def _format_scan(scan: dict) -> str:
    parts = [
        f"  - tool={_clean(scan.get('tool') or 'unknown')}",
        f"status={_clean(scan.get('status') or 'unknown')}",
    ]
    if scan.get("risk"):
        parts.append(f"risk={_clean(scan['risk'])}")
    if scan.get("elapsed_seconds") is not None:
        parts.append(f"elapsed={scan['elapsed_seconds']}s")
    if scan.get("finding_id"):
        parts.append(f"finding_id={_clean(scan['finding_id'])}")
    return " ".join(parts)


def _findings_for_latest_scans(scans: list[dict], flattened_findings: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for scan in scans:
        finding = scan.get("finding")
        if not finding:
            tool = str(scan.get("tool") or "").lower().removesuffix(".sh")
            matches = [
                item for item in flattened_findings
                if str(item.get("source") or "").lower().removesuffix(".sh") == tool
            ]
            finding = matches[-1] if matches else None
        if finding:
            findings.append(finding)
    return findings


def _sanitize_assessment_ai_report(report: str, context: dict) -> str:
    """Correct narrow scanner-semantic contradictions in model-authored reports."""
    latest = select_latest_scans(context.get("scans") or [])
    latest_by_tool = {str(scan.get("tool") or "").lower().removesuffix(".sh"): scan for scan in latest}
    lines: list[str] = []
    for line in report.splitlines():
        lowered = line.lower()
        if ("ffuw" in lowered or "ffuf" in lowered) and "hidden content" in lowered and any(
            term in lowered for term in ("no hidden", "zero hidden", "no structured", "no paths")
        ):
            scan = latest_by_tool.get("ffuf") or {}
            finding = scan.get("finding") or {}
            metadata = finding.get("metadata") or {}
            results = finding.get("ffuf_results") or []
            profile = metadata.get("ffuf_profile_label") or metadata.get("profile") or "recorded"
            line = (
                f"ffuf: the {profile} run stored {len(results)} structured response observation(s); "
                "zero observations do not establish that hidden content or paths are absent."
            )
        if "hsts" in lowered and "secure" in lowered:
            nuclei_scan = latest_by_tool.get("nuclei") or {}
            matches = ((nuclei_scan.get("finding") or {}).get("nuclei_findings") or [])
            hsts_matches = [
                item for item in matches
                if "hsts" in str(item.get("template_id") or item.get("name") or "").lower()
            ]
            hsts_severities = sorted({str(item.get("severity") or "info").upper() for item in hsts_matches})
            detail = (
                f" The assessment also contains {len(hsts_matches)} HSTS-related Nuclei template match(es) "
                f"({', '.join(hsts_severities)}); their stored wording requires validation."
                if hsts_matches else ""
            )
            line = "HSTS presence is a stored observation only and does not establish security." + detail
        if "no findings indicate" in lowered and any(term in lowered for term in ("vulnerab", "exploit")):
            line = "No confirmed vulnerability or exploitability conclusion is established by the stored evidence."
        if "no immediate remediation" in lowered:
            line = (
                "Next actions should address failed or unperformed coverage and validate relevant stored observations; "
                "this report does not execute tools or prescribe remediation without validation."
            )
        if "playwright" in lowered and "forms" in lowered:
            scan = latest_by_tool.get("playwright") or {}
            observation = ((scan.get("finding") or {}).get("playwright_observation") or {})
            if observation and int(observation.get("forms_count") or 0) == 0:
                inputs = int(observation.get("inputs_count") or 0)
                links = int(observation.get("links_count") or 0)
                line = (
                    f"Playwright: the passive returned state recorded 0 forms, {inputs} inputs, and {links} links; "
                    "zero forms in that returned state does not establish absence elsewhere."
                )
        if "playwright" in lowered and "no hidden content" in lowered:
            line = "Playwright: passive browser observation was recorded; it does not establish that hidden content is absent."
        if "nuclei" in lowered and "issue" in lowered:
            scan = latest_by_tool.get("nuclei") or {}
            matches = ((scan.get("finding") or {}).get("nuclei_findings") or [])
            if matches:
                severities = sorted({str(item.get("severity") or "info").upper() for item in matches})
                line = (
                    f"Nuclei: {len(matches)} template match(es) were stored ({', '.join(severities)}); "
                    "these observations do not automatically establish a confirmed vulnerability or exploitability."
                )
        if "testssl" in lowered:
            scan = latest_by_tool.get("testssl") or {}
            status = str(scan.get("status") or "").lower()
            evidence = (scan.get("finding") or {}).get("testssl_evidence") or {}
            if status == "failed" and not evidence and any(term in lowered for term in ("clean", "no finding", "completed", "stored tls", "tls observations")):
                line = "testssl.sh: FAILED; no completed structured TLS configuration evidence was stored."
        lines.append(line)
    return "\n".join(lines).strip()


def _format_finding(finding: dict) -> list[str]:
    lines = [
        f"  - tool={_clean(finding.get('source') or 'unknown')} target={_clean(finding.get('target') or 'unknown')} "
        f"risk={_clean(finding.get('risk_level') or 'unknown')} summary={_clean(finding.get('summary') or '')}"
    ]
    open_ports = finding.get("open_ports") or []
    if open_ports:
        lines.append("    Open ports:")
        for open_port in open_ports[:20]:
            lines.append(
                f"    - {_clean(open_port.get('port') or 'unknown')}/{_clean(open_port.get('protocol') or 'tcp')} "
                f"{_clean(open_port.get('service') or 'unknown')}"
            )
    nuclei_findings = finding.get("nuclei_findings") or []
    if nuclei_findings:
        lines.append("    Nuclei template matches:")
        for item in nuclei_findings[:20]:
            lines.append(
                f"    - {_clean(item.get('template_id') or item.get('name') or 'template match')} "
                f"severity={_clean(item.get('severity') or 'unknown')} "
                f"matched={_clean(item.get('matched_at') or item.get('host') or 'unknown')}"
            )
    observation_counts = finding.get("observation_counts") or {}
    if observation_counts:
        lines.append(
            "    Observation counts: "
            + ", ".join(f"{_clean(key)}={int(value or 0)}" for key, value in sorted(observation_counts.items()))
        )
    httpx_services = finding.get("httpx_services") or []
    if httpx_services:
        lines.append("    httpx response observations:")
        for service in httpx_services[:20]:
            parts = [
                f"url={_clean(service.get('url') or service.get('host') or 'unknown')}",
                f"status={_clean(service.get('status_code') or 'unknown')}",
            ]
            if service.get("title"):
                parts.append(f"title={_clean(service.get('title'))}")
            if service.get("web_server"):
                parts.append(f"server={_clean(service.get('web_server'))}")
            if service.get("technologies"):
                parts.append("tech=" + ", ".join(_clean(value) for value in service.get("technologies")[:8]))
            if service.get("redirect_location") or service.get("final_url"):
                parts.append(f"redirect={_clean(service.get('redirect_location') or service.get('final_url'))}")
            lines.append("    - " + " ".join(parts))
    katana_observations = finding.get("katana_observations") or []
    if katana_observations:
        lines.append("    Katana observations:")
        for observation in katana_observations[:20]:
            parts = [
                f"url={_clean(observation.get('url') or 'unknown')}",
                f"type={_clean(observation.get('endpoint_type') or 'url')}",
            ]
            if observation.get("method"):
                parts.append(f"method={_clean(observation.get('method'))}")
            if observation.get("status_code"):
                parts.append(f"status={_clean(observation.get('status_code'))}")
            if observation.get("depth") is not None:
                parts.append(f"depth={_clean(observation.get('depth'))}")
            if observation.get("source"):
                parts.append(f"source={_clean(observation.get('source'))}")
            if observation.get("query_parameters"):
                parts.append("params_observed_during_crawl=" + ", ".join(_clean(value) for value in observation.get("query_parameters")[:8]))
            if observation.get("forms"):
                parts.append(f"forms_observed_during_crawl={len(observation.get('forms') or [])}")
            lines.append("    - " + " ".join(parts))
        lines.append("    - boundary=Katana crawl observations only; does not prove vulnerability, exploitability, sensitive exposure, ownership, public availability at all times, or complete coverage")
    playwright_observation = finding.get("playwright_observation") or {}
    if playwright_observation:
        lines.append("    Playwright observation:")
        parts = [
            f"requested={_clean(playwright_observation.get('requested_url') or 'unknown')}",
            f"final={_clean(playwright_observation.get('final_url') or 'unknown')}",
            f"load={_clean(playwright_observation.get('load_status') or 'unknown')}",
        ]
        if playwright_observation.get("status_code"):
            parts.append(f"status={_clean(playwright_observation.get('status_code'))}")
        if playwright_observation.get("title"):
            parts.append(f"title={_clean(playwright_observation.get('title'))}")
        parts.append(f"forms_observed_in_returned_state={int(playwright_observation.get('forms_count') or 0)}")
        parts.append(f"inputs_observed_in_returned_state={int(playwright_observation.get('inputs_count') or 0)}")
        parts.append(f"links_observed_in_returned_state={int(playwright_observation.get('links_count') or 0)}")
        parts.append(f"console_issues={int(playwright_observation.get('console_issue_count') or 0)}")
        parts.append(f"network_issues={int(playwright_observation.get('network_issue_count') or 0)}")
        lines.append("    - " + " ".join(parts))
        lines.append("    - boundary=passive returned browser state only; does not test XSS, SQL injection, CSRF, authentication flaws, hidden-content absence, vulnerability absence, or complete application behavior")
    ffuf_results = finding.get("ffuf_results") or []
    if ffuf_results or str(finding.get("source") or "").lower() == "ffuf":
        metadata = finding.get("metadata") or {}
        lines.append(
            "    ffuf run scope: "
            f"profile={_clean(metadata.get('ffuf_profile_label') or metadata.get('profile') or 'not recorded')} "
            f"wordlist={_clean(metadata.get('wordlist_path') or metadata.get('wordlist') or 'not recorded')} "
            f"wordlist_source={_clean(metadata.get('wordlist_source') or 'not recorded')} "
            f"wordlist_entries={_clean(metadata.get('wordlist_count') if metadata.get('wordlist_count') is not None else 'not recorded')} "
            f"timeout={_clean(metadata.get('timeout_seconds') if metadata.get('timeout_seconds') is not None else 'not recorded')}"
        )
        lines.append(f"    ffuf structured response observations: {len(ffuf_results)}")
        if not ffuf_results:
            lines.append("    - boundary=zero structured response observations does not establish that hidden content is absent")
    if ffuf_results:
        lines.append("    ffuf response observations:")
        for result in ffuf_results[:20]:
            parts = [
                f"url={_clean(result.get('url') or 'unknown')}",
                f"status={_clean(result.get('status_code') or 'unknown')}",
                f"classification={_clean(result.get('classification') or 'observed')}",
            ]
            if result.get("content_length") is not None:
                parts.append(f"length={_clean(result.get('content_length'))}")
            if result.get("words") is not None:
                parts.append(f"words={_clean(result.get('words'))}")
            if result.get("lines") is not None:
                parts.append(f"lines={_clean(result.get('lines'))}")
            if result.get("redirect_location"):
                parts.append(f"redirect={_clean(result.get('redirect_location'))}")
            if result.get("input_word"):
                parts.append(f"word={_clean(result.get('input_word'))}")
            lines.append("    - " + " ".join(parts))
        lines.append("    - boundary=ffuf fuzzing response metadata only; does not prove vulnerability, exploitability, sensitive exposure, authentication bypass, or complete discovery coverage")
    testssl_evidence = finding.get("testssl_evidence") or {}
    if testssl_evidence:
        lines.append("    testssl.sh TLS evidence:")
        cert = testssl_evidence.get("certificate") or {}
        if cert:
            lines.append(
                "    - certificate "
                f"subject={_clean(cert.get('subject') or cert.get('common_name') or 'unknown')} "
                f"issuer={_clean(cert.get('issuer') or 'unknown')} "
                f"expires={_clean(cert.get('not_after') or 'unknown')} "
                f"san={_clean(cert.get('subject_alt_names') or 'unknown')}"
            )
        protocols = testssl_evidence.get("protocols") or []
        if protocols:
            lines.append("    - protocols: " + ", ".join(_clean(item.get("name") or item.get("id")) for item in protocols[:10]))
        weak_protocols = testssl_evidence.get("weak_protocols") or []
        if weak_protocols:
            lines.append("    - weak/deprecated protocols: " + "; ".join(_clean(item) for item in weak_protocols[:10]))
        for label, key in (
            ("vulnerabilities", "vulnerabilities"),
            ("notable findings", "notable_findings"),
            ("cipher findings", "cipher_findings"),
            ("security headers", "security_headers"),
        ):
            values = testssl_evidence.get(key) or []
            if values:
                lines.append(f"    - {label}:")
                for item in values[:10]:
                    lines.append(
                        f"      - {_clean(item.get('id') or 'finding')} severity={_clean(item.get('severity') or 'info')} "
                        f"finding={_clean(item.get('finding') or '')}"
                    )
        for limitation in testssl_evidence.get("limitations") or []:
            lines.append(f"    - limitation: {_clean(limitation)}")
        lines.append("    - boundary=testssl.sh TLS scanner evidence only; preserve scanner severity and uncertainty; potential findings are not confirmed exploitability")
    gitleaks_evidence = finding.get("gitleaks_evidence") or {}
    if gitleaks_evidence:
        lines.append("    Gitleaks redacted secret-exposure evidence:")
        lines.append(f"    - scan_root={_clean(gitleaks_evidence.get('scan_root') or finding.get('target') or 'unknown')}")
        lines.append(f"    - findings={int(gitleaks_evidence.get('finding_count') or 0)} affected_files={int(gitleaks_evidence.get('affected_files_count') or 0)}")
        for item in (gitleaks_evidence.get("findings") or [])[:20]:
            lines.append(
                f"    - rule={_clean(item.get('rule_id') or 'unknown')} file={_clean(item.get('file_path') or 'unknown')} "
                f"line={_clean(item.get('line_number') or 'unknown')} provider={_clean(item.get('provider') or 'unknown')} "
                f"severity={_clean(item.get('severity') or 'unknown')} fingerprint={_clean(item.get('fingerprint') or item.get('secret_hash') or 'not supplied')} "
                f"commit={_clean(item.get('commit') or 'not supplied')} secret={_clean(item.get('redacted_secret_preview') or '<REDACTED>')}"
            )
        for limitation in gitleaks_evidence.get("limitations") or []:
            lines.append(f"    - limitation: {_clean(limitation)}")
        lines.append("    - boundary=Gitleaks redacted secret-pattern detection only; validity, current usability, ownership, access, compromise, exfiltration, repository security, and absence of secrets are not established")
    prowler_evidence = finding.get("prowler_evidence") or {}
    if prowler_evidence:
        summary = finding.get("prowler_summary") or {}
        checks = prowler_evidence.get("findings") or []
        failed = [item for item in checks if str(item.get("status") or "").upper() == "FAIL"]
        lines.append("    Prowler scanner-reported cloud check evidence:")
        lines.append(f"    - provider={_clean(finding.get('provider') or prowler_evidence.get('provider') or 'unknown')}")
        lines.append(f"    - context={_clean(finding.get('cloud_context') or prowler_evidence.get('cloud_context') or finding.get('target') or 'unknown')}")
        lines.append(
            f"    - checks={int(summary.get('finding_count') or prowler_evidence.get('finding_count') or len(checks))} "
            f"failed={int(summary.get('failed_count') or len(failed))} "
            f"passed={int(summary.get('passed_count') or 0)} "
            f"highest_scanner_severity={_clean(summary.get('highest_severity') or 'none')}"
        )
        for item in checks[:20]:
            lines.append(
                f"    - status={_clean(item.get('status') or 'unknown')} "
                f"severity={_clean(item.get('severity') or 'unknown')} "
                f"check_id={_clean(item.get('check_id') or 'check')} "
                f"service={_clean(item.get('service') or 'unknown')} "
                f"region={_clean(item.get('region') or 'unknown')} "
                f"resource={_clean(item.get('resource_identifier') or item.get('resource_name') or 'not supplied')} "
                f"title={_clean(item.get('check_title') or 'unknown')}"
            )
        for limitation in prowler_evidence.get("limitations") or []:
            lines.append(f"    - limitation: {_clean(limitation)}")
        lines.append("    - boundary=Prowler scanner-reported cloud check evidence only; PASS is not account/resource security proof, FAIL is not exploitability, compromise, attacker access, data exposure, or organization-wide compliance proof, and severity/compliance mappings remain scanner metadata")
    metasploit_evidence = finding.get("metasploit_evidence") or {}
    if metasploit_evidence:
        metadata = finding.get("metadata") or {}
        lines.append("    Metasploit normalized validation evidence:")
        lines.append(f"    - module={_clean(metasploit_evidence.get('module') or metadata.get('module') or 'unknown')}")
        lines.append(f"    - action={_clean(metasploit_evidence.get('action_type') or metadata.get('action_type') or 'unknown')}")
        lines.append(f"    - target={_clean(metasploit_evidence.get('target') or finding.get('target') or 'unknown')}")
        lines.append(f"    - port={_clean(metasploit_evidence.get('port') or metadata.get('port') or 'not supplied')}")
        lines.append(f"    - validation_state={_clean(metasploit_evidence.get('validation_state') or 'unknown')}")
        lines.append(f"    - subprocess_success={_bool_label(metasploit_evidence.get('subprocess_success'))}")
        lines.append(f"    - module_executed={_bool_label(metasploit_evidence.get('module_executed'))}")
        lines.append(f"    - session_established={_bool_label(metasploit_evidence.get('session_established'))}")
        lines.append(f"    - summary={_clean(metasploit_evidence.get('summary') or finding.get('summary') or '')}")
        lines.append(
            f"    - proposal_ref={_clean(metadata.get('proposal_id') or 'not supplied')} "
            f"artifact_ref={_clean(metadata.get('artifact_ref') or 'not supplied')}"
        )
        for limitation in metasploit_evidence.get("limitations") or []:
            lines.append(f"    - limitation: {_clean(limitation)}")
        lines.append(
            "    - boundary=Metasploit validation evidence only; subprocess success, compatibility, target response, "
            "failed validation, timeout, or no session is not exploit proof or target safety proof"
        )
    tshark_evidence = finding.get("tshark_evidence") or {}
    if tshark_evidence:
        lines.append("    TShark normalized packet metadata evidence:")
        lines.append(f"    - packet_count={int(tshark_evidence.get('packet_count') or 0)} byte_count={int(tshark_evidence.get('byte_count') or 0)}")
        lines.append(f"    - capture_start={_clean(tshark_evidence.get('capture_start') or 'not available')} capture_end={_clean(tshark_evidence.get('capture_end') or 'not available')}")
        for item in (tshark_evidence.get("observed_protocols") or [])[:10]:
            lines.append(f"    - protocol={_clean(item.get('protocol') or 'unknown')} packets={int(item.get('packet_count') or 0)}")
        for item in (tshark_evidence.get("observed_conversations") or [])[:10]:
            lines.append(
                f"    - conversation={_clean(item.get('src') or 'unknown')}:{_clean(item.get('src_port') or '')}->"
                f"{_clean(item.get('dst') or 'unknown')}:{_clean(item.get('dst_port') or '')} "
                f"transport={_clean(item.get('transport') or 'unknown')} packets={int(item.get('packet_count') or 0)}"
            )
        for item in (tshark_evidence.get("dns_observations") or [])[:10]:
            lines.append(f"    - dns_query={_clean(item.get('query_name') or 'n/a')} capture_response={_clean(item.get('response_name') or item.get('response_address') or 'n/a')}")
        for item in (tshark_evidence.get("http_observations") or [])[:10]:
            lines.append(
                f"    - http_request={_clean(item.get('method') or 'not observed')} host={_clean(item.get('host') or 'n/a')} "
                f"uri={_clean(item.get('uri') or 'n/a')} response_status={_clean(item.get('response_code') or 'not observed')}"
            )
        for item in (tshark_evidence.get("tls_observations") or [])[:10]:
            lines.append(f"    - tls_sni={_clean(item.get('sni') or 'n/a')} version={_clean(item.get('version') or 'n/a')} handshake_success=not established by stored metadata")
        truncation = tshark_evidence.get("truncation") or {}
        active_truncation = [key for key, value in sorted(truncation.items()) if value is True]
        if active_truncation:
            lines.append("    - truncation=" + ", ".join(_clean(value) for value in active_truncation))
        for limitation in tshark_evidence.get("evidence_limitations") or []:
            lines.append(f"    - limitation: {_clean(limitation)}")
        lines.append("    - boundary=TShark packet metadata only; packets, DNS, TCP, TLS, HTTP, and endpoints do not prove exploitation, compromise, ownership, authentication success, vulnerability, successful TLS handshake, or completed HTTP transaction unless explicit normalized evidence supports that exact claim")
    return lines


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:700]


def _bool_label(value: object) -> str:
    if value is True:
        return "True"
    if value is False:
        return "False"
    return "unknown"


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
