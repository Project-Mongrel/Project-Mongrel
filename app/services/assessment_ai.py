from app.services.ai_client import ask_ai
from app.services.assessment_guard import SECURE_PREAMBLE, build_guard_prompt_section, is_secure_question

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
        response = ask_ai(prompt)
    except Exception:
        return FALLBACK_REPORT

    if _is_unavailable_response(response):
        return FALLBACK_REPORT

    return str(response or "").strip() or FALLBACK_REPORT


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
            "- Never imply a clean Nuclei scan means the target is secure.",
            "- If evidence is missing, explain what has not yet been assessed.",
            "- Include completed and partial scans as represented evidence, clearly labeling partial evidence as partial.",
            "- Base conclusions only on Nmap, BBOT, Nuclei, httpx, Katana, Playwright, ffuf, assessment history, artifacts, and notes in the supplied context.",
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

    scans = context.get("scans") or []
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
        missing_tools = [tool for tool in ("nmap", "bbot", "nuclei", "httpx", "katana", "playwright", "ffuf") if tool not in represented_tools]
        lines.append("- Represented tools:")
        lines.append("  - " + (", ".join(represented_tools) if represented_tools else "none"))
        lines.append("- Missing or not represented:")
        lines.append("  - " + (", ".join(missing_tools) if missing_tools else "none"))
    else:
        lines.append("- Scan history: no scans recorded")

    findings = context.get("findings") or []
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
        lines.append("    Nuclei findings:")
        for item in nuclei_findings[:20]:
            lines.append(
                f"    - {_clean(item.get('template_id') or item.get('name') or 'finding')} "
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
        lines.append("    httpx services:")
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
                parts.append("params=" + ", ".join(_clean(value) for value in observation.get("query_parameters")[:8]))
            if observation.get("forms"):
                parts.append(f"forms={len(observation.get('forms') or [])}")
            lines.append("    - " + " ".join(parts))
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
        parts.append(f"forms={int(playwright_observation.get('forms_count') or 0)}")
        parts.append(f"inputs={int(playwright_observation.get('inputs_count') or 0)}")
        parts.append(f"links={int(playwright_observation.get('links_count') or 0)}")
        parts.append(f"console_issues={int(playwright_observation.get('console_issue_count') or 0)}")
        parts.append(f"network_issues={int(playwright_observation.get('network_issue_count') or 0)}")
        lines.append("    - " + " ".join(parts))
    ffuf_results = finding.get("ffuf_results") or []
    if ffuf_results:
        lines.append("    ffuf results:")
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
    return lines


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:700]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
