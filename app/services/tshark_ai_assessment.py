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
    "TShark AI assessment unavailable.",
    "Use the deterministic TShark PCAP metadata result for observed evidence and limitations.",
]


def generate_tshark_ai_assessment(normalized_evidence: dict) -> list[str]:
    prompt = build_tshark_ai_assessment_prompt(normalized_evidence)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)
    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)
    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return lines or list(FALLBACK_LINES)


def build_tshark_ai_assessment_prompt(normalized_evidence: dict) -> str:
    return "\n".join(
        [
            "You are a senior security analyst preparing offline PCAP metadata notes for another security consultant.",
            "",
            "Rules:",
            "- Use only the supplied normalized TShark evidence.",
            "- Do not use or request raw TShark stdout.",
            "- Do not include payloads, packet bodies, HTTP bodies, cookies, authorization headers, credentials, secrets, or raw hex.",
            "- Packets are observations, not attacks.",
            "- A connection is not compromise.",
            "- A DNS query is not exfiltration.",
            "- Encrypted traffic limits visibility.",
            "- Absence from a capture proves nothing about absence from the network.",
            "- Capture scope and time range limit conclusions.",
            "- Do not invent malware, command-and-control, data theft, exploitation, compromise, credentials, or user identity.",
            "- Separate observed metadata from hypotheses and recommended follow-up.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Observed PCAP Metadata",
            "Network Conversation Notes",
            "DNS / HTTP / TLS Notes",
            "Potential Follow-up",
            "Evidence Confidence / Limitations",
            "",
            "Normalized TShark Evidence:",
            _format_tshark_evidence(normalized_evidence),
        ]
    )


def _format_tshark_evidence(evidence: dict) -> str:
    source_file = evidence.get("source_file") or {}
    lines = [
        "- Tool: TShark",
        f"- Execution status: {_clean(evidence.get('execution_status') or 'unknown')}",
        f"- Source file name: {_clean(source_file.get('name') or 'uploaded capture')}",
        f"- Packet count: {int(evidence.get('packet_count') or 0)}",
        f"- Byte count: {int(evidence.get('byte_count') or 0)}",
        f"- Capture start: {_clean(evidence.get('capture_start') or 'not available')}",
        f"- Capture end: {_clean(evidence.get('capture_end') or 'not available')}",
    ]
    _append_items(lines, "Observed protocols", evidence.get("observed_protocols") or [], _protocol_line, 20)
    _append_items(lines, "Observed endpoints", evidence.get("observed_endpoints") or [], _endpoint_line, 30)
    _append_items(lines, "Observed conversations", evidence.get("observed_conversations") or [], _conversation_line, 30)
    _append_items(lines, "DNS metadata", evidence.get("dns_observations") or [], _dns_line, 20)
    _append_items(lines, "HTTP metadata", evidence.get("http_observations") or [], _http_line, 20)
    _append_items(lines, "TLS metadata", evidence.get("tls_observations") or [], _tls_line, 20)
    truncation = evidence.get("truncation") or {}
    if truncation:
        lines.append("- Truncation: " + ", ".join(f"{_clean(key)}={bool(value)}" for key, value in sorted(truncation.items())))
    for warning in evidence.get("parser_warnings") or []:
        lines.append(f"- Parser warning: {_clean(warning)}")
    for limitation in evidence.get("evidence_limitations") or []:
        lines.append(f"- Limitation: {_clean(limitation)}")
    return "\n".join(lines)


def _append_items(lines: list[str], title: str, items: list, formatter, limit: int) -> None:
    if not items:
        return
    lines.append(f"- {title}:")
    for item in items[:limit]:
        lines.append(f"  - {formatter(item)}")


def _protocol_line(item: dict) -> str:
    return f"{_clean(item.get('protocol') or 'unknown')} packets={int(item.get('packet_count') or 0)}"


def _endpoint_line(item: dict) -> str:
    return f"{_clean(item.get('address') or 'unknown')} packets={int(item.get('packet_count') or 0)}"


def _conversation_line(item: dict) -> str:
    return (
        f"{_clean(item.get('src') or 'unknown')}:{_clean(item.get('src_port') or '')} -> "
        f"{_clean(item.get('dst') or 'unknown')}:{_clean(item.get('dst_port') or '')} "
        f"{_clean(item.get('transport') or 'unknown')} packets={int(item.get('packet_count') or 0)}"
    )


def _dns_line(item: dict) -> str:
    return f"query={_clean(item.get('query_name') or 'n/a')} response={_clean(item.get('response_name') or item.get('response_address') or 'n/a')}"


def _http_line(item: dict) -> str:
    return f"{_clean(item.get('method') or 'HTTP')} host={_clean(item.get('host') or 'n/a')} uri={_clean(item.get('uri') or 'n/a')} status={_clean(item.get('response_code') or 'n/a')}"


def _tls_line(item: dict) -> str:
    return f"sni={_clean(item.get('sni') or 'n/a')} version={_clean(item.get('version') or 'n/a')}"


def _clean(value: object) -> str:
    return str(value or "").replace("\n", " ").replace("\r", " ").strip()[:500]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
