import json
import re
from ipaddress import ip_address

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
    "Executive Summary",
    "Correlated Metasploit and TShark assessment unavailable.",
    "",
    "Metasploit Evidence",
    "Use the stored normalized Metasploit validation evidence.",
    "",
    "TShark Evidence",
    "Use the stored normalized TShark packet metadata evidence.",
    "",
    "Correlation Outcome",
    "No AI correlation narrative was generated.",
    "",
    "Confidence",
    "Inconclusive.",
    "",
    "Limitations",
    "Review the stored correlation artifact for deterministic evidence and limitations.",
    "",
    "Recommended Next Actions",
    "Review the validation result, capture provenance, and packet metadata together.",
]


def build_tshark_metasploit_correlation_record(
    *,
    user_id: int,
    assessment_id: int,
    validation_result_id: str | None,
    capture_provenance_id: str | None,
    provenance: dict,
    metasploit_evidence: dict,
    tshark_evidence: dict,
) -> dict:
    target = _clean(provenance.get("target") or metasploit_evidence.get("target"))
    expected_port = _clean(provenance.get("port") or metasploit_evidence.get("port"))
    target_ips = _target_ips(target, tshark_evidence)
    matching_conversations = _matching_conversations(tshark_evidence, target, target_ips, expected_port)
    dns_evidence = _matching_dns(tshark_evidence, target)
    tls_evidence = _matching_tls(tshark_evidence, target, target_ips)
    http_evidence = _matching_http(tshark_evidence, target, target_ips)
    observed_protocols = _observed_protocols(tshark_evidence)
    observed_endpoint_ports = _observed_endpoint_ports(tshark_evidence, matching_conversations)
    outcome, confidence, agreement_state, limitations = _correlation_outcome(
        provenance=provenance,
        metasploit_evidence=metasploit_evidence,
        tshark_evidence=tshark_evidence,
        target=target,
        expected_port=expected_port,
        target_ips=target_ips,
        matching_conversations=matching_conversations,
        dns_evidence=dns_evidence,
        tls_evidence=tls_evidence,
        http_evidence=http_evidence,
    )
    return {
        "schema_version": "tshark_metasploit_correlation.v1",
        "source": "tshark_metasploit_correlation",
        "user_id": int(user_id),
        "assessment_id": int(assessment_id),
        "validation_proposal_id": _clean(provenance.get("validation_proposal_id")),
        "validation_result_id": _clean(validation_result_id),
        "capture_proposal_id": _clean(provenance.get("capture_proposal_id")),
        "capture_provenance_id": _clean(capture_provenance_id),
        "target_hostname": target,
        "target_resolved_ips_observed": target_ips,
        "expected_port": expected_port,
        "validation_started_at": _clean(provenance.get("validation_started_at")),
        "validation_ended_at": _clean(provenance.get("validation_ended_at")),
        "capture_started_at": _clean(provenance.get("capture_started_at")),
        "capture_ended_at": _clean(provenance.get("capture_ended_at")),
        "metasploit": {
            "module": _clean(metasploit_evidence.get("module") or provenance.get("module")),
            "action": _clean(metasploit_evidence.get("action_type") or provenance.get("action")),
            "state": _clean(metasploit_evidence.get("validation_state")),
            "observed_service_metadata": _metasploit_service_metadata(metasploit_evidence),
        },
        "tshark": {
            "execution_status": _clean(tshark_evidence.get("execution_status")),
            "success": bool(tshark_evidence.get("success")),
            "packet_count": int(tshark_evidence.get("packet_count") or 0),
            "capture_start": _clean(tshark_evidence.get("capture_start")),
            "capture_end": _clean(tshark_evidence.get("capture_end")),
            "relevant_conversations": matching_conversations,
            "observed_endpoints_ports": observed_endpoint_ports,
            "observed_protocols": observed_protocols,
            "dns_evidence": dns_evidence,
            "tcp_connection_evidence": _tcp_evidence(matching_conversations),
            "tls_handshake_evidence": {
                "observations": tls_evidence,
                "successful_handshake_observed": any(item.get("handshake_complete") is True for item in tls_evidence),
            },
            "http_evidence": {
                "requests": [item for item in http_evidence if item.get("method") or item.get("host") or item.get("uri")],
                "responses": [item for item in http_evidence if item.get("response_code")],
            },
        },
        "packet_count": int(tshark_evidence.get("packet_count") or 0),
        "correlation_confidence": confidence,
        "limitations": limitations,
        "correlation_outcome": outcome,
        "agreement_disagreement_state": agreement_state,
    }


def generate_tshark_metasploit_correlated_assessment(correlation_record: dict) -> list[str]:
    prompt = build_tshark_metasploit_correlated_prompt(correlation_record)
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)
    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)
    lines = [line.rstrip() for line in str(response or "").strip().splitlines()]
    return lines or list(FALLBACK_LINES)


def build_tshark_metasploit_correlated_prompt(correlation_record: dict) -> str:
    return "\n".join(
        [
            "You are preparing a correlated assessment for one authorized Metasploit validation and one bounded TShark capture.",
            "",
            "Rules:",
            "- Use only the supplied normalized current-run correlation record.",
            "- Do not use historical findings, prior captures, prior validations, or raw PCAP text.",
            "- Do not claim packets belong to the validation solely because they occurred in the same time window.",
            "- Use hostname, resolved IP, expected port, and timing alignment only as represented in the record.",
            "- Never claim a successful TLS handshake unless successful_handshake_observed is true.",
            "- Never claim an HTTP response identified a service unless packet metadata explicitly proves that service identification.",
            "- Packet evidence must not upgrade Metasploit detection into a vulnerability.",
            "- Failed or missing capture/validation evidence must remain inconclusive or not corroborated.",
            "- Preserve provenance, uncertainty, and limitations.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "Executive Summary",
            "Metasploit Evidence",
            "TShark Evidence",
            "Correlation Outcome",
            "Confidence",
            "Limitations",
            "Recommended Next Actions",
            "",
            "Normalized Current-Run Correlation Record:",
            json.dumps(_bounded_record(correlation_record), sort_keys=True),
        ]
    )


def _correlation_outcome(
    *,
    provenance: dict,
    metasploit_evidence: dict,
    tshark_evidence: dict,
    target: str,
    expected_port: str,
    target_ips: list[str],
    matching_conversations: list[dict],
    dns_evidence: list[dict],
    tls_evidence: list[dict],
    http_evidence: list[dict],
) -> tuple[str, str, str, list[str]]:
    limitations = [
        "Correlation uses only current-run normalized Metasploit evidence, normalized TShark metadata, and capture provenance.",
        "Packet timing alone is not treated as attribution to the validation.",
        "No packet evidence upgrades service detection into vulnerability validation.",
    ]
    if metasploit_evidence.get("validation_state") in {"FAILED", "BLOCKED"} or metasploit_evidence.get("source") != "metasploit":
        limitations.append("Metasploit validation did not complete with usable validation evidence.")
        return "inconclusive", "low", "inconclusive", limitations
    if tshark_evidence.get("success") is not True:
        limitations.append("TShark capture or parsing failed, so packet evidence cannot independently corroborate the validation.")
        return "inconclusive", "low", "inconclusive", limitations
    if int(tshark_evidence.get("packet_count") or 0) <= 0:
        limitations.append("TShark produced no packet metadata for this run.")
        return "not_corroborated", "low", "no_packet_agreement", limitations

    host_aligned = bool(dns_evidence or _matching_host_http_or_tls(target, http_evidence, tls_evidence) or target_ips)
    port_aligned = bool(matching_conversations)
    time_aligned = bool(provenance.get("capture_started_at") and provenance.get("validation_started_at"))

    if host_aligned and port_aligned and time_aligned:
        return "corroborated", "high", "agreement", limitations
    if (host_aligned and (dns_evidence or http_evidence or tls_evidence)) or port_aligned:
        limitations.append("Packet evidence matched only part of the hostname/IP/port/time attribution set.")
        return "partially_corroborated", "medium", "partial_agreement", limitations
    if target_ips and _target_seen_on_other_ports(tshark_evidence, target_ips, expected_port):
        limitations.append("The target IP appeared in packet metadata, but not with the expected validation port.")
        return "not_corroborated", "low", "potential_disagreement", limitations

    limitations.append("No matching hostname/IP/port packet evidence was observed for the validation target.")
    return "not_corroborated", "low", "no_packet_agreement", limitations


def _matching_conversations(evidence: dict, target: str, target_ips: list[str], expected_port: str) -> list[dict]:
    if not expected_port:
        return []
    target_is_ip = _is_ip(target)
    matched = []
    for item in evidence.get("observed_conversations") or []:
        src = _clean(item.get("src"))
        dst = _clean(item.get("dst"))
        if expected_port not in {_clean(item.get("src_port")), _clean(item.get("dst_port"))}:
            continue
        if target_is_ip and target not in {src, dst}:
            continue
        if not target_is_ip and target_ips and src not in target_ips and dst not in target_ips:
            continue
        if not target_is_ip and not target_ips:
            continue
        matched.append(_bounded_item(item))
    return matched[:20]


def _matching_dns(evidence: dict, target: str) -> list[dict]:
    if not target or _is_ip(target):
        return []
    target_name = target.rstrip(".").lower()
    matched = []
    for item in evidence.get("dns_observations") or []:
        names = {_clean(item.get("query_name")).rstrip(".").lower(), _clean(item.get("response_name")).rstrip(".").lower()}
        if target_name in names:
            matched.append(_bounded_item(item))
    return matched[:20]


def _matching_tls(evidence: dict, target: str, target_ips: list[str]) -> list[dict]:
    matched = []
    target_name = target.rstrip(".").lower()
    for item in evidence.get("tls_observations") or []:
        sni = _clean(item.get("sni")).rstrip(".").lower()
        if (target_name and not _is_ip(target) and sni == target_name) or _endpoint_matches(item, target, target_ips):
            matched.append(_bounded_item(item))
    return matched[:20]


def _matching_http(evidence: dict, target: str, target_ips: list[str]) -> list[dict]:
    matched = []
    target_name = target.rstrip(".").lower()
    for item in evidence.get("http_observations") or []:
        host = _clean(item.get("host")).split(":", 1)[0].rstrip(".").lower()
        if (target_name and not _is_ip(target) and host == target_name) or _endpoint_matches(item, target, target_ips):
            matched.append(_bounded_item(item))
    return matched[:20]


def _target_ips(target: str, evidence: dict) -> list[str]:
    observed = set()
    endpoint_addresses = {_clean(item.get("address")) for item in evidence.get("observed_endpoints") or []}
    if _is_ip(target) and target in endpoint_addresses:
        observed.add(target)
    target_name = target.rstrip(".").lower()
    for item in evidence.get("dns_observations") or []:
        query = _clean(item.get("query_name")).rstrip(".").lower()
        response_name = _clean(item.get("response_name")).rstrip(".").lower()
        response_address = _clean(item.get("response_address"))
        if target_name and target_name in {query, response_name} and _is_ip(response_address):
            observed.add(response_address)
    return sorted(ip for ip in observed if ip in endpoint_addresses)


def _observed_protocols(evidence: dict) -> list[str]:
    return [_clean(item.get("protocol")) for item in evidence.get("observed_protocols") or [] if _clean(item.get("protocol"))][:30]


def _observed_endpoint_ports(evidence: dict, conversations: list[dict]) -> list[dict]:
    source = conversations or (evidence.get("observed_conversations") or [])[:20]
    return [
        {
            "src": _clean(item.get("src")),
            "src_port": _clean(item.get("src_port")),
            "dst": _clean(item.get("dst")),
            "dst_port": _clean(item.get("dst_port")),
            "transport": _clean(item.get("transport")),
        }
        for item in source
    ]


def _tcp_evidence(conversations: list[dict]) -> dict:
    return {
        "connections_observed": bool(conversations),
        "conversations": [item for item in conversations if _clean(item.get("transport")).lower() == "tcp"][:20],
    }


def _metasploit_service_metadata(evidence: dict) -> dict:
    excerpt = _clean(evidence.get("raw_evidence_excerpt"), limit=800)
    metadata_lines = []
    for line in re.split(r"[\r\n]+", excerpt):
        clean_line = _clean(line, limit=200)
        if clean_line and any(term in clean_line.lower() for term in ("server", "http/", "https/", "title", "powered by", "version")):
            metadata_lines.append(clean_line)
    return {
        "summary": _clean(evidence.get("summary")),
        "evidence_confidence": _clean(evidence.get("evidence_confidence")),
        "metadata_excerpt": metadata_lines[:10],
    }


def _matching_host_http_or_tls(target: str, http_evidence: list[dict], tls_evidence: list[dict]) -> bool:
    if _is_ip(target):
        return False
    target_name = target.rstrip(".").lower()
    return any(_clean(item.get("host")).split(":", 1)[0].rstrip(".").lower() == target_name for item in http_evidence) or any(
        _clean(item.get("sni")).rstrip(".").lower() == target_name for item in tls_evidence
    )


def _target_seen_on_other_ports(evidence: dict, target_ips: list[str], expected_port: str) -> bool:
    for item in evidence.get("observed_conversations") or []:
        if _clean(item.get("src")) not in target_ips and _clean(item.get("dst")) not in target_ips:
            continue
        if expected_port not in {_clean(item.get("src_port")), _clean(item.get("dst_port"))}:
            return True
    return False


def _endpoint_matches(item: dict, target: str, target_ips: list[str]) -> bool:
    endpoints = {_clean(item.get("src")), _clean(item.get("dst"))}
    if _is_ip(target) and target in endpoints:
        return True
    return bool(target_ips and endpoints.intersection(target_ips))


def _bounded_record(record: dict) -> dict:
    bounded = dict(record)
    if isinstance(bounded.get("tshark"), dict):
        tshark = dict(bounded["tshark"])
        tshark["relevant_conversations"] = (tshark.get("relevant_conversations") or [])[:20]
        tshark["observed_endpoints_ports"] = (tshark.get("observed_endpoints_ports") or [])[:20]
        bounded["tshark"] = tshark
    return bounded


def _bounded_item(item: dict) -> dict:
    return {str(key): _clean(value) if not isinstance(value, (int, bool)) else value for key, value in dict(item).items()}


def _is_ip(value: object) -> bool:
    try:
        ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def _clean(value: object, limit: int = 300) -> str:
    return str(value or "").replace("\r", "").replace("\n", " ").strip()[:limit]


def _is_unavailable_response(response: object) -> bool:
    text = str(response or "").strip()
    return not text or any(text.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
