from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from app.core.config import get_settings
from app.tools.tshark_runner import TSHARK_FIELDS

EVIDENCE_LIMITATIONS = [
    "A packet observation is not malicious by itself.",
    "A connection is not evidence of compromise by itself.",
    "A DNS query is not evidence of exfiltration by itself.",
    "Retransmission or repeated traffic is not automatically an attack.",
    "Encrypted traffic limits application visibility.",
    "Capture scope and capture time limit what can be observed.",
    "Absence from the capture does not prove absence from the network.",
]
_SENSITIVE_QUERY_KEYS = frozenset({"authorization", "cookie", "password", "passwd", "token", "secret", "api_key", "apikey", "access_key", "session", "sessionid"})


def normalize_tshark_result(result: dict) -> dict:
    settings = get_settings()
    limits = {
        "max_packets_normalized": int(settings.tshark_max_packets_normalized),
        "max_unique_endpoints": int(settings.tshark_max_unique_endpoints),
        "max_conversations": int(settings.tshark_max_conversations),
        "max_dns_observations": int(settings.tshark_max_dns_observations),
        "max_http_observations": int(settings.tshark_max_http_observations),
        "max_tls_observations": int(settings.tshark_max_tls_observations),
    }
    output = str(result.get("output") or "")
    rows, warnings = _parse_tsv(output)
    normalized_rows = rows[: limits["max_packets_normalized"]]
    truncation = {
        "output_truncated": bool(result.get("output_truncated")),
        "packets_truncated": len(rows) > len(normalized_rows),
        "endpoints_truncated": False,
        "conversations_truncated": False,
        "dns_truncated": False,
        "http_truncated": False,
        "tls_truncated": False,
    }

    source_file = _source_file_metadata(result)
    packet_count = len(normalized_rows)
    byte_count = 0
    timestamps: list[float] = []
    protocols: Counter[str] = Counter()
    endpoints: dict[str, dict] = {}
    conversations: dict[tuple, dict] = {}
    dns_observations: list[dict] = []
    http_observations: list[dict] = []
    tls_observations: list[dict] = []

    for row in normalized_rows:
        frame_len = _int_or_none(row.get("frame.len"))
        if frame_len is not None:
            byte_count += frame_len
        timestamp = _float_or_none(row.get("frame.time_epoch"))
        if timestamp is not None:
            timestamps.append(timestamp)
        stack = _split_protocols(row.get("frame.protocols"))
        for protocol in stack:
            protocols[protocol] += 1
        src_ip = _first(row.get("ip.src"), row.get("ipv6.src"))
        dst_ip = _first(row.get("ip.dst"), row.get("ipv6.dst"))
        src_port = _first(row.get("tcp.srcport"), row.get("udp.srcport"))
        dst_port = _first(row.get("tcp.dstport"), row.get("udp.dstport"))
        transport = "tcp" if row.get("tcp.srcport") or row.get("tcp.dstport") else "udp" if row.get("udp.srcport") or row.get("udp.dstport") else ""
        highest_protocol = stack[-1] if stack else ""
        _add_endpoint(endpoints, src_ip, limits["max_unique_endpoints"], truncation)
        _add_endpoint(endpoints, dst_ip, limits["max_unique_endpoints"], truncation)
        _add_conversation(conversations, src_ip, dst_ip, src_port, dst_port, transport, highest_protocol, frame_len, limits["max_conversations"], truncation)
        _add_dns_observation(dns_observations, row, timestamp, src_ip, dst_ip, limits["max_dns_observations"], truncation)
        _add_http_observation(http_observations, row, timestamp, src_ip, dst_ip, limits["max_http_observations"], truncation)
        _add_tls_observation(tls_observations, row, timestamp, src_ip, dst_ip, limits["max_tls_observations"], truncation)

    return {
        "source": "tshark",
        "execution_status": "completed" if result.get("success") is True else "failed",
        "success": bool(result.get("success")),
        "source_file": source_file,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "capture_start": str(min(timestamps)) if timestamps else "",
        "capture_end": str(max(timestamps)) if timestamps else "",
        "observed_protocols": [{"protocol": protocol, "packet_count": count} for protocol, count in protocols.most_common()],
        "observed_endpoints": list(endpoints.values()),
        "observed_conversations": list(conversations.values()),
        "dns_observations": dns_observations,
        "http_observations": http_observations,
        "tls_observations": tls_observations,
        "parser_warnings": warnings,
        "truncation": truncation,
        "limits": limits,
        "evidence_limitations": list(EVIDENCE_LIMITATIONS),
        "error": str(result.get("error") or ""),
        "error_type": result.get("error_type"),
    }


def _parse_tsv(output: str) -> tuple[list[dict[str, str]], list[str]]:
    lines = [line for line in str(output or "").splitlines() if line.strip()]
    if not lines:
        return [], ["No structured TShark rows were available."]
    header = lines[0].split("\t")
    if not set(TSHARK_FIELDS).issubset(set(header)):
        return [], ["Malformed TShark structured output: expected field header was not present."]
    rows = []
    warnings = []
    for line_number, line in enumerate(lines[1:], start=2):
        values = line.split("\t")
        if len(values) != len(header):
            warnings.append(f"Malformed TShark row skipped at line {line_number}.")
            continue
        rows.append(dict(zip(header, values, strict=True)))
    return rows, warnings


def _source_file_metadata(result: dict) -> dict:
    path_text = str(result.get("capture_file") or "")
    metadata = {"path": path_text, "name": Path(path_text).name if path_text else "", "extension": Path(path_text).suffix.lower() if path_text else "", "size_bytes": None}
    try:
        path = Path(path_text)
        if path.is_file():
            metadata["size_bytes"] = path.stat().st_size
    except OSError:
        metadata["size_bytes"] = None
    return metadata


def _split_protocols(value: object) -> list[str]:
    return [item.strip().lower() for item in str(value or "").split(":") if item.strip()]


def _first(*values: object) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value or "").strip())
    except ValueError:
        return None


def _float_or_none(value: object) -> float | None:
    try:
        return float(str(value or "").strip())
    except ValueError:
        return None


def _add_endpoint(endpoints: dict[str, dict], ip_address: str, limit: int, truncation: dict) -> None:
    if not ip_address:
        return
    if ip_address not in endpoints and len(endpoints) >= limit:
        truncation["endpoints_truncated"] = True
        return
    endpoint = endpoints.setdefault(ip_address, {"address": ip_address, "packet_count": 0})
    endpoint["packet_count"] += 1


def _add_conversation(conversations: dict[tuple, dict], src_ip: str, dst_ip: str, src_port: str, dst_port: str, transport: str, protocol: str, frame_len: int | None, limit: int, truncation: dict) -> None:
    if not src_ip or not dst_ip:
        return
    key = (src_ip, dst_ip, src_port, dst_port, transport)
    if key not in conversations and len(conversations) >= limit:
        truncation["conversations_truncated"] = True
        return
    conversation = conversations.setdefault(
        key,
        {
            "src": src_ip,
            "dst": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "transport": transport,
            "highest_protocol": protocol,
            "packet_count": 0,
            "byte_count": 0,
        },
    )
    conversation["packet_count"] += 1
    conversation["byte_count"] += frame_len or 0


def _add_dns_observation(observations: list[dict], row: dict, timestamp: float | None, src_ip: str, dst_ip: str, limit: int, truncation: dict) -> None:
    query_name = _clean(row.get("dns.qry.name"))
    response_name = _clean(row.get("dns.resp.name"))
    response_address = _clean(_first(row.get("dns.a"), row.get("dns.aaaa")))
    if not any((query_name, response_name, response_address)):
        return
    if len(observations) >= limit:
        truncation["dns_truncated"] = True
        return
    observations.append({"timestamp": _timestamp(timestamp), "src": src_ip, "dst": dst_ip, "query_name": query_name, "response_name": response_name, "response_address": response_address})


def _add_http_observation(observations: list[dict], row: dict, timestamp: float | None, src_ip: str, dst_ip: str, limit: int, truncation: dict) -> None:
    method = _clean(row.get("http.request.method"))
    host = _clean(row.get("http.host"))
    uri = _sanitize_uri(row.get("http.request.uri"))
    response_code = _clean(row.get("http.response.code"))
    if not any((method, host, uri, response_code)):
        return
    if len(observations) >= limit:
        truncation["http_truncated"] = True
        return
    observations.append({"timestamp": _timestamp(timestamp), "src": src_ip, "dst": dst_ip, "method": method, "host": host, "uri": uri, "response_code": response_code})


def _add_tls_observation(observations: list[dict], row: dict, timestamp: float | None, src_ip: str, dst_ip: str, limit: int, truncation: dict) -> None:
    sni = _clean(row.get("tls.handshake.extensions_server_name"))
    version = _clean(row.get("tls.handshake.version"))
    if not any((sni, version)):
        return
    if len(observations) >= limit:
        truncation["tls_truncated"] = True
        return
    observations.append({"timestamp": _timestamp(timestamp), "src": src_ip, "dst": dst_ip, "sni": sni, "version": version})


def _timestamp(value: float | None) -> str:
    return str(value) if value is not None else ""


def _clean(value: object, limit: int = 300) -> str:
    return str(value or "").replace("\r", "").replace("\n", " ").strip()[:limit]


def _sanitize_uri(value: object) -> str:
    uri = _clean(value, limit=500)
    if not uri:
        return ""
    try:
        parsed = urlsplit(uri)
        if not parsed.query:
            return uri
        sanitized = []
        for key, query_value in parse_qsl(parsed.query, keep_blank_values=True):
            sanitized.append((key, "<REDACTED>" if key.lower() in _SENSITIVE_QUERY_KEYS else query_value))
        query = "&".join(f"{key}={query_value}" for key, query_value in sanitized)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
    except ValueError:
        return uri[:500]
