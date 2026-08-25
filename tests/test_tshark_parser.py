from unittest.mock import patch

from app.core.config import Settings
from app.parsers.tshark_parser import normalize_tshark_result
from app.tools.tshark_runner import TSHARK_FIELDS


def _tsv(rows: list[dict[str, str]]) -> str:
    lines = ["\t".join(TSHARK_FIELDS)]
    for row in rows:
        lines.append("\t".join(row.get(field, "") for field in TSHARK_FIELDS))
    return "\n".join(lines)


def _result(output: str, capture_file: str = "sample.pcap") -> dict:
    return {"success": True, "capture_file": capture_file, "output": output, "output_truncated": False}


def test_tshark_parser_normalizes_ipv4_ipv6_dns_http_and_tls(tmp_path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    output = _tsv(
        [
            {
                "frame.time_epoch": "1710000000.1",
                "frame.len": "74",
                "frame.protocols": "eth:ethertype:ip:udp:dns",
                "ip.src": "192.0.2.10",
                "ip.dst": "8.8.8.8",
                "udp.srcport": "53000",
                "udp.dstport": "53",
                "dns.qry.name": "example.com",
                "dns.a": "93.184.216.34",
            },
            {
                "frame.time_epoch": "1710000001.2",
                "frame.len": "120",
                "frame.protocols": "eth:ethertype:ip:tcp:http",
                "ip.src": "192.0.2.10",
                "ip.dst": "198.51.100.20",
                "tcp.srcport": "51000",
                "tcp.dstport": "80",
                "http.request.method": "GET",
                "http.host": "example.com",
                "http.request.uri": "/login?token=secret-value&next=/",
                "http.response.code": "200",
            },
            {
                "frame.time_epoch": "1710000002.3",
                "frame.len": "160",
                "frame.protocols": "eth:ethertype:ipv6:tcp:tls",
                "ipv6.src": "2001:db8::1",
                "ipv6.dst": "2001:db8::2",
                "tcp.srcport": "52000",
                "tcp.dstport": "443",
                "tls.handshake.extensions_server_name": "tls.example.com",
                "tls.handshake.version": "0x0303",
            },
        ]
    )

    normalized = normalize_tshark_result(_result(output, str(capture)))

    assert normalized["execution_status"] == "completed"
    assert normalized["source_file"]["name"] == "sample.pcapng"
    assert normalized["packet_count"] == 3
    assert normalized["byte_count"] == 354
    assert normalized["capture_start"] == "1710000000.1"
    assert normalized["capture_end"] == "1710000002.3"
    assert {"address": "192.0.2.10", "packet_count": 2} in normalized["observed_endpoints"]
    assert {"address": "2001:db8::1", "packet_count": 1} in normalized["observed_endpoints"]
    assert any(protocol["protocol"] == "dns" for protocol in normalized["observed_protocols"])
    assert normalized["dns_observations"][0]["query_name"] == "example.com"
    assert normalized["dns_observations"][0]["response_address"] == "93.184.216.34"
    assert normalized["http_observations"][0]["method"] == "GET"
    assert normalized["http_observations"][0]["uri"] == "/login?token=<REDACTED>&next=/"
    assert "secret-value" not in str(normalized)
    assert normalized["tls_observations"][0]["sni"] == "tls.example.com"
    assert normalized["tls_observations"][0]["version"] == "0x0303"
    assert "A DNS query is not evidence of exfiltration by itself." in normalized["evidence_limitations"]
    assert "A DNS response in a capture is not permanent ownership or authoritative mapping proof." in normalized["evidence_limitations"]
    assert "TCP packets or conversations do not prove completed connections, application success, exploit success, or compromise by themselves." in normalized["evidence_limitations"]
    assert "TLS SNI/version metadata does not prove a successful TLS handshake by itself." in normalized["evidence_limitations"]
    assert "HTTP request metadata without a response code is not a completed HTTP transaction." in normalized["evidence_limitations"]
    assert "Absence from the capture does not prove absence from the network." in normalized["evidence_limitations"]


def test_tshark_parser_malformed_structured_output_records_warning() -> None:
    normalized = normalize_tshark_result(_result("not\tthe\texpected\theader\n1\t2\t3\t4"))

    assert normalized["packet_count"] == 0
    assert normalized["parser_warnings"] == ["Malformed TShark structured output: expected field header was not present."]


def test_tshark_parser_records_truncation_flags() -> None:
    rows = [
        {
            "frame.time_epoch": str(1710000000 + index),
            "frame.len": "64",
            "frame.protocols": "eth:ethertype:ip:tcp:http",
            "ip.src": f"192.0.2.{index}",
            "ip.dst": f"198.51.100.{index}",
            "tcp.srcport": str(50000 + index),
            "tcp.dstport": "80",
            "http.request.method": "GET",
            "http.host": f"host{index}.example",
            "http.request.uri": "/",
        }
        for index in range(5)
    ]
    settings = Settings(
        _env_file=None,
        tshark_max_packets_normalized=3,
        tshark_max_unique_endpoints=2,
        tshark_max_conversations=2,
        tshark_max_http_observations=2,
    )

    with patch("app.parsers.tshark_parser.get_settings", return_value=settings):
        normalized = normalize_tshark_result({"success": True, "capture_file": "sample.pcap", "output": _tsv(rows), "output_truncated": True})

    assert normalized["packet_count"] == 3
    assert normalized["truncation"]["output_truncated"] is True
    assert normalized["truncation"]["packets_truncated"] is True
    assert normalized["truncation"]["endpoints_truncated"] is True
    assert normalized["truncation"]["conversations_truncated"] is True
    assert normalized["truncation"]["http_truncated"] is True
    assert len(normalized["observed_endpoints"]) == 2
    assert len(normalized["observed_conversations"]) == 2
    assert len(normalized["http_observations"]) == 2


def test_tshark_parser_does_not_store_sensitive_header_or_payload_fields() -> None:
    output = _tsv(
        [
            {
                "frame.time_epoch": "1710000000.1",
                "frame.len": "100",
                "frame.protocols": "eth:ethertype:ip:tcp:http",
                "ip.src": "192.0.2.10",
                "ip.dst": "198.51.100.20",
                "http.request.method": "GET",
                "http.host": "example.com",
                "http.request.uri": "/?password=secret",
            }
        ]
    )

    normalized = normalize_tshark_result(_result(output))

    assert "http.authorization" not in str(normalized).lower()
    assert "cookie" not in str(normalized).lower()
    assert "payload" not in str(normalized).lower()
    assert "secret" not in str(normalized).lower()
    assert "<REDACTED>" in str(normalized)
