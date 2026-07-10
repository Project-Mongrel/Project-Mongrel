from unittest.mock import patch

from app.services.tshark_ai_assessment import FALLBACK_LINES, build_tshark_ai_assessment_prompt, generate_tshark_ai_assessment


def _evidence() -> dict:
    return {
        "source": "tshark",
        "execution_status": "completed",
        "source_file": {"name": "capture.pcap"},
        "packet_count": 3,
        "byte_count": 354,
        "capture_start": "1710000000.1",
        "capture_end": "1710000002.3",
        "output": "raw tshark stdout should not appear",
        "observed_protocols": [{"protocol": "dns", "packet_count": 1}, {"protocol": "tls", "packet_count": 1}],
        "observed_endpoints": [{"address": "192.0.2.10", "packet_count": 2}],
        "observed_conversations": [{"src": "192.0.2.10", "dst": "198.51.100.20", "src_port": "53000", "dst_port": "53", "transport": "udp", "packet_count": 1}],
        "dns_observations": [{"query_name": "example.com", "response_address": "93.184.216.34"}],
        "http_observations": [{"method": "GET", "host": "example.com", "uri": "/?token=<REDACTED>", "response_code": "200"}],
        "tls_observations": [{"sni": "tls.example.com", "version": "0x0303"}],
        "parser_warnings": ["one malformed row skipped"],
        "truncation": {"output_truncated": False},
        "evidence_limitations": [
            "A packet observation is not malicious by itself.",
            "A connection is not evidence of compromise by itself.",
            "A DNS query is not evidence of exfiltration by itself.",
            "Encrypted traffic limits application visibility.",
            "Absence from the capture does not prove absence from the network.",
        ],
    }


def test_tshark_ai_prompt_uses_normalized_evidence_only_and_preserves_uncertainty() -> None:
    prompt = build_tshark_ai_assessment_prompt(_evidence())

    assert "Normalized TShark Evidence:" in prompt
    assert "Packet count: 3" in prompt
    assert "dns packets=1" in prompt
    assert "query=example.com response=93.184.216.34" in prompt
    assert "sni=tls.example.com version=0x0303" in prompt
    assert "raw tshark stdout should not appear" not in prompt
    assert "Packets are observations, not attacks." in prompt
    assert "A connection is not compromise." in prompt
    assert "A DNS query is not exfiltration." in prompt
    assert "Encrypted traffic limits visibility." in prompt
    assert "Absence from a capture proves nothing" in prompt


def test_tshark_ai_prompt_excludes_sensitive_fields() -> None:
    prompt = build_tshark_ai_assessment_prompt(_evidence()).lower()

    assert "authorization" in prompt
    assert "cookies" in prompt
    assert "secret" in prompt
    assert "packet bodies" in prompt
    assert "raw hex" in prompt
    assert "secret-value" not in prompt
    assert "password=" not in prompt


def test_tshark_ai_assessment_success_and_fallback() -> None:
    response = "Executive Summary\nOffline PCAP metadata reviewed."
    with patch("app.services.tshark_ai_assessment.ask_ai", return_value=response):
        assert generate_tshark_ai_assessment(_evidence()) == response.splitlines()

    with patch("app.services.tshark_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_tshark_ai_assessment(_evidence()) == FALLBACK_LINES
