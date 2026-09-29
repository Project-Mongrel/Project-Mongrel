import json
from unittest.mock import patch

import pytest

from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.tshark_metasploit_correlation import (
    TRUTHFULNESS_FALLBACK_LINES,
    build_tshark_metasploit_correlated_prompt,
    build_tshark_metasploit_correlation_record,
    generate_tshark_metasploit_correlated_assessment,
)


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _provenance(port: int = 443) -> dict:
    return {
        "user_id": 100,
        "validation_proposal_id": "msf-proposal-1",
        "capture_proposal_id": "cap-proposal-1",
        "target": "example.com",
        "module": "auxiliary/scanner/http/http_version",
        "action": "auxiliary_validation",
        "port": port,
        "capture_started_at": "2026-07-23T10:00:00+00:00",
        "capture_ended_at": "2026-07-23T10:00:05+00:00",
        "validation_started_at": "2026-07-23T10:00:01+00:00",
        "validation_ended_at": "2026-07-23T10:00:02+00:00",
    }


def _metasploit(state: str = "DETECTED") -> dict:
    return {
        "source": "metasploit",
        "module": "auxiliary/scanner/http/http_version",
        "action_type": "auxiliary_validation",
        "target": "example.com",
        "port": 443,
        "validation_state": state,
        "subprocess_success": True,
        "module_executed": True,
        "session_established": state == "SESSION_ESTABLISHED",
        "summary": "Metasploit reported service or version metadata.",
        "evidence_confidence": "tool_reported",
        "raw_evidence_excerpt": "Server: nginx",
        "limitations": [],
    }


def _tshark(*, conversation_port: str = "443", success: bool = True, packet_count: int = 4) -> dict:
    return {
        "source": "tshark",
        "execution_status": "completed" if success else "failed",
        "success": success,
        "packet_count": packet_count,
        "capture_start": "1710000000.1",
        "capture_end": "1710000001.2",
        "observed_protocols": [{"protocol": "tcp", "packet_count": 2}, {"protocol": "tls", "packet_count": 1}, {"protocol": "http", "packet_count": 1}],
        "observed_endpoints": [{"address": "192.0.2.10", "packet_count": 2}, {"address": "93.184.216.34", "packet_count": 2}],
        "observed_conversations": [
            {"src": "192.0.2.10", "dst": "93.184.216.34", "src_port": "53000", "dst_port": conversation_port, "transport": "tcp", "packet_count": 2}
        ],
        "dns_observations": [{"query_name": "example.com", "response_address": "93.184.216.34", "src": "192.0.2.10", "dst": "198.51.100.53"}],
        "http_observations": [{"method": "GET", "host": "example.com", "uri": "/", "response_code": "200", "src": "192.0.2.10", "dst": "93.184.216.34"}],
        "tls_observations": [{"sni": "example.com", "version": "0x0303", "src": "192.0.2.10", "dst": "93.184.216.34"}],
        "parser_warnings": [],
        "truncation": {},
        "evidence_limitations": [],
    }


def _record(provenance=None, metasploit=None, tshark=None) -> dict:
    return build_tshark_metasploit_correlation_record(
        user_id=100,
        assessment_id=7,
        validation_result_id="assessment_artifact:1",
        capture_provenance_id="assessment_artifact:2",
        provenance=provenance or _provenance(),
        metasploit_evidence=metasploit or _metasploit(),
        tshark_evidence=tshark or _tshark(),
    )


def test_exact_target_ip_port_time_aligned_corroboration() -> None:
    record = _record()

    assert record["target_resolved_ips_observed"] == ["93.184.216.34"]
    assert record["tshark"]["relevant_conversations"][0]["dst_port"] == "443"
    assert record["metasploit"]["session_established"] is False
    assert record["correlation_outcome"] == "corroborated"
    assert record["correlation_confidence"] == "high"
    assert "not exploitability" in record["correlation_confidence_meaning"]
    assert record["agreement_disagreement_state"] == "agreement"


def test_partial_corroboration_from_dns_without_expected_port_conversation() -> None:
    tshark = _tshark(conversation_port="8443")

    record = _record(tshark=tshark)

    assert record["correlation_outcome"] == "partially_corroborated"
    assert record["correlation_confidence"] == "medium"
    assert record["agreement_disagreement_state"] == "partial_agreement"


def test_no_matching_packet_evidence_is_not_corroborated() -> None:
    tshark = _tshark()
    tshark["observed_endpoints"] = [{"address": "203.0.113.5", "packet_count": 2}]
    tshark["observed_conversations"] = [{"src": "192.0.2.10", "dst": "203.0.113.5", "src_port": "53000", "dst_port": "443", "transport": "tcp"}]
    tshark["dns_observations"] = []
    tshark["http_observations"] = []
    tshark["tls_observations"] = []

    record = _record(tshark=tshark)

    assert record["correlation_outcome"] == "not_corroborated"
    assert record["agreement_disagreement_state"] == "no_packet_agreement"


def test_failed_capture_is_inconclusive_not_fabricated_support() -> None:
    record = _record(tshark=_tshark(success=False, packet_count=0))

    assert record["correlation_outcome"] == "inconclusive"
    assert record["correlation_confidence"] == "low"
    assert any("failed" in limitation.lower() for limitation in record["limitations"])


def test_failed_validation_is_inconclusive_not_fabricated_support() -> None:
    record = _record(metasploit=_metasploit("FAILED"))

    assert record["correlation_outcome"] == "inconclusive"
    assert record["agreement_disagreement_state"] == "inconclusive"


def test_no_false_tls_handshake_or_http_service_response_claim_in_record_and_prompt() -> None:
    record = _record()
    prompt = build_tshark_metasploit_correlated_prompt(record)

    assert record["tshark"]["tls_handshake_evidence"]["successful_handshake_observed"] is False
    assert record["tshark"]["http_evidence"]["responses"][0]["response_code"] == "200"
    assert "Never claim a successful TLS handshake unless successful_handshake_observed is true." in prompt
    assert "Never claim an HTTP response identified a service unless packet metadata explicitly proves that service identification." in prompt
    assert "Correlation confidence describes attribution to the approved validation, not exploitability confidence." in prompt
    assert "If session_established is false, correlated packets must not be described as shell/session access or exploit success." in prompt


def test_live_shaped_metadata_does_not_authorize_tls_handshake_or_user_attribution_claims() -> None:
    tshark = _tshark()
    tshark["tls_observations"] = [
        {
            "sni": "example.com",
            "version": "0x0303",
            "handshake_success": "not established by stored metadata",
            "src": "192.0.2.10",
            "dst": "93.184.216.34",
        }
    ]
    record = _record(metasploit=_metasploit("DETECTED"), tshark=tshark)
    unsafe_response = "\n".join(
        [
            "Executive Summary",
            "The validation result is supported as evidenced by the observed TLS handshake.",
            "The user initiated several UDP and TCP connections during validation.",
        ]
    )

    with patch("app.services.tshark_metasploit_correlation.ask_ai", return_value=unsafe_response):
        lines = generate_tshark_metasploit_correlated_assessment(record)

    assert lines == TRUTHFULNESS_FALLBACK_LINES
    assert record["tshark"]["tls_handshake_evidence"]["successful_handshake_observed"] is False


def test_process_completion_does_not_become_validation_success_for_detected_state() -> None:
    response = "Executive Summary\nThe validation completed successfully and the target was confirmed."

    with patch("app.services.tshark_metasploit_correlation.ask_ai", return_value=response):
        lines = generate_tshark_metasploit_correlated_assessment(_record(metasploit=_metasploit("DETECTED")))

    assert lines == TRUTHFULNESS_FALLBACK_LINES


@pytest.mark.parametrize(
    "observations, request_count, response_count",
    [
        ([{"method": "GET", "host": "example.com", "uri": "/"}], 1, 0),
        ([{"response_status": "301", "src": "93.184.216.34", "dst": "192.0.2.10"}], 0, 1),
        ([{"method": "GET"}, {"response_code": "301"}, {"method": "HEAD", "response_status": "204"}], 2, 2),
        ([{"host": "example.com", "uri": "/attempted"}, {"src": "192.0.2.10", "dst": "93.184.216.34"}], 0, 0),
    ],
)
def test_current_run_http_evidence_classifies_only_explicit_request_and_response_fields(
    observations: list[dict], request_count: int, response_count: int,
) -> None:
    tshark = _tshark()
    tshark["http_observations"] = observations

    record = _record(tshark=tshark)

    assert len(record["tshark"]["http_evidence"]["requests"]) == request_count
    assert len(record["tshark"]["http_evidence"]["responses"]) == response_count


def test_http_counts_ignore_stale_artifacts_and_validation_http_metadata() -> None:
    tshark = _tshark()
    tshark["http_observations"] = [{"method": "GET"}, {"response_status": "301"}]
    tshark["related_artifacts"] = [{"http_observations": [{"method": "OLD"}] * 9}]
    metasploit = _metasploit()
    metasploit["http_observations"] = [{"response_status": "500"}] * 7

    record = _record(tshark=tshark, metasploit=metasploit)

    assert len(record["tshark"]["http_evidence"]["requests"]) == 1
    assert len(record["tshark"]["http_evidence"]["responses"]) == 1
    assert record["tshark"]["http_evidence"]["responses"][0]["response_status"] == "301"
    with patch("app.services.tshark_metasploit_correlation.ask_ai", return_value="TShark Evidence\n- Address:"):
        rendered = "\n".join(generate_tshark_metasploit_correlated_assessment(record))
    assert "1 request observation(s) and 1 separate response observation(s); response codes: 301" in rendered
    assert "transaction pairing is not established" in rendered


def test_no_metasploit_session_remains_no_session_despite_correlated_packets() -> None:
    record = _record(metasploit=_metasploit("VALIDATED"))

    assert record["correlation_outcome"] == "corroborated"
    assert record["metasploit"]["session_established"] is False
    assert any("not exploitability" in limitation for limitation in record["limitations"])


def test_actual_metasploit_session_evidence_is_preserved() -> None:
    record = _record(metasploit=_metasploit("SESSION_ESTABLISHED"))
    prompt = build_tshark_metasploit_correlated_prompt(record)

    assert record["metasploit"]["state"] == "SESSION_ESTABLISHED"
    assert record["metasploit"]["session_established"] is True
    assert "If session_established is true, packet absence must not downgrade the Metasploit session evidence." in prompt


def test_legitimate_session_evidence_scoped_wording_is_allowed() -> None:
    response = "\n".join(
        [
            "Executive Summary",
            "Metasploit session evidence indicates a session was established.",
            "Correlation confidence describes packet attribution only and does not prove additional compromise.",
        ]
    )

    with patch("app.services.tshark_metasploit_correlation.ask_ai", return_value=response):
        lines = generate_tshark_metasploit_correlated_assessment(_record(metasploit=_metasploit("SESSION_ESTABLISHED")))

    assert lines == response.splitlines()


def test_no_observed_traffic_does_not_prove_no_traffic_occurred() -> None:
    record = _record(tshark=_tshark(packet_count=0))

    assert record["correlation_outcome"] == "not_corroborated"
    assert any("does not prove no traffic occurred" in limitation for limitation in record["limitations"])


def test_ai_prompt_receives_only_structured_current_run_evidence_without_history() -> None:
    record = _record()
    prompt = build_tshark_metasploit_correlated_prompt(record)

    payload = prompt.split("Normalized Current-Run Correlation Record:\n", 1)[1]
    parsed = json.loads(payload)
    assert parsed["schema_version"] == "tshark_metasploit_correlation.v1"
    assert "observed_conversations" not in prompt
    assert "historical" not in payload.lower()
    assert "prior" not in payload.lower()


def test_ai_generation_uses_structured_record() -> None:
    record = _record()
    with patch("app.services.tshark_metasploit_correlation.ask_ai", return_value="Executive Summary\nCorrelated."):
        lines = generate_tshark_metasploit_correlated_assessment(record)

    assert lines == ["Executive Summary", "Correlated."]


def test_truncated_model_field_is_replaced_by_deterministic_assessment() -> None:
    response = "Executive Summary\nObserved packet details follow.\n\nTShark Evidence\n- Address:"

    with patch("app.services.tshark_metasploit_correlation.ask_ai", return_value=response):
        lines = generate_tshark_metasploit_correlated_assessment(_record())

    rendered = "\n".join(lines)
    assert rendered != response
    assert "The normalized current-run capture recorded" in rendered
    assert not rendered.rstrip().endswith("Address:")


def test_deterministic_assessment_bounds_long_endpoint_list_cleanly() -> None:
    tshark = _tshark()
    tshark["observed_endpoints"] = [
        {"address": f"192.0.2.{index}", "packet_count": 1} for index in range(1, 26)
    ]
    record = _record(tshark=tshark)

    with patch("app.services.tshark_metasploit_correlation.ask_ai", return_value="TShark Evidence\n- Address:"):
        rendered = "\n".join(generate_tshark_metasploit_correlated_assessment(record))

    assert "and 13 more" in rendered
    assert "192.0.2.25" not in rendered


@pytest.mark.parametrize(
    "unsafe_response",
    [
        "Executive Summary\nThe exploit succeeded.",
        "Executive Summary\nHigh correlation confidence confirms the exploit worked.",
        "Executive Summary\nThe target was compromised.",
        "Executive Summary\nThe TLS handshake succeeded.",
        "Executive Summary\nThe HTTP transaction completed successfully.",
        "Executive Summary\nA shell was obtained.",
    ],
)
def test_unsupported_correlated_ai_wording_is_withheld(unsafe_response: str) -> None:
    with patch("app.services.tshark_metasploit_correlation.ask_ai", return_value=unsafe_response):
        lines = generate_tshark_metasploit_correlated_assessment(_record())

    assert lines == TRUTHFULNESS_FALLBACK_LINES


def test_legitimate_evidence_scoped_correlated_wording_is_allowed() -> None:
    response = "\n".join(
        [
            "Executive Summary",
            "High correlation confidence indicates attribution between current-run packet metadata and the approved validation target, port, and time window.",
            "This does not establish successful exploitation or compromise.",
        ]
    )

    with patch("app.services.tshark_metasploit_correlation.ask_ai", return_value=response):
        lines = generate_tshark_metasploit_correlated_assessment(_record())

    assert lines == response.splitlines()


def test_packet_absence_contradictions_are_replaced_with_deterministic_current_run_evidence() -> None:
    tshark = _tshark()
    tshark.update(
        {
            "packet_count": 59,
            "byte_count": 6758,
            "observed_protocols": [
                {"protocol": "eth", "packet_count": 59},
                {"protocol": "ip", "packet_count": 40},
                {"protocol": "ipv6", "packet_count": 19},
                {"protocol": "tcp", "packet_count": 30},
                {"protocol": "udp", "packet_count": 20},
                {"protocol": "dns", "packet_count": 10},
                {"protocol": "http", "packet_count": 8},
            ],
            "observed_endpoints": [
                {"address": "192.0.2.10", "packet_count": 20},
                {"address": "2001:db8::10", "packet_count": 10},
                {"address": "93.184.216.34", "packet_count": 29},
            ],
            "observed_conversations": [],
            "dns_observations": [{"query_name": "example.com", "response_address": "93.184.216.34"}],
            "http_observations": [
                {"method": "GET", "host": "example.com", "uri": "/", "src": "192.0.2.10", "dst": "93.184.216.34"},
                {"response_code": "301", "src": "93.184.216.34", "dst": "192.0.2.10"},
            ],
            "tls_observations": [],
        }
    )
    record = _record(metasploit=_metasploit("VALIDATED"), tshark=tshark)
    unsafe_response = "\n".join(
        [
            "Executive Summary",
            "No observed endpoints or ports were found.",
            "No external connections to known HTTP or HTTPS services were detected.",
            "Only eth, ethertype, and ip protocols were observed.",
        ]
    )

    with patch("app.services.tshark_metasploit_correlation.ask_ai", return_value=unsafe_response):
        lines = generate_tshark_metasploit_correlated_assessment(record)

    rendered = "\n".join(lines)
    assert "59 packet(s) / 6758 byte(s)" in rendered
    assert "192.0.2.10" in rendered
    assert "2001:db8::10" in rendered
    assert "TCP" in rendered and "UDP" in rendered and "DNS" in rendered and "HTTP" in rendered
    assert "1 request observation(s) and 1 separate response observation(s); response codes: 301" in rendered
    assert "transaction pairing is not established" in rendered
    assert "No TLS metadata was stored" in rendered
    assert "session established: False" in rendered
    assert "do not establish vulnerability, exploitation, or compromise" in rendered
    assert "No observed endpoints" not in rendered
    assert record["tshark"]["observed_endpoints"][0]["address"] == "192.0.2.10"
