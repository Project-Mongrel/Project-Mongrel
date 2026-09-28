import json
from unittest.mock import patch

import pytest

from app.bot.handlers.upload import _persist_tshark_assessment_evidence
from app.services.assessment_map_ingestion import AssessmentMapIngestionError, ingest_assessment_scan
from app.services.assessment_map_retrieval import build_assessment_map_context
from app.services.assessment_map_store import AssessmentMapScopeError
from app.services.assessment_store import add_assessment_artifact, create_assessment, record_assessment_scan
from app.services.findings_store import _get_connection, close_findings_database, configure_findings_database


SECRET = "AKIA1234567890ABCDEF"


@pytest.fixture(autouse=True)
def isolated_database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _rows(table: str) -> list[dict]:
    return [dict(row) for row in _get_connection().execute(f"SELECT * FROM {table}").fetchall()]


def _tshark_evidence(*, success: bool = True, secret_uri: bool = False) -> dict:
    uri = "/login?token=<REDACTED>&page=home" if secret_uri else "/login?page=home"
    return {
        "source": "tshark",
        "execution_status": "completed" if success else "failed",
        "success": success,
        "source_file": {"name": "capture.pcap", "extension": ".pcap", "size_bytes": 128},
        "packet_count": 3,
        "byte_count": 240,
        "capture_start": "1.0",
        "capture_end": "3.0",
        "observed_protocols": [{"protocol": "eth", "packet_count": 3}, {"protocol": "tcp", "packet_count": 2}],
        "observed_endpoints": [{"address": "192.0.2.10", "packet_count": 2}, {"address": "198.51.100.20", "packet_count": 1}],
        "observed_conversations": [{
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "src_port": "51514",
            "dst_port": "443",
            "transport": "tcp",
            "highest_protocol": "tls",
            "packet_count": 2,
            "byte_count": 160,
        }],
        "dns_observations": [{
            "timestamp": "1.1",
            "src": "192.0.2.10",
            "dst": "198.51.100.53",
            "query_name": "example.com",
            "response_name": "example.com",
            "response_address": "198.51.100.20",
        }],
        "http_observations": [{
            "timestamp": "1.2",
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "method": "GET",
            "host": "example.com",
            "uri": uri,
            "response_code": "403",
        }],
        "tls_observations": [{
            "timestamp": "1.3",
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "sni": "example.com",
            "version": "0x0303",
        }],
        "truncation": {},
        "evidence_limitations": [
            "A packet observation is not malicious by itself.",
            "TLS SNI/version metadata does not prove a successful TLS handshake by itself.",
        ],
    }


def _scan_with_tshark_artifact(user_id: int, assessment_id: int, evidence: dict) -> dict:
    status = "completed" if evidence.get("success") is not False else "failed"
    scan = record_assessment_scan(assessment_id, tool="tshark", status=status, raw_reference="assessment_artifact:tshark_normalized_evidence")
    add_assessment_artifact(
        assessment_id,
        scan_id=scan["id"],
        artifact_type="tshark_normalized_evidence",
        title="TShark normalized PCAP evidence",
        content=json.dumps(evidence, sort_keys=True),
    )
    return scan


def test_tshark_maps_packet_flows_dns_http_tls_without_security_upgrade() -> None:
    assessment = create_assessment("TShark map", user_id=9201)
    scan = _scan_with_tshark_artifact(9201, assessment["id"], _tshark_evidence())

    ledger = ingest_assessment_scan(user_id=9201, assessment_id=assessment["id"], scan_id=scan["id"])

    entities = _rows("assessment_map_entities")
    assertions = _rows("assessment_map_assertions")
    evidence = _rows("assessment_map_evidence_links")
    serialized = json.dumps({"entities": entities, "assertions": assertions})
    assert ledger["status"] == "complete"
    assert {row["entity_type"] for row in entities} >= {"ip", "service", "hostname", "finding"}
    assert {row["predicate"] for row in assertions} >= {
        "observed_network_flow_to",
        "observed_port_traffic",
        "observed_dns_query",
        "observed_dns_response_address",
        "observed_http_host",
        "observed_tls_sni",
        "observed_tls_version_field",
    }
    assert any(row["evidence_path"] == "artifacts[1].observed_conversations[0].dst" for row in evidence)
    assert "successful_handshake" not in serialized.lower()
    assert "compromise" not in serialized.lower()
    assert "exploit" not in serialized.lower()


def test_tshark_authoritative_capture_summary_is_retained_in_map() -> None:
    assessment = create_assessment("TShark capture summary", user_id=9208)
    evidence = _tshark_evidence()
    evidence.update({"packet_count": 2055, "byte_count": 7067089, "duration_seconds": 19.9})
    scan = _scan_with_tshark_artifact(9208, assessment["id"], evidence)

    ingest_assessment_scan(user_id=9208, assessment_id=assessment["id"], scan_id=scan["id"])

    summary_values: dict[str, list[object]] = {}
    for row in _rows("assessment_map_assertions"):
        if row["predicate"] in {"has_packet_count", "has_byte_count", "has_capture_duration_seconds"}:
            summary_values.setdefault(row["predicate"], []).append(json.loads(row["normalized_value_json"]))
    assert 2055 in summary_values["has_packet_count"]
    assert 7067089 in summary_values["has_byte_count"]
    assert 19.9 in summary_values["has_capture_duration_seconds"]


def test_tshark_secret_bearing_http_uri_is_not_mapped() -> None:
    assessment = create_assessment("TShark secret URI", user_id=9202)
    scan = _scan_with_tshark_artifact(9202, assessment["id"], _tshark_evidence(secret_uri=True))

    ingest_assessment_scan(user_id=9202, assessment_id=assessment["id"], scan_id=scan["id"])

    serialized = json.dumps({"entities": _rows("assessment_map_entities"), "assertions": _rows("assessment_map_assertions")})
    assert SECRET not in serialized
    assert "token=" not in serialized.lower()


def test_tshark_failed_capture_with_observations_remains_bounded_evidence() -> None:
    assessment = create_assessment("TShark partial", user_id=9207)
    evidence = _tshark_evidence(success=False)
    evidence["execution_status"] = "failed"
    evidence["error_type"] = "timeout"
    scan = _scan_with_tshark_artifact(9207, assessment["id"], evidence)

    ledger = ingest_assessment_scan(user_id=9207, assessment_id=assessment["id"], scan_id=scan["id"])

    assertions = _rows("assessment_map_assertions")
    values = [json.loads(row["normalized_value_json"]) for row in assertions if row["normalized_value_json"] is not None]
    assert ledger["status"] == "complete"
    assert "failed" in values
    assert "successful" not in json.dumps(values).lower()


def test_tshark_correlation_requires_explicit_correlation_artifact() -> None:
    assessment = create_assessment("TShark correlation", user_id=9203)
    scan = _scan_with_tshark_artifact(9203, assessment["id"], _tshark_evidence())
    ingest_assessment_scan(user_id=9203, assessment_id=assessment["id"], scan_id=scan["id"])
    assert not any(row["predicate"] == "has_correlation_confidence" for row in _rows("assessment_map_assertions"))

    add_assessment_artifact(
        assessment["id"],
        scan_id=scan["id"],
        artifact_type="tshark_metasploit_correlation_record",
        title="TShark and Metasploit correlation record",
        content=json.dumps({
            "source": "tshark_metasploit_correlation",
            "schema_version": "tshark_metasploit_correlation.v1",
            "validation_proposal_id": "msf-proposal-1",
            "validation_result_id": "assessment_artifact:11",
            "capture_proposal_id": "capture-proposal-1",
            "capture_provenance_id": "assessment_artifact:12",
            "target_hostname": "example.com",
            "expected_port": "443",
            "correlation_confidence": "high",
            "correlation_confidence_meaning": "Confidence describes attribution only, not exploitability or compromise.",
            "correlation_outcome": "corroborated",
            "agreement_disagreement_state": "agreement",
            "tshark": {"relevant_conversations": [{"src": "192.0.2.10", "dst": "198.51.100.20", "dst_port": "443"}]},
        }, sort_keys=True),
    )

    ingest_assessment_scan(user_id=9203, assessment_id=assessment["id"], scan_id=scan["id"])

    assertions = _rows("assessment_map_assertions")
    assert any(row["predicate"] == "has_correlation_confidence" for row in assertions)
    assert any(row["predicate"] == "has_correlation_confidence_meaning" for row in assertions)
    assert not any("exploitability" in row["predicate"].lower() for row in assertions)


def test_tshark_mapping_enforces_owner_and_assessment_scope() -> None:
    owned = create_assessment("Owned TShark", user_id=9204)
    other = create_assessment("Other TShark", user_id=9204)
    scan = _scan_with_tshark_artifact(9204, owned["id"], _tshark_evidence())

    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=9999, assessment_id=owned["id"], scan_id=scan["id"])
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=9204, assessment_id=other["id"], scan_id=scan["id"])


def test_tshark_assessment_persistence_wires_nonfatal_map_ingestion() -> None:
    assessment = create_assessment("TShark live mapping hook", user_id=9205)
    context = {"assessment_id": assessment["id"], "user_id": 9205}

    with patch("app.bot.handlers.upload.ingest_assessment_scan", side_effect=AssessmentMapIngestionError("synthetic mapper failure")) as ingest:
        scan = _persist_tshark_assessment_evidence(
            context,
            {"success": True, "elapsed_seconds": 1.0},
            _tshark_evidence(),
        )

    assert scan["tool"] == "tshark"
    ingest.assert_called_once_with(user_id=9205, assessment_id=assessment["id"], scan_id=scan["id"])


def test_ask_map_retrieval_contains_bounded_tshark_and_correlation_provenance() -> None:
    assessment = create_assessment("Ask TShark map", user_id=9206)
    scan = _scan_with_tshark_artifact(9206, assessment["id"], _tshark_evidence())
    add_assessment_artifact(
        assessment["id"],
        scan_id=scan["id"],
        artifact_type="tshark_metasploit_correlation_record",
        title="TShark and Metasploit correlation record",
        content=json.dumps({
            "source": "tshark_metasploit_correlation",
            "target_hostname": "example.com",
            "correlation_confidence": "medium",
            "correlation_confidence_meaning": "Attribution confidence only; not exploit confidence.",
            "correlation_outcome": "partially_corroborated",
        }, sort_keys=True),
    )
    ingest_assessment_scan(user_id=9206, assessment_id=assessment["id"], scan_id=scan["id"])

    context = build_assessment_map_context(
        user_id=9206,
        assessment_id=assessment["id"],
        question="What packet and correlation evidence is mapped?",
        entity_limit=8,
        relationship_limit=10,
        max_chars=2600,
    )

    rendered = json.dumps(context, sort_keys=True)
    assert context["available"] is True
    assert "tshark" in rendered.lower()
    assert "correlation" in rendered.lower()
    assert "exploit confidence" in rendered.lower()
    assert SECRET not in rendered
    assert len(rendered) <= 2600
