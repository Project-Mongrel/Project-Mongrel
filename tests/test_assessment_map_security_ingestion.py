import json

import pytest

from app.parsers.nuclei_parser import parse_nuclei_results
from app.parsers.testssl_parser import normalize_testssl_output
from app.services import assessment_map_ingestion
from app.services.assessment_map_ingestion import ingest_assessment_scan
from app.services.assessment_map_store import AssessmentMapScopeError
from app.services.assessment_store import add_assessment_artifact, create_assessment, record_assessment_scan
from app.services.findings_store import (
    _get_connection, add_finding, close_findings_database, configure_findings_database,
)


@pytest.fixture(autouse=True)
def isolated_database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _scan(user_id, assessment_id, tool, finding, status="completed"):
    stored = add_finding(user_id, finding) if finding is not None else None
    return record_assessment_scan(
        assessment_id, tool=tool, status=status,
        finding_id=stored["id"] if stored else None,
    )


def _rows(table):
    return [dict(row) for row in _get_connection().execute(f"SELECT * FROM {table}").fetchall()]


def _keys(table):
    return "\n".join(row["canonical_key"] for row in _rows(table))


def _replace_finding(finding_id, data):
    with _get_connection():
        _get_connection().execute(
            "UPDATE findings SET data_json = ? WHERE id = ?", (json.dumps(data), finding_id)
        )


def _nuclei_finding(records):
    return {"source": "nuclei", "target": "https://input.example", "nuclei_findings": records}


def _testssl_finding(evidence):
    return {"source": "testssl", "target": evidence.get("target"), "testssl_evidence": evidence}


def test_actual_nuclei_parser_shape_maps_template_matcher_surface_and_info_severity() -> None:
    assessment = create_assessment("Nuclei", user_id=500)
    records = parse_nuclei_results(
        '{"template-id":"weak-hsts","matcher-name":"header","type":"http",'
        '"info":{"name":"Weak HSTS","severity":"info","tags":["http","tls"],'
        '"reference":["https://docs.example/ref?token=secret#fragment"]},'
        '"host":"https://input.example","matched-at":"https://user:pw@example.com/Login?q=secret#frag"}'
    )
    scan = _scan(500, assessment["id"], "nuclei", _nuclei_finding(records))
    ledger = ingest_assessment_scan(user_id=500, assessment_id=assessment["id"], scan_id=scan["id"])
    entities = _rows("assessment_map_entities")
    predicates = {row["predicate"] for row in _rows("assessment_map_assertions")}
    combined = _keys("assessment_map_entities") + _keys("assessment_map_assertions")
    assert ledger["status"] == "complete"
    assert {row["entity_type"] for row in entities} == {"endpoint", "finding"}
    assert {"finding_affects", "has_template_id", "has_matcher", "has_scanner_severity", "has_tag", "has_reference"} <= predicates
    assert '"value":"info"' in combined and '"path":"/Login"' in combined
    finding_payload = json.loads(next(row["canonical_key"] for row in entities if row["entity_type"] == "finding"))["payload"]
    assert finding_payload["stable_id"] == "weak-hsts" and finding_payload["matcher"] == "header"
    assert finding_payload["affected_surface_type"] == "endpoint"
    assert all(secret not in combined for secret in ("user:pw", "secret", "fragment", "frag"))


def test_actual_nuclei_tcp_match_creates_service_surface() -> None:
    assessment = create_assessment("Nuclei service", user_id=515)
    records = parse_nuclei_results(
        '{"template-id":"ssh-detect","type":"tcp","matcher-name":"banner",'
        '"info":{"name":"SSH Detect","severity":"info"},"matched":"example.com:22"}'
    )
    scan = _scan(515, assessment["id"], "nuclei", _nuclei_finding(records))
    ingest_assessment_scan(user_id=515, assessment_id=assessment["id"], scan_id=scan["id"])
    entities = _rows("assessment_map_entities")
    assert {row["entity_type"] for row in entities} == {"service", "finding"}
    service = next(row for row in entities if row["entity_type"] == "service")
    assert json.loads(service["canonical_key"])["payload"]["port"] == 22


def test_nuclei_explicit_host_ip_ipv6_and_host_port_surfaces_remain_bounded() -> None:
    assessment = create_assessment("Nuclei network surfaces", user_id=516)
    scan = _scan(516, assessment["id"], "nuclei", _nuclei_finding([
        {"template_id": "host", "severity": "info", "matched_at": "Example.COM",
         "matched_surface_source": "matched"},
        {"template_id": "ipv4", "severity": "info", "matched_at": "192.0.2.10",
         "matched_surface_source": "matched"},
        {"template_id": "ipv6", "severity": "info", "matched_at": "2001:db8::10",
         "matched_surface_source": "matched"},
        {"template_id": "host-port", "severity": "info", "matched_at": "example.com:8443",
         "matched_surface_source": "matched"},
        {"template_id": "udp-service", "severity": "info", "template_type": "udp",
         "matched_at": "[2001:db8::20]:161", "matched_surface_source": "matched"},
    ]))
    ingest_assessment_scan(user_id=516, assessment_id=assessment["id"], scan_id=scan["id"])
    entities = _rows("assessment_map_entities")
    assertions = _keys("assessment_map_assertions")
    service_payloads = [
        json.loads(row["canonical_key"])["payload"] for row in entities if row["entity_type"] == "service"
    ]
    assert {row["entity_type"] for row in entities} >= {"hostname", "ip", "service", "finding"}
    assert any(
        payload["port"] == 161 and payload["transport"] == "udp" and "2001:db8::20" in payload["host_key"]
        for payload in service_payloads
    )
    assert '"predicate":"has_observed_port"' in assertions and '"value":8443' in assertions
    assert not any(payload.get("port") == 8443 for payload in service_payloads)


def test_nuclei_references_and_tags_are_strictly_sanitized() -> None:
    assessment = create_assessment("Nuclei refs", user_id=517)
    scan = _scan(517, assessment["id"], "nuclei", _nuclei_finding([
        {
            "template_id": "refs", "severity": "info", "matched_at": "https://example.com",
            "matched_surface_source": "matched-at",
            "tags": [
                "http", "tls_1.2", "cve-2024", {"name": "secret"}, "token=secret",
                "https://bad.example/tag", "frag#secret", "api-key", "bad tag!",
            ],
            "references": [
                "CVE-2024-12345", "cwe-79", "GHSA-abcd-efgh-ijkl",
                "https://docs.example/path?token=secret#frag", "mailto:admin@example.com",
                "internal note token=secret", {"url": "https://bad.example"},
            ],
        }
    ]))
    ledger = ingest_assessment_scan(user_id=517, assessment_id=assessment["id"], scan_id=scan["id"])
    combined = _keys("assessment_map_assertions")
    skipped = json.loads(ledger["metadata_json"])["skipped_optional_records"]
    assert "CVE-2024-12345" in combined and "CWE-79" in combined and "GHSA-ABCD-EFGH-IJKL" in combined
    assert "http" in combined and "tls_1.2" in combined and "cve-2024" in combined
    assert "docs.example" in combined
    assert all(
        secret not in combined
        for secret in ("token=secret", "api-key", "frag#secret", "bad tag!", "mailto", "internal note", "bad.example")
    )
    assert skipped == {"unsupported_nuclei_tag": 6, "unsupported_nuclei_reference": 3}


def test_nuclei_input_only_record_is_not_a_matched_finding_and_valid_sibling_survives() -> None:
    assessment = create_assessment("Nuclei boundary", user_id=501)
    scan = _scan(501, assessment["id"], "nuclei", _nuclei_finding([
        {"template_id": "input-only", "severity": "info", "host": "https://input.example"},
        {"template_id": "legacy", "severity": "info", "matched_at": "https://legacy.example"},
        {"template_id": "matched", "severity": "low", "matched_at": "https://example.com/observed",
         "matched_surface_source": "matched-at"},
    ]))
    ledger = ingest_assessment_scan(user_id=501, assessment_id=assessment["id"], scan_id=scan["id"])
    assert ledger["status"] == "complete"
    assert "input-only" not in _keys("assessment_map_entities")
    assert "matched" in _keys("assessment_map_entities")
    assert json.loads(ledger["metadata_json"])["skipped_optional_records"] == {"unsupported_nuclei_match": 2}


def test_nuclei_reuses_finding_identity_but_keeps_scan_provenance() -> None:
    assessment = create_assessment("Nuclei repeated", user_id=502)
    record = {"template_id": "tech-detect", "matcher_name": "body", "severity": "info",
              "matched_at": "https://example.com/", "matched_surface_source": "matched-at"}
    first = _scan(502, assessment["id"], "nuclei", _nuclei_finding([record]))
    second = _scan(502, assessment["id"], "nuclei", _nuclei_finding([record]))
    one = ingest_assessment_scan(user_id=502, assessment_id=assessment["id"], scan_id=first["id"])
    two = ingest_assessment_scan(user_id=502, assessment_id=assessment["id"], scan_id=second["id"])
    findings = [row for row in _rows("assessment_map_entities") if row["entity_type"] == "finding"]
    assert len(findings) == 1
    assert one["entity_count"] == two["entity_count"]
    assert {row["scan_id"] for row in _rows("assessment_map_evidence_links")} == {first["id"], second["id"]}


TESTSSL_JSON = """
[
  {"id":"cert_commonName","severity":"INFO","finding":"example.com"},
  {"id":"cert_issuer","severity":"INFO","finding":"Example CA"},
  {"id":"cert_subjectAltName","severity":"INFO","finding":"DNS:example.com, DNS:www.example.com"},
  {"id":"cert_fingerprintSHA256","severity":"INFO","finding":"aaaa:aaaa aaaa-aaaa aaaa:aaaa aaaa-aaaa aaaa:aaaa aaaa-aaaa aaaa:aaaa aaaa-aaaa"},
  {"id":"TLS1","severity":"LOW","finding":"offered"},
  {"id":"TLS1_2","severity":"OK","finding":"offered"},
  {"id":"heartbleed","severity":"OK","finding":"not vulnerable"},
  {"id":"cipherlist_NULL","severity":"HIGH","finding":"NULL ciphers not offered"},
  {"id":"HSTS","severity":"INFO","finding":"max-age=31536000"}
]
"""


def test_actual_testssl_shape_maps_host_service_observations_and_issue_boundary() -> None:
    assessment = create_assessment("testssl", user_id=503)
    evidence = normalize_testssl_output(TESTSSL_JSON, target="example.com:443")
    scan = _scan(503, assessment["id"], "testssl", _testssl_finding(evidence))
    ledger = ingest_assessment_scan(user_id=503, assessment_id=assessment["id"], scan_id=scan["id"])
    entities = _rows("assessment_map_entities")
    assertions = _rows("assessment_map_assertions")
    finding_keys = "\n".join(row["canonical_key"] for row in entities if row["entity_type"] == "finding")
    assert ledger["status"] == "complete"
    assert {row["entity_type"] for row in entities} >= {"hostname", "service", "finding"}
    assert {"exposes_service", "has_protocol_observation", "has_cipher_observation",
            "has_header_observation", "has_certificate_sha256", "finding_affects"} <= {
        row["predicate"] for row in assertions
    }
    assert "TLS1" in finding_keys
    assert "heartbleed" not in finding_keys and "cipherlist_NULL" not in finding_keys
    assert not any("safe" in row["predicate"] for row in assertions)
    evidence_paths = {row["evidence_path"] for row in _rows("assessment_map_evidence_links")}
    assert "finding.testssl_evidence.protocols[0].id" in evidence_paths
    assert "finding.testssl_evidence.protocols[0].finding" in evidence_paths
    assert "finding.testssl_evidence.protocols[0].severity" in evidence_paths
    metadata = json.loads(ledger["metadata_json"])
    coverage = metadata["sources"][0]["coverage"]
    assert coverage["notable_record_count"] == 0
    assert coverage["certificate_observation_count"] == 4
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in _keys("assessment_map_assertions")


def test_testssl_issue_polarity_uses_record_identity_not_free_text_guessing() -> None:
    assessment = create_assessment("testssl polarity", user_id=518)
    evidence = normalize_testssl_output(
        json.dumps([
            {"id": "secure_renego", "severity": "HIGH", "finding": "not supported"},
            {"id": "heartbleed", "severity": "HIGH", "finding": "false"},
            {"id": "robot", "severity": "HIGH", "finding": "false but potentially vulnerable"},
            {"id": "ticketbleed", "severity": "HIGH", "finding": "disabled"},
            {"id": "drown", "severity": "HIGH", "finding": "passed; vulnerable check not triggered"},
            {"id": "fake_warn", "severity": "HIGH", "finding": "enabled"},
            {"id": "HSTS", "severity": "HIGH", "finding": "enabled"},
        ]),
        target="example.com:443",
    )
    scan = _scan(518, assessment["id"], "testssl", _testssl_finding(evidence))
    ingest_assessment_scan(user_id=518, assessment_id=assessment["id"], scan_id=scan["id"])
    finding_keys = "\n".join(
        row["canonical_key"] for row in _rows("assessment_map_entities") if row["entity_type"] == "finding"
    )
    assert "secure_renego" in finding_keys
    assert all(
        item not in finding_keys
        for item in ("heartbleed", "robot", "ticketbleed", "drown", "fake_warn", "HSTS")
    )


@pytest.mark.parametrize(("target", "expected_port"), [("example.com", 443), ("example.com:8443", 8443)])
def test_testssl_default_and_explicit_ports(target, expected_port) -> None:
    assessment = create_assessment("TLS ports", user_id=504)
    evidence = normalize_testssl_output('[{"id":"TLS1_2","severity":"OK","finding":"offered"}]', target=target)
    scan = _scan(504, assessment["id"], "testssl", _testssl_finding(evidence))
    ingest_assessment_scan(user_id=504, assessment_id=assessment["id"], scan_id=scan["id"])
    service = next(row for row in _rows("assessment_map_entities") if row["entity_type"] == "service")
    assert json.loads(service["canonical_key"])["payload"]["port"] == expected_port


def test_testssl_certificate_names_do_not_create_ownership_entities() -> None:
    assessment = create_assessment("TLS certificate", user_id=505)
    evidence = normalize_testssl_output(TESTSSL_JSON, target="192.0.2.20:443")
    scan = _scan(505, assessment["id"], "testssl", _testssl_finding(evidence))
    ingest_assessment_scan(user_id=505, assessment_id=assessment["id"], scan_id=scan["id"])
    entities = _rows("assessment_map_entities")
    assert {row["entity_type"] for row in entities} >= {"ip", "service"}
    assert not any(row["entity_type"] == "hostname" for row in entities)
    assertions = _keys("assessment_map_assertions")
    assert "DNS:www.example.com" in assertions and "Example CA" in assertions


@pytest.mark.parametrize("scan_status", ["partial", "timed_out"])
def test_testssl_partial_or_timed_out_evidence_and_malformed_sibling_are_retained_truthfully(scan_status) -> None:
    assessment = create_assessment("TLS partial", user_id=506)
    evidence = normalize_testssl_output('[{"id":"TLS1_2","severity":"OK","finding":"offered"}]', target="example.com:443")
    evidence["protocols"].insert(0, "malformed")
    scan = _scan(506, assessment["id"], "testssl", _testssl_finding(evidence), status=scan_status)
    ledger = ingest_assessment_scan(user_id=506, assessment_id=assessment["id"], scan_id=scan["id"])
    assert ledger["status"] == "complete"
    assert "TLS1_2" in _keys("assessment_map_assertions")
    assert json.loads(ledger["metadata_json"])["skipped_optional_records"] == {
        "malformed_testssl_protocol_record": 1
    }


def test_phase5_identical_replay_and_changed_digest_replacement() -> None:
    assessment = create_assessment("Replace", user_id=507)
    stored = add_finding(507, _nuclei_finding([
        {"template_id": "keep", "severity": "info", "matched_at": "https://example.com/keep",
         "matched_surface_source": "matched-at"},
        {"template_id": "remove", "severity": "low", "matched_at": "https://example.com/remove",
         "matched_surface_source": "matched-at"},
    ]))
    scan = record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=stored["id"])
    first = ingest_assessment_scan(user_id=507, assessment_id=assessment["id"], scan_id=scan["id"])
    assert ingest_assessment_scan(user_id=507, assessment_id=assessment["id"], scan_id=scan["id"]) == first
    _replace_finding(stored["id"], _nuclei_finding([
        {"template_id": "keep", "severity": "info", "matched_at": "https://example.com/keep",
         "matched_surface_source": "matched-at"},
    ]))
    second = ingest_assessment_scan(user_id=507, assessment_id=assessment["id"], scan_id=scan["id"])
    assert first["source_digest"] != second["source_digest"]
    assert "remove" not in _keys("assessment_map_entities")


def test_phase5_shared_surface_survives_replacement_and_artifacts_are_ignored() -> None:
    assessment = create_assessment("Shared", user_id=508)
    first_finding = add_finding(508, _nuclei_finding([
        {"template_id": "one", "severity": "info", "matched_at": "https://example.com/shared",
         "matched_surface_source": "matched-at"},
    ]))
    first = record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=first_finding["id"])
    second = _scan(508, assessment["id"], "nuclei", _nuclei_finding([
        {"template_id": "two", "severity": "info", "matched_at": "https://example.com/shared",
         "matched_surface_source": "matched-at"},
    ]))
    artifact = add_assessment_artifact(
        assessment["id"], "nuclei_json", "Not a committed producer", scan_id=first["id"],
        content=json.dumps(_nuclei_finding([{"template_id": "artifact", "matched_at": "https://bad.example"}])),
    )
    ingest_assessment_scan(user_id=508, assessment_id=assessment["id"], scan_id=first["id"])
    ingest_assessment_scan(user_id=508, assessment_id=assessment["id"], scan_id=second["id"])
    _replace_finding(first_finding["id"], _nuclei_finding([
        {"template_id": "replacement", "severity": "info", "matched_at": "https://example.com/other",
         "matched_surface_source": "matched-at"},
    ]))
    ingest_assessment_scan(user_id=508, assessment_id=assessment["id"], scan_id=first["id"])
    assert "shared" in _keys("assessment_map_entities")
    assert artifact["id"] not in {row["artifact_id"] for row in _rows("assessment_map_evidence_links")}


def test_phase5_scope_and_transaction_rollback(monkeypatch) -> None:
    first = create_assessment("First", user_id=509)
    second = create_assessment("Second", user_id=509)
    scan = _scan(509, first["id"], "nuclei", _nuclei_finding([
        {"template_id": "one", "severity": "info", "matched_at": "https://example.com",
         "matched_surface_source": "matched-at"},
    ]))
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=510, assessment_id=first["id"], scan_id=scan["id"])
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=509, assessment_id=second["id"], scan_id=scan["id"])

    original = assessment_map_ingestion.map_security_source
    def fail_after_mapping(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("synthetic failure")
    monkeypatch.setattr(assessment_map_ingestion, "map_security_source", fail_after_mapping)
    with pytest.raises(RuntimeError, match="synthetic failure"):
        ingest_assessment_scan(user_id=509, assessment_id=first["id"], scan_id=scan["id"])
    assert not _rows("assessment_map_entities")
    assert not _rows("assessment_map_ingestions")
