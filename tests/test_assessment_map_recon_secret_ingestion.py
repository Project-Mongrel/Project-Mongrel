import json
from unittest.mock import patch

import pytest

from app.parsers.bbot_normalizer import normalize_bbot_output
from app.parsers.gitleaks_parser import normalize_gitleaks_output
from app.bot.handlers.scan import _ingest_assessment_map_after_scan
from app.services.assessment_map_ingestion import ingest_assessment_scan
from app.services.assessment_map_retrieval import build_assessment_map_context
from app.services.assessment_map_store import AssessmentMapScopeError
from app.services.assessment_store import create_assessment, record_assessment_scan
from app.services.findings_store import (
    _get_connection,
    add_finding,
    close_findings_database,
    configure_findings_database,
)

RAW_SECRET = "ghp_1234567890abcdefghijklmnopqrstuv"


@pytest.fixture(autouse=True)
def isolated_database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _scan(user_id: int, assessment_id: int, tool: str, finding: dict) -> tuple[dict, dict]:
    stored = add_finding(user_id, finding)
    scan = record_assessment_scan(
        assessment_id, tool=tool, status="completed", finding_id=stored["id"]
    )
    return stored, scan


def _rows(table: str) -> list[dict]:
    return [dict(row) for row in _get_connection().execute(f"SELECT * FROM {table}").fetchall()]


def _bbot_finding(raw_events: str, *, target: str = "example.com") -> dict:
    return {
        "source": "bbot",
        "target": target,
        "observations": normalize_bbot_output(raw_events, target, 8101, investigation_id="inv-1"),
    }


def _gitleaks_finding() -> dict:
    raw = json.dumps([{
        "RuleID": "github-pat",
        "Description": "GitHub Personal Access Token",
        "File": "src/secret-token.txt",
        "StartLine": 12,
        "Secret": RAW_SECRET,
        "Entropy": 4.9,
        "Fingerprint": "unsafe-fingerprint-material",
        "Commit": "sensitive-commit-metadata",
        "Author": "Sensitive Person",
        "Email": "sensitive@example.com",
    }])
    return {
        "source": "gitleaks",
        "target": "/authorized/repository",
        "gitleaks_evidence": normalize_gitleaks_output(raw, scan_root="/authorized/repository"),
    }


def test_bbot_maps_parser_observations_and_explicit_event_relationships() -> None:
    assessment = create_assessment("BBOT map", user_id=8101)
    raw = "\n".join([
        json.dumps({
            "type": "DNS_NAME", "data": "app.example.com", "source": "example.com",
            "module": "dnsbrute", "resolved_hosts": ["192.0.2.20"],
        }),
        json.dumps({"type": "URL", "data": "https://app.example.com/login"}),
        json.dumps({"type": "OPEN_TCP_PORT", "data": "192.0.2.20:443"}),
    ])
    stored, scan = _scan(8101, assessment["id"], "bbot", _bbot_finding(raw))

    ledger = ingest_assessment_scan(user_id=8101, assessment_id=assessment["id"], scan_id=scan["id"])

    entities = _rows("assessment_map_entities")
    assertions = _rows("assessment_map_assertions")
    evidence = _rows("assessment_map_evidence_links")
    assert ledger["status"] == "complete"
    assert {row["entity_type"] for row in entities} >= {"hostname", "ip", "service", "application", "endpoint"}
    assert {row["predicate"] for row in assertions} >= {
        "observed_address", "discovered_from", "exposes_endpoint", "exposes_service", "has_bbot_event_type",
    }
    assert {row["scan_id"] for row in evidence} == {scan["id"]}
    assert {row["finding_id"] for row in evidence} == {stored["id"]}
    assert any(row["evidence_path"] == "finding.observations[0].metadata.raw_event.resolved_hosts[0]" for row in evidence)
    open_tcp_index = next(
        index for index, observation in enumerate(stored["observations"])
        if observation.get("metadata", {}).get("raw_event", {}).get("type") == "OPEN_TCP_PORT"
    )
    assert any(row["evidence_path"] == f"finding.observations[{open_tcp_index}].value" for row in evidence)


def test_bbot_input_target_is_not_promoted_without_observed_evidence() -> None:
    assessment = create_assessment("BBOT input boundary", user_id=8102)
    finding = _bbot_finding('{"type":"DNS_NAME","data":"observed.example.net"}', target="input.example.com")
    _stored, scan = _scan(8102, assessment["id"], "bbot", finding)

    ingest_assessment_scan(user_id=8102, assessment_id=assessment["id"], scan_id=scan["id"])

    canonical = "\n".join(row["canonical_key"] for row in _rows("assessment_map_entities"))
    assert "observed.example.net" in canonical
    assert "input.example.com" not in canonical


def test_bbot_reuses_existing_cross_tool_hostname_identity() -> None:
    assessment = create_assessment("BBOT identity reuse", user_id=8103)
    nmap = add_finding(8103, {
        "source": "nmap", "target": "app.example.com", "host_status": "up", "open_ports": [],
    })
    nmap_scan = record_assessment_scan(
        assessment["id"], tool="nmap", status="completed", finding_id=nmap["id"]
    )
    ingest_assessment_scan(user_id=8103, assessment_id=assessment["id"], scan_id=nmap_scan["id"])
    _stored, bbot_scan = _scan(
        8103, assessment["id"], "bbot",
        _bbot_finding('{"type":"DNS_NAME","data":"app.example.com"}'),
    )

    ingest_assessment_scan(user_id=8103, assessment_id=assessment["id"], scan_id=bbot_scan["id"])

    hostname_rows = [row for row in _rows("assessment_map_entities") if row["entity_type"] == "hostname"]
    hostname_id = hostname_rows[0]["id"]
    provenance = [
        row for row in _rows("assessment_map_evidence_links")
        if row["destination_type"] == "entity" and row["destination_id"] == hostname_id
    ]
    assert len(hostname_rows) == 1
    assert {row["source_tool"] for row in provenance} == {"nmap", "bbot"}


def test_gitleaks_maps_only_redacted_finding_metadata_and_exact_provenance() -> None:
    assessment = create_assessment("Gitleaks map", user_id=8104)
    stored, scan = _scan(8104, assessment["id"], "gitleaks", _gitleaks_finding())

    ledger = ingest_assessment_scan(user_id=8104, assessment_id=assessment["id"], scan_id=scan["id"])

    assertions = _rows("assessment_map_assertions")
    evidence = _rows("assessment_map_evidence_links")
    mapped_dump = json.dumps({
        table: _rows(table)
        for table in (
            "assessment_map_entities", "assessment_map_assertions", "assessment_map_evidence_links",
            "assessment_map_ingestions", "assessment_map_ingestion_evidence", "assessment_map_ingestion_heads",
        )
    }, default=str)
    assert ledger["status"] == "complete"
    assert {row["predicate"] for row in assertions} >= {
        "has_rule_id", "observed_in_source_path", "has_line_number", "has_scanner_severity", "has_provider",
    }
    assert {row["finding_id"] for row in evidence} == {stored["id"]}
    assert {row["scan_id"] for row in evidence} == {scan["id"]}
    assert any(row["evidence_path"] == "finding.gitleaks_evidence.findings[0].file_path" for row in evidence)
    assert "src/[redacted-path]" in mapped_dump
    assert "secret-token.txt" not in mapped_dump
    for forbidden in (
        RAW_SECRET, "unsafe-fingerprint-material", "sensitive-commit-metadata", "Sensitive Person",
        "sensitive@example.com", "secret_hash", "redacted_secret_preview", "raw_json", "evidence_id",
    ):
        assert forbidden not in mapped_dump


def test_bbot_and_gitleaks_ingestion_enforce_owner_and_assessment_scope() -> None:
    owned = create_assessment("Owned", user_id=8105)
    other = create_assessment("Other", user_id=8105)
    _stored, scan = _scan(
        8105, owned["id"], "bbot", _bbot_finding('{"type":"DNS_NAME","data":"app.example.com"}')
    )
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=9999, assessment_id=owned["id"], scan_id=scan["id"])
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=8105, assessment_id=other["id"], scan_id=scan["id"])


@pytest.mark.parametrize("tool", ["bbot", "gitleaks"])
def test_live_mapping_hook_keeps_mapper_failures_nonfatal(tool: str) -> None:
    with patch(
        "app.bot.handlers.scan.ingest_assessment_scan",
        side_effect=RuntimeError("synthetic mapper failure"),
    ) as ingest:
        _ingest_assessment_map_after_scan(
            {"assessment_id": 41}, user_id=8107, tool=tool, scan={"id": 99}
        )

    ingest.assert_called_once_with(user_id=8107, assessment_id=41, scan_id=99)


def test_ask_map_retrieval_is_bounded_and_contains_redacted_new_tool_provenance() -> None:
    assessment = create_assessment("Ask mapped tools", user_id=8106)
    _bbot_stored, bbot_scan = _scan(
        8106, assessment["id"], "bbot",
        _bbot_finding('{"type":"URL","data":"https://app.example.com/login"}'),
    )
    ingest_assessment_scan(user_id=8106, assessment_id=assessment["id"], scan_id=bbot_scan["id"])
    _gitleaks_stored, gitleaks_scan = _scan(8106, assessment["id"], "gitleaks", _gitleaks_finding())
    ingest_assessment_scan(user_id=8106, assessment_id=assessment["id"], scan_id=gitleaks_scan["id"])

    context = build_assessment_map_context(
        user_id=8106,
        assessment_id=assessment["id"],
        question="Which endpoints and findings are associated with this assessment?",
        entity_limit=4,
        relationship_limit=6,
        max_chars=2200,
    )

    rendered = json.dumps(context, sort_keys=True)
    assert context["available"] is True
    assert context["truncated"] in {True, False}
    assert "bbot" in rendered
    assert "gitleaks" in rendered
    assert RAW_SECRET not in rendered
    assert len(rendered) <= 2200
