import json
import sqlite3

import pytest

from app.services import assessment_map_ingestion
from app.services.assessment_map_ingestion import INGESTION_VERSION, ingest_assessment_scan
from app.services.assessment_map_store import AssessmentMapScopeError
from app.services.assessment_store import add_assessment_artifact, create_assessment, record_assessment_scan
from app.services.findings_store import (
    _get_connection,
    add_finding,
    close_findings_database,
    configure_findings_database,
)
from app.services.sqlite_runtime import OperationalDatabaseBusyError
from app.parsers.httpx_parser import normalize_httpx_observation
from app.parsers.nmap_xml_parser import parse_nmap_xml
from app.tools.nmap_parser import parse_nmap_output


@pytest.fixture(autouse=True)
def isolated_database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _scan(user_id: int, assessment_id: int, tool: str, finding: dict | None) -> dict:
    stored = add_finding(user_id, finding) if finding is not None else None
    return record_assessment_scan(
        assessment_id,
        tool=tool,
        status="completed",
        finding_id=stored["id"] if stored else None,
    )


def _rows(table: str) -> list[dict]:
    return [dict(row) for row in _get_connection().execute(f"SELECT * FROM {table}").fetchall()]


def _replace_finding_data(finding_id: str, mutate) -> None:
    connection = _get_connection()
    row = connection.execute("SELECT data_json FROM findings WHERE id = ?", (finding_id,)).fetchone()
    data = json.loads(row["data_json"])
    mutate(data)
    with connection:
        connection.execute(
            "UPDATE findings SET data_json = ? WHERE id = ?",
            (json.dumps(data, default=str), finding_id),
        )


def _nmap_finding(*, ports: list[dict] | None = None) -> dict:
    return {
        "source": "nmap",
        "target": "scan.example",
        "host_status": "Up",
        "open_ports": ports if ports is not None else [
            {"port": "443", "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.24"}
        ],
    }


def _httpx_finding(services: list[dict]) -> dict:
    return {"source": "httpx", "target": "https://example.com", "httpx_services": services}


def test_ingestion_rejects_wrong_owner_and_wrong_assessment_scan() -> None:
    first = create_assessment("First", user_id=200)
    second = create_assessment("Second", user_id=200)
    scan = _scan(200, first["id"], "nmap", _nmap_finding())
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=201, assessment_id=first["id"], scan_id=scan["id"])
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=200, assessment_id=second["id"], scan_id=scan["id"])


def test_repeated_ingestion_is_a_noop_with_stable_counts() -> None:
    assessment = create_assessment("Repeat", user_id=202)
    scan = _scan(202, assessment["id"], "nmap", _nmap_finding())
    first = ingest_assessment_scan(user_id=202, assessment_id=assessment["id"], scan_id=scan["id"])
    before = tuple(len(_rows(table)) for table in (
        "assessment_map_entities", "assessment_map_assertions", "assessment_map_evidence_links"
    ))
    second = ingest_assessment_scan(user_id=202, assessment_id=assessment["id"], scan_id=scan["id"])
    after = tuple(len(_rows(table)) for table in (
        "assessment_map_entities", "assessment_map_assertions", "assessment_map_evidence_links"
    ))
    assert first == second
    assert before == after == (first["entity_count"], first["assertion_count"], first["evidence_count"])
    assert first["ingestion_version"] == INGESTION_VERSION


def test_unexpected_mapping_failure_rolls_back_without_terminal_ledger(monkeypatch) -> None:
    assessment = create_assessment("Rollback", user_id=203)
    scan = _scan(203, assessment["id"], "nmap", _nmap_finding())
    original = assessment_map_ingestion._ingest_nmap_source

    def fail_after_mapping(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("sensitive synthetic detail")

    monkeypatch.setattr(assessment_map_ingestion, "_ingest_nmap_source", fail_after_mapping)
    with pytest.raises(RuntimeError, match="sensitive synthetic detail"):
        ingest_assessment_scan(user_id=203, assessment_id=assessment["id"], scan_id=scan["id"])
    assert not _rows("assessment_map_entities")
    assert not _rows("assessment_map_assertions")
    assert not _rows("assessment_map_evidence_links")
    assert not _rows("assessment_map_ingestions")


def test_ledger_write_failure_rolls_back_all_map_rows(monkeypatch) -> None:
    assessment = create_assessment("Ledger rollback", user_id=210)
    scan = _scan(210, assessment["id"], "nmap", _nmap_finding())

    def fail_ledger(*args, **kwargs):
        raise RuntimeError("ledger unavailable")

    monkeypatch.setattr(assessment_map_ingestion, "_write_ledger", fail_ledger)
    with pytest.raises(RuntimeError, match="ledger unavailable"):
        ingest_assessment_scan(user_id=210, assessment_id=assessment["id"], scan_id=scan["id"])
    assert not _rows("assessment_map_entities")
    assert not _rows("assessment_map_assertions")
    assert not _rows("assessment_map_evidence_links")
    assert not _rows("assessment_map_ingestions")


def test_transient_mapping_lock_is_retried_without_failed_ledger(monkeypatch) -> None:
    assessment = create_assessment("Lock retry", user_id=211)
    scan = _scan(211, assessment["id"], "nmap", _nmap_finding())
    original = assessment_map_ingestion._ingest_nmap_source
    calls = 0

    def lock_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("database is locked")
        return original(*args, **kwargs)

    monkeypatch.setattr(assessment_map_ingestion, "_ingest_nmap_source", lock_once)
    ledger = ingest_assessment_scan(user_id=211, assessment_id=assessment["id"], scan_id=scan["id"])
    assert ledger["status"] == "complete"
    assert calls == 2
    assert len(_rows("assessment_map_ingestions")) == 1


def test_retry_after_contention_exhaustion_has_no_terminal_ledger(monkeypatch) -> None:
    assessment = create_assessment("Lock exhaustion", user_id=212)
    scan = _scan(212, assessment["id"], "nmap", _nmap_finding())
    original = assessment_map_ingestion._ingest_nmap_source
    monkeypatch.setattr(
        assessment_map_ingestion,
        "_ingest_nmap_source",
        lambda *args, **kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("database is busy")),
    )
    with pytest.raises(OperationalDatabaseBusyError):
        ingest_assessment_scan(user_id=212, assessment_id=assessment["id"], scan_id=scan["id"])
    assert not _rows("assessment_map_ingestions")
    assert not _rows("assessment_map_entities")
    monkeypatch.setattr(assessment_map_ingestion, "_ingest_nmap_source", original)
    assert ingest_assessment_scan(user_id=212, assessment_id=assessment["id"], scan_id=scan["id"])["status"] == "complete"


def test_missing_malformed_and_orphaned_evidence_are_ledgered_without_entities() -> None:
    assessment = create_assessment("Bad sources", user_id=204)
    missing = _scan(204, assessment["id"], "nmap", None)
    malformed = _scan(204, assessment["id"], "httpx", _httpx_finding("not-a-list"))
    orphan = record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id="missing-id")
    results = [
        ingest_assessment_scan(user_id=204, assessment_id=assessment["id"], scan_id=missing["id"]),
        ingest_assessment_scan(user_id=204, assessment_id=assessment["id"], scan_id=malformed["id"]),
        ingest_assessment_scan(user_id=204, assessment_id=assessment["id"], scan_id=orphan["id"]),
    ]
    assert [(item["status"], item["error_code"]) for item in results] == [
        ("skipped", "missing_structured_evidence"),
        ("failed", "malformed_structured_evidence"),
        ("skipped", "orphaned_finding_reference"),
    ]
    assert not _rows("assessment_map_entities")


def test_nmap_maps_explicit_host_services_and_attributed_observations_only() -> None:
    assessment = create_assessment("Nmap", user_id=205)
    scan = _scan(205, assessment["id"], "nmap", _nmap_finding())
    ledger = ingest_assessment_scan(user_id=205, assessment_id=assessment["id"], scan_id=scan["id"])
    entities = _rows("assessment_map_entities")
    assertions = _rows("assessment_map_assertions")
    assert ledger["status"] == "complete"
    assert {item["entity_type"] for item in entities} == {"hostname", "service"}
    assert {item["predicate"] for item in assertions} >= {
        "exposes_service", "has_host_state", "has_service_state", "has_service_name", "has_product", "has_version"
    }
    assert "finding" not in {item["entity_type"] for item in entities}
    assert all(item["scan_id"] == scan["id"] for item in _rows("assessment_map_evidence_links"))


@pytest.mark.parametrize("port", [0, 65536, "invalid", None, True])
def test_nmap_invalid_ports_fail_without_partial_entities(port) -> None:
    assessment = create_assessment("Invalid port", user_id=206)
    scan = _scan(
        206,
        assessment["id"],
        "nmap",
        _nmap_finding(ports=[{"port": port, "protocol": "tcp", "service": "http"}]),
    )
    ledger = ingest_assessment_scan(user_id=206, assessment_id=assessment["id"], scan_id=scan["id"])
    assert (ledger["status"], ledger["error_code"]) == ("failed", "malformed_structured_evidence")
    assert not _rows("assessment_map_entities")


def test_httpx_maps_only_response_backed_observations_and_explicit_relationships() -> None:
    assessment = create_assessment("httpx", user_id=207)
    services = [
        {"url": "https://attempted.example/private?token=secret"},
        {
            "url": "https://user:password@example.com/start?token=secret&q=value#fragment",
            "status_code": 301,
            "title": "Moved",
            "ip": "192.0.2.10",
            "cname": ["edge.example.net"],
            "technologies": [{"name": "nginx", "version": "1.24"}],
            "redirect_location": "https://example.com/final?session=private#hidden",
            "response_headers": {
                "server": "nginx",
                "set-cookie": "private-cookie",
                "location": "https://example.com/final?token=header-secret",
            },
        },
        {"url": "https://example.com/final", "status_code": 200},
    ]
    scan = _scan(207, assessment["id"], "httpx", _httpx_finding(services))
    ledger = ingest_assessment_scan(user_id=207, assessment_id=assessment["id"], scan_id=scan["id"])
    entities = _rows("assessment_map_entities")
    assertions = _rows("assessment_map_assertions")
    combined = "\n".join(item["canonical_key"] for item in entities) + "\n" + "\n".join(
        item["canonical_key"] for item in assertions
    )
    assert ledger["status"] == "complete"
    assert {item["entity_type"] for item in entities} >= {"application", "endpoint", "ip", "hostname", "technology"}
    assert {item["predicate"] for item in assertions} >= {
        "exposes_endpoint", "observed_ip", "observed_cname", "uses_technology", "redirects_to_reference"
    }
    assert "attempted.example" not in combined
    assert all(
        value not in combined
        for value in ("password", "secret", "private", "fragment", "hidden", "private-cookie", "header-secret")
    )
    assert '"query_parameter_names":["q","token"]' in combined


def test_httpx_repeated_observations_deduplicate_identity_but_keep_provenance() -> None:
    assessment = create_assessment("Repeated observations", user_id=208)
    observation = {"url": "https://example.com/", "status_code": 200, "title": "Home"}
    scan = _scan(208, assessment["id"], "httpx", _httpx_finding([observation, observation]))
    ledger = ingest_assessment_scan(user_id=208, assessment_id=assessment["id"], scan_id=scan["id"])
    endpoint_entities = [item for item in _rows("assessment_map_entities") if item["entity_type"] == "endpoint"]
    paths = {item["evidence_path"] for item in _rows("assessment_map_evidence_links")}
    assert ledger["status"] == "complete"
    assert len(endpoint_entities) == 1
    assert "finding.httpx_services[0].url" in paths
    assert "finding.httpx_services[1].url" in paths
    assert ledger["evidence_count"] == len(_rows("assessment_map_evidence_links"))


def test_structured_scan_artifact_is_supported_but_ai_artifact_is_ignored() -> None:
    assessment = create_assessment("Artifacts", user_id=209)
    scan = _scan(209, assessment["id"], "httpx", None)
    add_assessment_artifact(
        assessment["id"], "httpx_normalized_evidence", "Normalized", scan_id=scan["id"],
        content=json.dumps(_httpx_finding([{"url": "https://example.com", "status_code": 200}])),
    )
    add_assessment_artifact(
        assessment["id"], "httpx_ai_summary", "AI", scan_id=scan["id"],
        content=json.dumps(_httpx_finding([{"url": "https://ignored.example", "status_code": 200}])),
    )
    ledger = ingest_assessment_scan(user_id=209, assessment_id=assessment["id"], scan_id=scan["id"])
    keys = "\n".join(item["canonical_key"] for item in _rows("assessment_map_entities"))
    assert ledger["status"] == "complete"
    assert "example.com" in keys
    assert "ignored.example" not in keys
    assert all(item["artifact_id"] is not None for item in _rows("assessment_map_evidence_links"))


def test_changed_digest_removes_observations_and_changed_scalar_assertions() -> None:
    assessment = create_assessment("Replacement", user_id=213)
    finding = add_finding(
        213,
        _httpx_finding([
            {"url": "https://example.com/keep", "status_code": 200, "title": "Old title"},
            {"url": "https://example.com/remove", "status_code": 404},
        ]),
    )
    scan = record_assessment_scan(
        assessment["id"], tool="httpx", status="completed", finding_id=finding["id"]
    )
    first = ingest_assessment_scan(user_id=213, assessment_id=assessment["id"], scan_id=scan["id"])

    def change(data):
        data["httpx_services"] = [
            {"url": "https://example.com/keep", "status_code": 200, "title": "New title"}
        ]

    _replace_finding_data(finding["id"], change)
    second = ingest_assessment_scan(user_id=213, assessment_id=assessment["id"], scan_id=scan["id"])
    canonical = "\n".join(row["canonical_key"] for row in _rows("assessment_map_entities"))
    assertion_keys = "\n".join(row["canonical_key"] for row in _rows("assessment_map_assertions"))
    assert first["source_digest"] != second["source_digest"]
    assert "remove" not in canonical
    assert "Old title" not in assertion_keys
    assert "New title" in assertion_keys
    head = _rows("assessment_map_ingestion_heads")
    assert len(head) == 1 and head[0]["source_digest"] == second["source_digest"]


def test_replacement_never_removes_shared_entities_or_other_scan_evidence() -> None:
    assessment = create_assessment("Shared", user_id=214)
    first_finding = add_finding(
        214,
        _httpx_finding([
            {"url": "https://example.com/shared", "status_code": 200},
            {"url": "https://example.com/first-only", "status_code": 200},
        ]),
    )
    second_finding = add_finding(
        214, _httpx_finding([{"url": "https://example.com/shared", "status_code": 200}])
    )
    first_scan = record_assessment_scan(
        assessment["id"], tool="httpx", status="completed", finding_id=first_finding["id"]
    )
    second_scan = record_assessment_scan(
        assessment["id"], tool="httpx", status="completed", finding_id=second_finding["id"]
    )
    ingest_assessment_scan(user_id=214, assessment_id=assessment["id"], scan_id=first_scan["id"])
    second_ledger = ingest_assessment_scan(user_id=214, assessment_id=assessment["id"], scan_id=second_scan["id"])
    entity_total = len(_rows("assessment_map_entities"))

    _replace_finding_data(
        first_finding["id"],
        lambda data: data.update(
            {"httpx_services": [{"url": "https://example.com/first-only", "status_code": 200}]}
        ),
    )
    ingest_assessment_scan(user_id=214, assessment_id=assessment["id"], scan_id=first_scan["id"])
    canonical = "\n".join(row["canonical_key"] for row in _rows("assessment_map_entities"))
    second_evidence = [
        row for row in _rows("assessment_map_evidence_links") if row["scan_id"] == second_scan["id"]
    ]
    assert "shared" in canonical
    assert second_evidence
    assert second_ledger["entity_count"] > 0
    assert len(_rows("assessment_map_entities")) <= entity_total


def test_irrelevant_finding_fields_do_not_change_canonical_digest() -> None:
    assessment = create_assessment("Digest projection", user_id=215)
    finding = add_finding(215, _nmap_finding())
    scan = record_assessment_scan(
        assessment["id"], tool="nmap", status="completed", finding_id=finding["id"]
    )
    first = ingest_assessment_scan(user_id=215, assessment_id=assessment["id"], scan_id=scan["id"])
    _replace_finding_data(
        finding["id"],
        lambda data: data.update(
            {"summary": "changed interpretation", "raw_output": "unrelated raw output", "metadata": {"elapsed": 99}}
        ),
    )
    second = ingest_assessment_scan(user_id=215, assessment_id=assessment["id"], scan_id=scan["id"])
    assert first == second
    assert len(_rows("assessment_map_ingestions")) == 1


def test_actual_nmap_text_shape_preserves_explicit_hostname_and_ip() -> None:
    assessment = create_assessment("Nmap parser shape", user_id=216)
    parsed = parse_nmap_output(
        """Nmap scan report for example.com (192.0.2.25)\nHost is up.\n80/tcp open http\nNmap done: 1 IP address (1 host up) scanned in 1.0 seconds"""
    )
    parsed["source"] = "nmap"
    scan = _scan(216, assessment["id"], "nmap", parsed)
    ledger = ingest_assessment_scan(user_id=216, assessment_id=assessment["id"], scan_id=scan["id"])
    entities = _rows("assessment_map_entities")
    assertions = _rows("assessment_map_assertions")
    assert ledger["status"] == "complete"
    assert {row["entity_type"] for row in entities} == {"hostname", "ip", "service"}
    assert "observed_address" in {row["predicate"] for row in assertions}
    service = next(row for row in entities if row["entity_type"] == "service")
    assert "192.0.2.25" in service["canonical_key"]


def test_actual_nmap_xml_shape_maps_combined_service_version() -> None:
    assessment = create_assessment("Nmap XML parser shape", user_id=222)
    parsed = parse_nmap_xml(
        """<nmaprun><host><status state="up"/><address addr="192.0.2.30"/>
        <ports><port protocol="tcp" portid="443"><state state="open"/>
        <service name="https" product="Apache httpd" version="2.4.58"/></port></ports></host>
        <runstats><finished elapsed="1.0"/></runstats></nmaprun>"""
    )
    parsed["source"] = "nmap_xml"
    scan = _scan(222, assessment["id"], "nmap", parsed)
    ledger = ingest_assessment_scan(user_id=222, assessment_id=assessment["id"], scan_id=scan["id"])
    assertion_keys = "\n".join(row["canonical_key"] for row in _rows("assessment_map_assertions"))
    assert ledger["status"] == "complete"
    assert "Apache httpd 2.4.58" in assertion_keys


def test_actual_httpx_normalizer_shape_requires_response_status() -> None:
    assessment = create_assessment("httpx parser shape", user_id=217)
    attempted_with_metadata = normalize_httpx_observation(
        {"url": "https://attempted.example", "title": "Unconfirmed", "tech": ["nginx"], "tls": {"probe": True}}
    )
    response = normalize_httpx_observation(
        {"url": "https://observed.example", "status_code": 200, "title": "Observed", "tech": ["nginx"]}
    )
    scan = _scan(217, assessment["id"], "httpx", _httpx_finding([attempted_with_metadata, response]))
    ledger = ingest_assessment_scan(user_id=217, assessment_id=assessment["id"], scan_id=scan["id"])
    canonical = "\n".join(row["canonical_key"] for row in _rows("assessment_map_entities"))
    assert ledger["status"] == "complete"
    assert "observed.example" in canonical
    assert "attempted.example" not in canonical


def test_artifact_allowlist_and_source_mismatch_are_enforced() -> None:
    assessment = create_assessment("Artifact boundaries", user_id=218)
    ignored_scan = _scan(218, assessment["id"], "httpx", None)
    add_assessment_artifact(
        assessment["id"], "generic_json", "Not allowlisted", scan_id=ignored_scan["id"],
        content=json.dumps(_httpx_finding([{"url": "https://ignored.example", "status_code": 200}])),
    )
    ignored = ingest_assessment_scan(
        user_id=218, assessment_id=assessment["id"], scan_id=ignored_scan["id"]
    )
    assert (ignored["status"], ignored["error_code"]) == ("skipped", "missing_structured_evidence")

    mismatch_scan = _scan(218, assessment["id"], "httpx", None)
    add_assessment_artifact(
        assessment["id"], "httpx_normalized_evidence", "Wrong source", scan_id=mismatch_scan["id"],
        content=json.dumps({"source": "nmap", "httpx_services": [{"url": "https://bad.example", "status_code": 200}]}),
    )
    mismatch = ingest_assessment_scan(
        user_id=218, assessment_id=assessment["id"], scan_id=mismatch_scan["id"]
    )
    assert (mismatch["status"], mismatch["error_code"]) == ("failed", "malformed_structured_evidence")


def test_finding_and_multiple_artifacts_keep_distinct_provenance() -> None:
    assessment = create_assessment("Provenance", user_id=219)
    observation = _httpx_finding([{"url": "https://example.com", "status_code": 200}])
    scan = _scan(219, assessment["id"], "httpx", observation)
    artifacts = [
        add_assessment_artifact(
            assessment["id"], "httpx_normalized_evidence", f"Artifact {index}", scan_id=scan["id"],
            content=json.dumps(observation),
        )
        for index in range(2)
    ]
    ledger = ingest_assessment_scan(user_id=219, assessment_id=assessment["id"], scan_id=scan["id"])
    evidence = _rows("assessment_map_evidence_links")
    assert ledger["status"] == "complete"
    assert any(row["finding_id"] is not None for row in evidence)
    assert {row["artifact_id"] for row in evidence if row["artifact_id"] is not None} == {
        artifact["id"] for artifact in artifacts
    }
    assert len({row["evidence_fingerprint"] for row in evidence}) == len(evidence)


def test_malformed_later_source_rolls_back_earlier_valid_source() -> None:
    assessment = create_assessment("Multi-source rollback", user_id=220)
    scan = _scan(
        220, assessment["id"], "httpx",
        _httpx_finding([{"url": "https://valid.example", "status_code": 200}]),
    )
    add_assessment_artifact(
        assessment["id"], "httpx_normalized_evidence", "Malformed", scan_id=scan["id"],
        content=json.dumps(_httpx_finding([{"url": "https://bad.example", "status_code": 200, "technologies": "not-a-list"}])),
    )
    ledger = ingest_assessment_scan(user_id=220, assessment_id=assessment["id"], scan_id=scan["id"])
    assert ledger["status"] == "failed"
    assert not _rows("assessment_map_entities")
    assert not _rows("assessment_map_evidence_links")


def test_counts_are_referenced_rows_when_entities_are_preexisting() -> None:
    assessment = create_assessment("Referenced counts", user_id=221)
    observation = _httpx_finding([{"url": "https://example.com", "status_code": 200}])
    first_scan = _scan(221, assessment["id"], "httpx", observation)
    second_scan = _scan(221, assessment["id"], "httpx", observation)
    first = ingest_assessment_scan(user_id=221, assessment_id=assessment["id"], scan_id=first_scan["id"])
    entity_total = len(_rows("assessment_map_entities"))
    second = ingest_assessment_scan(user_id=221, assessment_id=assessment["id"], scan_id=second_scan["id"])
    assert second["entity_count"] == first["entity_count"]
    assert second["assertion_count"] == first["assertion_count"]
    assert len(_rows("assessment_map_entities")) == entity_total
    assert second["evidence_count"] > 0
