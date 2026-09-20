import json

import pytest

from app.parsers.ffuf_parser import parse_ffuf_output
from app.parsers.katana_parser import parse_katana_output
from app.parsers.playwright_parser import normalize_playwright_observation
from app.services.assessment_map_ingestion import ingest_assessment_scan
from app.services.assessment_map_store import AssessmentMapScopeError
from app.services.assessment_store import add_assessment_artifact, create_assessment, record_assessment_scan
from app.services.findings_store import (
    _get_connection,
    add_finding,
    close_findings_database,
    configure_findings_database,
)


@pytest.fixture(autouse=True)
def isolated_database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _scan(user_id, assessment_id, tool, finding, *, status="completed"):
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


def test_phase4_shared_scope_and_identical_replay() -> None:
    first = create_assessment("First", user_id=400)
    second = create_assessment("Second", user_id=400)
    finding = {"source": "katana", "katana_observations": [{"url": "https://example.com/a"}]}
    scan = _scan(400, first["id"], "katana", finding)
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=401, assessment_id=first["id"], scan_id=scan["id"])
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=400, assessment_id=second["id"], scan_id=scan["id"])
    initial = ingest_assessment_scan(user_id=400, assessment_id=first["id"], scan_id=scan["id"])
    counts = tuple(len(_rows(table)) for table in (
        "assessment_map_entities", "assessment_map_assertions", "assessment_map_evidence_links"
    ))
    assert ingest_assessment_scan(user_id=400, assessment_id=first["id"], scan_id=scan["id"]) == initial
    assert counts == tuple(len(_rows(table)) for table in (
        "assessment_map_entities", "assessment_map_assertions", "assessment_map_evidence_links"
    ))


def test_actual_katana_shape_maps_crawled_urls_forms_and_parameter_names_safely() -> None:
    assessment = create_assessment("Katana", user_id=402)
    observations = parse_katana_output(
        '{"url":"https://user:pw@example.com/Search?token=secret&q=value#frag",'
        '"source":"https://example.com/","method":"GET","depth":2,'
        '"forms":[{"action":"/Login?csrf=private","method":"POST","inputs":["password"]}]}'
    )
    scan = _scan(402, assessment["id"], "katana", {
        "source": "katana", "katana_observations": observations,
    })
    ledger = ingest_assessment_scan(user_id=402, assessment_id=assessment["id"], scan_id=scan["id"])
    combined = _keys("assessment_map_entities") + _keys("assessment_map_assertions")
    predicates = {row["predicate"] for row in _rows("assessment_map_assertions")}
    assert ledger["status"] == "complete"
    assert {"contains_endpoint", "discovered_from_reference", "declares_form_action", "has_crawl_depth"} <= predicates
    assert "has_form_action" not in predicates and "declares_method" in predicates
    assert '"path":"/Search"' in combined and '"path":"/Login"' in combined
    assert '"query_parameter_names":["q","token"]' in combined
    assert all(secret not in combined for secret in ("user:pw", "secret", "frag", "private", "=value"))


def test_katana_changed_digest_replaces_only_this_scan_projection() -> None:
    assessment = create_assessment("Katana replace", user_id=403)
    stored = add_finding(403, {
        "source": "katana", "katana_observations": [
            {"url": "https://example.com/keep"}, {"url": "https://example.com/remove"},
        ],
    })
    scan = record_assessment_scan(assessment["id"], tool="katana", status="completed", finding_id=stored["id"])
    first = ingest_assessment_scan(user_id=403, assessment_id=assessment["id"], scan_id=scan["id"])
    _replace_finding(stored["id"], {
        "source": "katana", "katana_observations": [{"url": "https://example.com/keep"}],
    })
    second = ingest_assessment_scan(user_id=403, assessment_id=assessment["id"], scan_id=scan["id"])
    assert first["source_digest"] != second["source_digest"]
    assert "remove" not in _keys("assessment_map_entities")


def test_playwright_attempted_url_and_counts_do_not_create_entities() -> None:
    assessment = create_assessment("Playwright attempted", user_id=404)
    scan = _scan(404, assessment["id"], "playwright", {
        "source": "playwright",
        "playwright_observation": {"requested_url": "https://attempted.example", "links_count": 99},
    })
    ledger = ingest_assessment_scan(user_id=404, assessment_id=assessment["id"], scan_id=scan["id"])
    assert ledger["status"] == "failed"
    assert not _rows("assessment_map_entities")


def test_actual_playwright_shape_maps_final_url_network_responses_and_sampled_links() -> None:
    assessment = create_assessment("Playwright", user_id=405)
    observation = normalize_playwright_observation({
        "requested_url": "https://attempted.example/input",
        "final_url": "https://user:pw@example.com/Final?session=secret#frag",
        "status_code": 200,
        "title": "Observed",
        "links_count": 20,
        "link_samples": ["https://example.com/About?ref=value"],
        "network_events": [
            {"url": "https://example.com/api?token=hidden", "status": 201},
            {"url": "https://example.com/request-only"},
        ],
    })
    scan = _scan(405, assessment["id"], "playwright", {
        "source": "playwright", "playwright_observation": observation,
    })
    ledger = ingest_assessment_scan(user_id=405, assessment_id=assessment["id"], scan_id=scan["id"])
    combined = _keys("assessment_map_entities") + _keys("assessment_map_assertions")
    assert ledger["status"] == "complete"
    assert "attempted.example" not in combined and "request-only" not in combined
    assert all(value not in combined for value in ("user:pw", "secret", "hidden", "frag", "=value"))
    assert "/Final" in combined and "/About" in combined and "/api" in combined


def test_actual_ffuf_shape_maps_response_metrics_redirect_and_run_scope() -> None:
    assessment = create_assessment("ffuf", user_id=406)
    results = parse_ffuf_output(
        '{"results":[{"url":"https://user:pw@example.com/Admin?token=secret#frag",'
        '"status":301,"length":120,"words":10,"lines":3,'
        '"redirectlocation":"/Login?session=private"}]}'
    )
    scan = _scan(406, assessment["id"], "ffuf", {
        "source": "ffuf", "ffuf_results": results,
        "metadata": {"ffuf_profile": "standard", "wordlist_path": "/safe/ffuf-standard.txt",
                     "wordlist_count": 2570, "timeout_seconds": 600},
    })
    ledger = ingest_assessment_scan(user_id=406, assessment_id=assessment["id"], scan_id=scan["id"])
    combined = _keys("assessment_map_entities") + _keys("assessment_map_assertions")
    assert ledger["status"] == "complete"
    assert {"has_response_status", "has_content_length", "redirects_to_reference", "has_ffuf_profile"} <= {
        row["predicate"] for row in _rows("assessment_map_assertions")
    }
    assert "ffuf-standard.txt" in combined and "/safe/" not in combined
    assert all(value not in combined for value in ("pw", "secret", "frag", "private"))


def test_ffuf_zero_results_and_partial_results_preserve_truthful_boundaries() -> None:
    assessment = create_assessment("ffuf zero", user_id=407)
    zero = _scan(407, assessment["id"], "ffuf", {
        "source": "ffuf", "ffuf_results": [],
        "metadata": {"ffuf_profile": "deep", "wordlist_count": 29999},
    })
    zero_ledger = ingest_assessment_scan(user_id=407, assessment_id=assessment["id"], scan_id=zero["id"])
    assert zero_ledger["status"] == "complete"
    assert zero_ledger["entity_count"] == zero_ledger["assertion_count"] == 0

    partial = _scan(407, assessment["id"], "ffuf", {
        "source": "ffuf", "ffuf_results": [{"url": "https://example.com/seen", "status_code": 403}],
        "metadata": {"ffuf_profile": "deep"},
    }, status="partial")
    partial_ledger = ingest_assessment_scan(user_id=407, assessment_id=assessment["id"], scan_id=partial["id"])
    assert partial_ledger["status"] == "complete"
    assert "seen" in _keys("assessment_map_entities")
    assert not any("absent" in row["predicate"] or "safe" in row["predicate"] for row in _rows("assessment_map_assertions"))


def test_phase4_uses_findings_only_and_rejects_source_mismatch() -> None:
    assessment = create_assessment("Artifacts", user_id=408)
    scan = _scan(408, assessment["id"], "katana", None)
    add_assessment_artifact(assessment["id"], "generic_json", "Ignored", scan_id=scan["id"],
                            content=json.dumps({"source": "katana", "katana_observations": [{"url": "https://ignored.example"}]}))
    assert ingest_assessment_scan(user_id=408, assessment_id=assessment["id"], scan_id=scan["id"])["status"] == "skipped"

    good_scan = _scan(408, assessment["id"], "katana", {
        "source": "katana", "katana_observations": [{"url": "https://example.com/a"}],
    })
    artifact = add_assessment_artifact(
        assessment["id"], "katana_normalized_evidence", "Normalized", scan_id=good_scan["id"],
        content=json.dumps({"source": "katana", "katana_observations": [{"url": "https://example.com/a"}]}),
    )
    ledger = ingest_assessment_scan(user_id=408, assessment_id=assessment["id"], scan_id=good_scan["id"])
    evidence = _rows("assessment_map_evidence_links")
    assert ledger["status"] == "complete"
    assert any(row["finding_id"] for row in evidence)
    assert artifact["id"] not in {row["artifact_id"] for row in evidence}

    mismatch_scan = _scan(408, assessment["id"], "ffuf", {
        "source": "katana", "ffuf_results": [{"url": "https://bad.example", "status_code": 200}],
    })
    mismatch = ingest_assessment_scan(user_id=408, assessment_id=assessment["id"], scan_id=mismatch_scan["id"])
    assert (mismatch["status"], mismatch["error_code"]) == ("failed", "malformed_structured_evidence")


def test_phase4_ignored_artifact_does_not_affect_counts_reference_rows() -> None:
    assessment = create_assessment("Rollback", user_id=409)
    finding = {"source": "playwright", "playwright_observation": {
        "final_url": "https://example.com", "status_code": 200,
    }}
    first_scan = _scan(409, assessment["id"], "playwright", finding)
    first = ingest_assessment_scan(user_id=409, assessment_id=assessment["id"], scan_id=first_scan["id"])
    second_scan = _scan(409, assessment["id"], "playwright", finding)
    add_assessment_artifact(
        assessment["id"], "playwright_normalized_evidence", "Bad", scan_id=second_scan["id"],
        content=json.dumps({"source": "playwright", "playwright_observation": {
            "final_url": "https://bad.example", "network_events": "bad",
        }}),
    )
    second = ingest_assessment_scan(user_id=409, assessment_id=assessment["id"], scan_id=second_scan["id"])
    assert second["status"] == "complete"
    assert any(row["scan_id"] == second_scan["id"] for row in _rows("assessment_map_evidence_links"))

    third_scan = _scan(409, assessment["id"], "playwright", finding)
    third = ingest_assessment_scan(user_id=409, assessment_id=assessment["id"], scan_id=third_scan["id"])
    assert third["entity_count"] == first["entity_count"]
    assert third["assertion_count"] == first["assertion_count"]
    assert third["evidence_count"] > 0


def test_katana_parameter_names_drop_structured_and_inline_secret_values() -> None:
    assessment = create_assessment("Katana names", user_id=410)
    observations = parse_katana_output(json.dumps({
        "url": "https://example.com/search",
        "query_parameters": ["q=secret", {"name": "page", "value": "private"}, {"value": "drop"}],
        "forms": [{
            "action": "/login", "method": "POST",
            "inputs": ["username=alice", {"name": "password", "value": "hunter2"}, {"value": "drop"}],
        }],
    }))
    scan = _scan(410, assessment["id"], "katana", {
        "source": "katana", "katana_observations": observations,
    })
    assert ingest_assessment_scan(user_id=410, assessment_id=assessment["id"], scan_id=scan["id"])["status"] == "complete"
    assertions = _keys("assessment_map_assertions")
    for name in ("q", "page", "username", "password"):
        assert f'"value":"{name}"' in assertions
    for secret in ("secret", "private", "alice", "hunter2", "{'name'", "drop"):
        assert secret not in assertions


def test_referenced_form_actions_and_sampled_links_never_gain_observation_semantics() -> None:
    assessment = create_assessment("References", user_id=411)
    katana = _scan(411, assessment["id"], "katana", {
        "source": "katana", "katana_observations": [{
            "url": "https://example.com/page", "forms": [{"action": "/submit", "method": "POST"}],
        }],
    })
    playwright = _scan(411, assessment["id"], "playwright", {
        "source": "playwright", "playwright_observation": {
            "final_url": "https://example.com/page", "status_code": 200,
            "link_samples": ["/linked"],
        },
    })
    ingest_assessment_scan(user_id=411, assessment_id=assessment["id"], scan_id=katana["id"])
    ingest_assessment_scan(user_id=411, assessment_id=assessment["id"], scan_id=playwright["id"])
    endpoint_by_path = {
        json.loads(row["canonical_key"])["payload"]["path"]: row["id"]
        for row in _rows("assessment_map_entities") if row["entity_type"] == "endpoint"
    }
    assertions = _rows("assessment_map_assertions")
    assert any(row["predicate"] == "declares_form_action" and row["object_entity_id"] == endpoint_by_path["/submit"] for row in assertions)
    assert any(row["predicate"] == "links_to" and row["object_entity_id"] == endpoint_by_path["/linked"] for row in assertions)
    for path in ("/submit", "/linked"):
        endpoint_id = endpoint_by_path[path]
        assert not any(
            row["object_entity_id"] == endpoint_id and row["predicate"] == "contains_endpoint"
            for row in assertions
        )
        assert not any(
            row["subject_entity_id"] == endpoint_id and row["predicate"] == "has_response_status"
            for row in assertions
        )


@pytest.mark.parametrize(
    ("tool", "finding", "expected_path"),
    [
        ("katana", {"source": "katana", "katana_observations": [
            {"url": "not-a-url"},
            {"url": "https://example.com/good", "source": "bad", "forms": [{"action": "http://[bad"}]},
        ]}, "/good"),
        ("playwright", {"source": "playwright", "playwright_observation": {
            "final_url": "https://example.com/good", "status_code": 200,
            "link_samples": ["http://[bad", "/linked"],
            "network_events": [{"url": "http://[bad", "status": 200}, {"url": "/api", "status": 201}],
        }}, "/good"),
        ("ffuf", {"source": "ffuf", "ffuf_results": [
            {"url": "not-a-url", "status_code": 200},
            {"url": "https://example.com/good", "status_code": 200, "redirect_location": "http://[bad"},
        ], "metadata": {"ffuf_profile": "standard"}}, "/good"),
    ],
)
def test_malformed_optional_and_primary_urls_do_not_discard_valid_records(tool, finding, expected_path) -> None:
    assessment = create_assessment(f"Mixed {tool}", user_id=412)
    scan = _scan(412, assessment["id"], tool, finding)
    ledger = ingest_assessment_scan(user_id=412, assessment_id=assessment["id"], scan_id=scan["id"])
    metadata = json.loads(ledger["metadata_json"])
    assert ledger["status"] == "complete"
    assert expected_path in _keys("assessment_map_entities")
    assert metadata["skipped_optional_records"]
    assert "not-a-url" not in ledger["metadata_json"] and "http://[bad" not in ledger["metadata_json"]


def test_ffuf_zero_result_coverage_metadata_is_sanitized_and_replaced_atomically() -> None:
    assessment = create_assessment("ffuf coverage", user_id=413)
    stored = add_finding(413, {
        "source": "ffuf", "ffuf_results": [],
        "metadata": {"ffuf_profile": "standard", "ffuf_profile_label": "Standard",
                     "wordlist_path": "/private/path/ffuf-standard.txt", "wordlist_source": "SecLists",
                     "wordlist_count": 2570, "timeout_seconds": 600},
    })
    scan = record_assessment_scan(assessment["id"], tool="ffuf", status="completed", finding_id=stored["id"])
    first = ingest_assessment_scan(user_id=413, assessment_id=assessment["id"], scan_id=scan["id"])
    coverage = json.loads(first["metadata_json"])["sources"][0]["coverage"]
    assert coverage == {
        "profile": "standard", "profile_label": "Standard", "result_count": 0,
        "timeout_seconds": 600, "wordlist_entry_count": 2570,
        "wordlist_name": "ffuf-standard.txt", "wordlist_source": "SecLists",
    }
    assert "/private/path" not in first["metadata_json"]
    assert first["entity_count"] == first["assertion_count"] == first["evidence_count"] == 0

    _replace_finding(stored["id"], {
        "source": "ffuf", "ffuf_results": [],
        "metadata": {"ffuf_profile": "deep", "wordlist_path": "/other/ffuf-deep.txt",
                     "wordlist_source": "SecLists", "wordlist_count": 29999, "timeout_seconds": 2400},
    })
    second = ingest_assessment_scan(user_id=413, assessment_id=assessment["id"], scan_id=scan["id"])
    replacement = json.loads(second["metadata_json"])["sources"][0]["coverage"]
    assert second["source_digest"] != first["source_digest"]
    assert replacement["profile"] == "deep" and replacement["wordlist_entry_count"] == 29999
    head = _rows("assessment_map_ingestion_heads")
    assert len(head) == 1 and head[0]["source_digest"] == second["source_digest"]


def test_phase4_replacement_preserves_shared_endpoint_from_another_scan() -> None:
    assessment = create_assessment("Shared web", user_id=414)
    first_finding = add_finding(414, {"source": "katana", "katana_observations": [
        {"url": "https://example.com/shared"}, {"url": "https://example.com/first"},
    ]})
    second = _scan(414, assessment["id"], "playwright", {
        "source": "playwright", "playwright_observation": {
            "final_url": "https://example.com/shared", "status_code": 200,
        },
    })
    first = record_assessment_scan(assessment["id"], tool="katana", status="completed", finding_id=first_finding["id"])
    ingest_assessment_scan(user_id=414, assessment_id=assessment["id"], scan_id=first["id"])
    ingest_assessment_scan(user_id=414, assessment_id=assessment["id"], scan_id=second["id"])
    _replace_finding(first_finding["id"], {
        "source": "katana", "katana_observations": [{"url": "https://example.com/first"}],
    })
    ingest_assessment_scan(user_id=414, assessment_id=assessment["id"], scan_id=first["id"])
    assert "shared" in _keys("assessment_map_entities")
    assert any(row["scan_id"] == second["id"] for row in _rows("assessment_map_evidence_links"))
