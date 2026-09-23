import json
from unittest.mock import patch

import pytest

from app.bot.handlers.scan import _ingest_assessment_map_after_scan
from app.parsers.metasploit_parser import parse_metasploit_validation_result
from app.parsers.prowler_parser import normalize_prowler_output
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
from app.services.metasploit_approval import (
    approve_metasploit_proposal,
    clear_metasploit_proposals,
    mark_metasploit_proposal_status,
    propose_metasploit_action,
    record_metasploit_result_reference,
)
from app.services.metasploit_policy import build_metasploit_action_request


SECRET = "AKIA1234567890ABCDEF"


@pytest.fixture(autouse=True)
def isolated_database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    clear_metasploit_proposals()
    yield
    clear_metasploit_proposals()
    close_findings_database()
    configure_findings_database(None)


def _scan(user_id: int, assessment_id: int, tool: str, finding: dict) -> tuple[dict, dict]:
    stored = add_finding(user_id, finding)
    scan = record_assessment_scan(
        assessment_id, tool=tool, status=finding.get("status") or "completed", finding_id=stored["id"]
    )
    return stored, scan


def _rows(table: str) -> list[dict]:
    return [dict(row) for row in _get_connection().execute(f"SELECT * FROM {table}").fetchall()]


def _prowler_finding(records: list[dict], *, provider: str = "aws", context: str = "assessment-aws") -> dict:
    evidence = normalize_prowler_output(records, provider=provider)
    evidence["cloud_context"] = context
    return {
        "source": "prowler",
        "target": context,
        "provider": provider,
        "cloud_context": context,
        "status": "completed",
        "prowler_evidence": evidence,
    }


def _prowler_record(
    *,
    account_id: str,
    resource_id: str = "resource-001",
    resource_name: str = "shared-name",
    status: str = "FAIL",
    check_id: str = "iam_check",
) -> dict:
    return {
        "metadata": {"event_code": check_id, "product": {"feature": {"name": "iam"}}},
        "cloud": {"provider": "aws", "region": "global", "account": {"uid": account_id, "name": "test-account"}},
        "finding_info": {"uid": f"{check_id}-finding", "title": "IAM check"},
        "status_code": status,
        "severity": "Medium",
        "resources": [{"uid": resource_id, "name": resource_name, "region": "global", "group": {"name": "iam"}}],
    }


def _metasploit_finding(
    *,
    user_id: int,
    assessment_id: int,
    output: str = "Server: nginx",
    success: bool = True,
) -> dict:
    request = build_metasploit_action_request(
        module="auxiliary/scanner/http/http_version",
        action_type="auxiliary_validation",
        target="example.com",
        port=443,
        options={"SSL": "true"},
    )
    proposal = propose_metasploit_action(
        user_id,
        request,
        assessment_context={"assessment_id": assessment_id, "tool": "metasploit"},
    )
    approve_metasploit_proposal(proposal.id, user_id=user_id, actor="human")
    mark_metasploit_proposal_status(proposal.id, "executed" if success else "failed")
    record_metasploit_result_reference(proposal.id, "assessment_artifact:1")
    result = {
        "success": success,
        "module": request["module"],
        "action_type": request["action_type"],
        "target": request["target"],
        "port": request["port"],
        "output": output,
        "error": "",
        "elapsed_seconds": 1,
        "returncode": 0 if success else 1,
    }
    normalized = parse_metasploit_validation_result(result)
    return {
        "source": "metasploit",
        "target": "example.com",
        "status": "completed" if success else "failed",
        "metasploit_evidence": normalized,
        "metadata": {
            "proposal_id": proposal.id,
            "artifact_ref": "assessment_artifact:1",
            "module": request["module"],
            "action_type": request["action_type"],
            "port": request["port"],
        },
    }


def test_prowler_maps_cloud_context_resources_and_check_status_without_security_upgrade() -> None:
    assessment = create_assessment("Prowler map", user_id=9101)
    stored, scan = _scan(
        9101,
        assessment["id"],
        "prowler",
        _prowler_finding([
            _prowler_record(account_id="111111111111", status="FAIL"),
            _prowler_record(account_id="111111111111", status="PASS", resource_id="resource-002", check_id="s3_check"),
        ]),
    )

    ledger = ingest_assessment_scan(user_id=9101, assessment_id=assessment["id"], scan_id=scan["id"])

    entities = _rows("assessment_map_entities")
    assertions = _rows("assessment_map_assertions")
    evidence = _rows("assessment_map_evidence_links")
    serialized = json.dumps({"entities": entities, "assertions": assertions})
    assert ledger["status"] == "complete"
    assert {row["entity_type"] for row in entities} >= {"cloud_account", "cloud_region", "cloud_resource", "finding"}
    assert {row["predicate"] for row in assertions} >= {
        "contains_cloud_region", "contains_cloud_resource", "finding_affects",
        "has_check_id", "has_scanner_status", "has_scanner_severity",
    }
    assert "scanner_reported_failed_check" in serialized
    assert "scanner_reported_passed_check" in serialized
    assert "exploit" not in serialized.lower()
    assert "compromise" not in serialized.lower()
    assert {row["scan_id"] for row in evidence} == {scan["id"]}
    assert {row["finding_id"] for row in evidence} == {stored["id"]}
    assert any(row["evidence_path"] == "finding.prowler_evidence.findings[0].status" for row in evidence)


def test_prowler_cloud_resource_identity_is_account_scoped_and_suppresses_sensitive_values() -> None:
    assessment = create_assessment("Prowler identity", user_id=9102)
    finding = _prowler_finding([
        _prowler_record(account_id="111111111111", resource_name="shared-name"),
        _prowler_record(account_id="222222222222", resource_name="shared-name", resource_id="resource-001"),
        _prowler_record(account_id="333333333333", resource_name=SECRET, resource_id=SECRET, check_id="secret_check"),
    ])
    _stored, scan = _scan(9102, assessment["id"], "prowler", finding)

    ingest_assessment_scan(user_id=9102, assessment_id=assessment["id"], scan_id=scan["id"])

    entities = _rows("assessment_map_entities")
    resources = [row for row in entities if row["entity_type"] == "cloud_resource"]
    serialized = json.dumps({"entities": entities, "assertions": _rows("assessment_map_assertions")})
    assert len(resources) == 2
    assert "111111111111" in serialized
    assert "222222222222" in serialized
    assert SECRET not in serialized


def test_prowler_ingestion_migrates_phase8_entity_type_check_for_cloud_entities() -> None:
    assessment = create_assessment("Prowler legacy map schema", user_id=9108)
    connection = _get_connection()
    connection.execute(
        """
        CREATE TABLE assessment_map_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            entity_type TEXT NOT NULL CHECK(entity_type IN ('hostname','ip','service','application','endpoint','technology','finding')),
            identity_version TEXT NOT NULL,
            identity_hash TEXT NOT NULL,
            canonical_key TEXT NOT NULL,
            display_value TEXT,
            attributes_json TEXT NOT NULL DEFAULT '{}',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(assessment_id, user_id, entity_type, identity_hash),
            UNIQUE(id, assessment_id, user_id),
            FOREIGN KEY(assessment_id, user_id) REFERENCES assessments(id, user_id) ON DELETE RESTRICT
        )
        """
    )
    connection.commit()
    _stored, scan = _scan(
        9108,
        assessment["id"],
        "prowler",
        _prowler_finding([_prowler_record(account_id="111111111111")]),
    )

    ledger = ingest_assessment_scan(user_id=9108, assessment_id=assessment["id"], scan_id=scan["id"])

    assert ledger["status"] == "complete"
    assert any(row["entity_type"] == "cloud_account" for row in _rows("assessment_map_entities"))


def test_metasploit_maps_execution_state_without_inventing_session_or_compromise() -> None:
    assessment = create_assessment("Metasploit map", user_id=9103)
    finding = _metasploit_finding(user_id=9103, assessment_id=assessment["id"], output="Server: nginx")
    stored, scan = _scan(9103, assessment["id"], "metasploit", finding)

    ledger = ingest_assessment_scan(user_id=9103, assessment_id=assessment["id"], scan_id=scan["id"])

    assertions = _rows("assessment_map_assertions")
    attempts = _rows("assessment_validation_attempts")
    evidence = _rows("assessment_map_evidence_links")
    serialized = json.dumps({"assertions": assertions, "attempts": attempts})
    bool_values = {
        row["predicate"]: json.loads(row["normalized_value_json"])
        for row in assertions
        if row["predicate"] in {"has_module_executed", "has_session_established"}
    }
    assert ledger["status"] == "complete"
    assert "DETECTED" in serialized
    assert bool_values["has_module_executed"] is True
    assert bool_values["has_session_established"] is False
    assert not any("compromise" in row["predicate"].lower() for row in assertions)
    assert attempts[0]["validation_state"] == "DETECTED"
    assert attempts[0]["session_established"] == 0
    assert {row["finding_id"] for row in evidence} == {stored["id"]}
    assert any(row["evidence_path"] == "finding.metasploit_evidence.validation_state" for row in evidence)


def test_metasploit_session_evidence_requires_explicit_session_marker() -> None:
    assessment = create_assessment("Metasploit session", user_id=9104)
    finding = _metasploit_finding(
        user_id=9104,
        assessment_id=assessment["id"],
        output="Meterpreter session 1 opened",
    )
    _stored, scan = _scan(9104, assessment["id"], "metasploit", finding)

    ingest_assessment_scan(user_id=9104, assessment_id=assessment["id"], scan_id=scan["id"])

    serialized = json.dumps({"assertions": _rows("assessment_map_assertions"), "attempts": _rows("assessment_validation_attempts")})
    assert "SESSION_ESTABLISHED" in serialized
    assert _rows("assessment_validation_attempts")[0]["session_established"] == 1


def test_cloud_validation_ingestion_enforces_owner_and_assessment_scope() -> None:
    owned = create_assessment("Owned", user_id=9105)
    other = create_assessment("Other", user_id=9105)
    _stored, scan = _scan(
        9105, owned["id"], "prowler",
        _prowler_finding([_prowler_record(account_id="111111111111")]),
    )
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=9999, assessment_id=owned["id"], scan_id=scan["id"])
    with pytest.raises(AssessmentMapScopeError):
        ingest_assessment_scan(user_id=9105, assessment_id=other["id"], scan_id=scan["id"])


@pytest.mark.parametrize("tool", ["prowler", "metasploit"])
def test_live_mapping_hook_keeps_cloud_validation_mapper_failures_nonfatal(tool: str) -> None:
    with patch(
        "app.bot.handlers.scan.ingest_assessment_scan",
        side_effect=RuntimeError("synthetic mapper failure"),
    ) as ingest:
        _ingest_assessment_map_after_scan(
            {"assessment_id": 41}, user_id=9107, tool=tool, scan={"id": 99}
        )

    ingest.assert_called_once_with(user_id=9107, assessment_id=41, scan_id=99)


def test_ask_map_retrieval_contains_bounded_prowler_and_metasploit_provenance() -> None:
    assessment = create_assessment("Ask mapped validation", user_id=9106)
    _prowler_stored, prowler_scan = _scan(
        9106, assessment["id"], "prowler",
        _prowler_finding([_prowler_record(account_id="111111111111")]),
    )
    ingest_assessment_scan(user_id=9106, assessment_id=assessment["id"], scan_id=prowler_scan["id"])
    _metasploit_stored, metasploit_scan = _scan(
        9106, assessment["id"], "metasploit",
        _metasploit_finding(user_id=9106, assessment_id=assessment["id"]),
    )
    ingest_assessment_scan(user_id=9106, assessment_id=assessment["id"], scan_id=metasploit_scan["id"])

    context = build_assessment_map_context(
        user_id=9106,
        assessment_id=assessment["id"],
        question="What cloud resources and validation evidence are mapped?",
        entity_limit=6,
        relationship_limit=8,
        max_chars=2600,
    )

    rendered = json.dumps(context, sort_keys=True)
    assert context["available"] is True
    assert "prowler" in rendered
    assert "metasploit" in rendered
    assert SECRET not in rendered
    assert len(rendered) <= 2600
