from datetime import datetime

import pytest

from app.services.assessment_store import (
    add_assessment_artifact,
    add_assessment_note,
    add_assessment_target,
    create_assessment,
    get_assessment,
    list_assessment_artifacts,
    list_assessment_notes,
    list_assessment_scans,
    list_assessment_targets,
    list_assessments,
    record_assessment_scan,
)
from app.services.findings_store import add_finding, close_findings_database, configure_findings_database, get_user_findings


@pytest.fixture(autouse=True)
def sqlite_assessment_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_create_assessment() -> None:
    assessment = create_assessment("External Pentest", description="Q3 perimeter review")

    assert isinstance(assessment["id"], int)
    assert assessment["name"] == "External Pentest"
    assert assessment["description"] == "Q3 perimeter review"
    assert assessment["status"] == "active"
    assert isinstance(assessment["created_at"], datetime)
    assert isinstance(assessment["updated_at"], datetime)
    assert get_assessment(assessment["id"]) == assessment


def test_list_assessments_and_status_filter() -> None:
    active = create_assessment("Active Assessment")
    create_assessment("Another Assessment")

    assessments = list_assessments()
    assert [assessment["name"] for assessment in assessments] == ["Active Assessment", "Another Assessment"]
    assert list_assessments(status="active")[0]["id"] == active["id"]
    assert list_assessments(status="archived") == []


def test_add_and_list_assessment_targets() -> None:
    assessment = create_assessment("Targeted Assessment")
    target = add_assessment_target(
        assessment["id"],
        address="scanme.nmap.org",
        name="Scanme",
        target_type="hostname",
    )

    assert target["assessment_id"] == assessment["id"]
    assert target["name"] == "Scanme"
    assert target["address"] == "scanme.nmap.org"
    assert target["target_type"] == "hostname"
    assert list_assessment_targets(assessment["id"]) == [target]


def test_record_nmap_bbot_and_nuclei_style_scans() -> None:
    assessment = create_assessment("Scan Assessment")
    target = add_assessment_target(assessment["id"], address="example.com", target_type="hostname")

    nmap_scan = record_assessment_scan(
        assessment_id=assessment["id"],
        target_id=target["id"],
        tool="nmap",
        status="completed",
        finding_id="finding-nmap",
        elapsed_seconds=9,
        risk="medium",
        raw_reference="scan_runs/finding-nmap",
    )
    bbot_scan = record_assessment_scan(assessment["id"], tool="bbot", status="completed", elapsed_seconds=19, risk="info")
    nuclei_scan = record_assessment_scan(assessment["id"], tool="nuclei", status="failed", raw_reference="logs/nuclei.log")
    httpx_scan = record_assessment_scan(assessment["id"], tool="httpx", status="completed", elapsed_seconds=4, risk="info")
    katana_scan = record_assessment_scan(assessment["id"], tool="katana", status="completed", elapsed_seconds=11, risk="info")

    assert nmap_scan["target_id"] == target["id"]
    assert nmap_scan["tool"] == "nmap"
    assert nmap_scan["status"] == "completed"
    assert nmap_scan["completed_at"] is not None
    assert nmap_scan["finding_id"] == "finding-nmap"
    assert bbot_scan["tool"] == "bbot"
    assert nuclei_scan["tool"] == "nuclei"
    assert httpx_scan["tool"] == "httpx"
    assert katana_scan["tool"] == "katana"
    assert [scan["tool"] for scan in list_assessment_scans(assessment["id"])] == ["nmap", "bbot", "nuclei", "httpx", "katana"]


def test_add_and_list_assessment_artifacts() -> None:
    assessment = create_assessment("Artifact Assessment")
    scan = record_assessment_scan(assessment["id"], tool="nmap", status="completed")
    artifact = add_assessment_artifact(
        assessment_id=assessment["id"],
        scan_id=scan["id"],
        artifact_type="ai_summary",
        title="Nmap AI Assessment",
        content="Observed SSH service.",
        file_path="artifacts/nmap-ai.txt",
    )

    assert artifact["assessment_id"] == assessment["id"]
    assert artifact["scan_id"] == scan["id"]
    assert artifact["artifact_type"] == "ai_summary"
    assert artifact["title"] == "Nmap AI Assessment"
    assert artifact["content"] == "Observed SSH service."
    assert list_assessment_artifacts(assessment["id"]) == [artifact]


def test_add_and_list_assessment_notes() -> None:
    assessment = create_assessment("Notes Assessment")
    note = add_assessment_note(assessment["id"], "Customer approved external scan window.", note_type="scope")

    assert note["assessment_id"] == assessment["id"]
    assert note["note_type"] == "scope"
    assert note["content"] == "Customer approved external scan window."
    assert list_assessment_notes(assessment["id"]) == [note]


def test_schema_initialization_is_idempotent_and_preserves_loose_findings() -> None:
    finding = add_finding(
        user_id=42,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "low",
            "finding_count": 0,
            "status": "completed",
            "summary": "Loose scan result.",
        },
    )

    assert list_assessments() == []
    assessment = create_assessment("Migration Assessment")
    assert get_assessment(assessment["id"]) == assessment
    assert get_user_findings(42)[0]["id"] == finding["id"]

    close_findings_database()
    assert get_assessment(assessment["id"]) == assessment
    assert get_user_findings(42)[0]["id"] == finding["id"]
