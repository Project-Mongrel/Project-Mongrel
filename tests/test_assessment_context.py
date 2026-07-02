import pytest

from app.services.assessment_context import build_assessment_context
from app.services.assessment_store import (
    add_assessment_artifact,
    add_assessment_note,
    add_assessment_target,
    create_assessment,
    record_assessment_scan,
)
from app.services.findings_store import add_finding, close_findings_database, configure_findings_database


@pytest.fixture(autouse=True)
def sqlite_assessment_context_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_assessment_context_collects_assessment_evidence() -> None:
    assessment = create_assessment("Context Assessment", description="External assessment")
    target = add_assessment_target(assessment["id"], address="scanme.nmap.org", target_type="hostname")
    finding = add_finding(
        user_id=8100,
        finding={
            "source": "nmap",
            "target": "scanme.nmap.org",
            "risk_level": "medium",
            "status": "completed",
            "summary": "SSH and HTTP observed.",
            "open_ports": [
                {"port": "22", "protocol": "tcp", "service": "ssh"},
                {"port": "80", "protocol": "tcp", "service": "http"},
            ],
        },
    )
    scan = record_assessment_scan(
        assessment["id"],
        tool="nmap",
        status="completed",
        target_id=target["id"],
        finding_id=finding["id"],
        risk="medium",
    )
    artifact = add_assessment_artifact(assessment["id"], artifact_type="summary", title="Nmap Summary", content="SSH observed.")
    note = add_assessment_note(assessment["id"], "Customer approved testing.", note_type="scope")

    context = build_assessment_context(assessment["id"], user_id=8100)

    assert context["assessment"]["name"] == "Context Assessment"
    assert context["targets"] == [target]
    assert context["scans"][0]["id"] == scan["id"]
    assert context["scans"][0]["finding"]["id"] == finding["id"]
    assert context["findings"][0]["open_ports"][0]["service"] == "ssh"
    assert context["artifacts"] == [artifact]
    assert context["notes"] == [note]


def test_assessment_context_includes_httpx_evidence_when_present() -> None:
    assessment = create_assessment("httpx Context")
    target = add_assessment_target(assessment["id"], address="example.com", target_type="hostname")
    finding = add_finding(
        user_id=8101,
        finding={
            "source": "httpx",
            "target": "https://example.com",
            "risk_level": "info",
            "status": "completed",
            "summary": "httpx observed one HTTP service.",
            "httpx_services": [
                {
                    "url": "https://example.com",
                    "status_code": 200,
                    "title": "Example",
                    "web_server": "nginx",
                    "technologies": ["React"],
                }
            ],
        },
    )
    record_assessment_scan(
        assessment["id"],
        tool="httpx",
        status="completed",
        target_id=target["id"],
        finding_id=finding["id"],
        risk="info",
    )

    context = build_assessment_context(assessment["id"], user_id=8101)

    assert context["scans"][0]["tool"] == "httpx"
    assert context["scans"][0]["finding"]["httpx_services"][0]["title"] == "Example"
    assert context["findings"][0]["source"] == "httpx"


def test_assessment_context_includes_katana_evidence_when_present() -> None:
    assessment = create_assessment("Katana Context")
    target = add_assessment_target(assessment["id"], address="example.com", target_type="hostname")
    finding = add_finding(
        user_id=8102,
        finding={
            "source": "katana",
            "target": "https://example.com",
            "risk_level": "info",
            "status": "completed",
            "summary": "Katana observed one endpoint.",
            "katana_observations": [
                {
                    "url": "https://example.com/search?q=test",
                    "host": "example.com",
                    "path": "/search",
                    "endpoint_type": "parameterized_url",
                    "query_parameters": ["q"],
                    "depth": 2,
                }
            ],
        },
    )
    record_assessment_scan(
        assessment["id"],
        tool="katana",
        status="completed",
        target_id=target["id"],
        finding_id=finding["id"],
        risk="info",
    )

    context = build_assessment_context(assessment["id"], user_id=8102)

    assert context["scans"][0]["tool"] == "katana"
    assert context["scans"][0]["finding"]["katana_observations"][0]["query_parameters"] == ["q"]
    assert context["findings"][0]["source"] == "katana"
