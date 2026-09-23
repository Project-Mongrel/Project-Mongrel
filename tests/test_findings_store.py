import pytest

from app.services.assessment_map_ingestion import ingest_assessment_scan
from app.services.assessment_store import create_assessment, record_assessment_scan
from app.services.findings_store import (
    _get_connection,
    add_finding,
    add_report_metadata,
    clear_user_findings,
    clear_user_reports,
    close_findings_database,
    configure_findings_database,
    get_latest_user_finding_for_target,
    get_latest_user_report,
    get_user_report,
    get_user_reports,
    get_user_scan_runs,
    get_user_findings,
)


@pytest.fixture(autouse=True)
def sqlite_findings_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_add_finding() -> None:
    clear_user_findings(2001)

    finding = add_finding(
        user_id=2001,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "host_status": "Up",
            "open_ports": [],
            "duration": "0.32s",
        },
    )

    assert finding["id"]
    assert finding["user_id"] == 2001
    assert finding["source"] == "nmap"
    assert finding["created_at"] is not None


def test_get_user_findings() -> None:
    clear_user_findings(2002)
    first_finding = add_finding(user_id=2002, finding={"source": "nmap", "target": "one"})
    second_finding = add_finding(user_id=2002, finding={"source": "nmap", "target": "two"})

    assert get_user_findings(2002) == [first_finding, second_finding]


def test_user_isolation() -> None:
    clear_user_findings(2003)
    clear_user_findings(9999)
    finding = add_finding(user_id=2003, finding={"source": "nmap", "target": "mine"})
    add_finding(user_id=9999, finding={"source": "nmap", "target": "theirs"})

    assert get_user_findings(2003) == [finding]


def test_clear_findings() -> None:
    clear_user_findings(2004)
    add_finding(user_id=2004, finding={"source": "nmap", "target": "127.0.0.1"})

    clear_user_findings(2004)

    assert get_user_findings(2004) == []


def test_clear_findings_removes_user_map_references_without_cross_user_deletion() -> None:
    first = create_assessment("Mapped finding cleanup", user_id=2013)
    second = create_assessment("Other mapped finding cleanup", user_id=2014)
    first_finding = add_finding(
        user_id=2013,
        finding={
            "source": "nmap",
            "target": "owned.example",
            "host_status": "up",
            "open_ports": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https"}],
        },
    )
    second_finding = add_finding(
        user_id=2014,
        finding={
            "source": "nmap",
            "target": "other.example",
            "host_status": "up",
            "open_ports": [{"port": "80", "protocol": "tcp", "state": "open", "service": "http"}],
        },
    )
    first_scan = record_assessment_scan(
        first["id"], tool="nmap", status="completed", finding_id=first_finding["id"]
    )
    second_scan = record_assessment_scan(
        second["id"], tool="nmap", status="completed", finding_id=second_finding["id"]
    )
    ingest_assessment_scan(user_id=2013, assessment_id=first["id"], scan_id=first_scan["id"])
    ingest_assessment_scan(user_id=2014, assessment_id=second["id"], scan_id=second_scan["id"])

    clear_user_findings(2013)

    connection = _get_connection()
    assert get_user_findings(2013) == []
    assert get_user_findings(2014) == [second_finding]
    assert connection.execute(
        "SELECT COUNT(*) FROM assessment_map_evidence_links WHERE user_id = ?",
        (2013,),
    ).fetchone()[0] == 0
    assert connection.execute(
        "SELECT COUNT(*) FROM assessment_map_evidence_links WHERE user_id = ?",
        (2014,),
    ).fetchone()[0] > 0


def test_previous_lookup_works_with_target_key() -> None:
    clear_user_findings(2005)
    finding = add_finding(
        user_id=2005,
        finding={
            "source": "nmap",
            "target": "localhost (127.0.0.1)",
            "target_key": "127.0.0.1",
        },
    )

    assert get_latest_user_finding_for_target(2005, "127.0.0.1") == finding


def test_previous_lookup_fallback_works_without_target_key() -> None:
    clear_user_findings(2006)
    finding = add_finding(
        user_id=2006,
        finding={
            "source": "nmap",
            "target": "DESKTOP-MSP5KSM (192.168.0.24)",
        },
    )

    assert get_latest_user_finding_for_target(2006, "192.168.0.24") == finding


def test_previous_lookup_filters_by_source() -> None:
    clear_user_findings(2012)
    nmap_finding = add_finding(
        user_id=2012,
        finding={"source": "nmap", "target": "127.0.0.1", "risk_level": "high"},
    )
    add_finding(
        user_id=2012,
        finding={"source": "nuclei", "target": "127.0.0.1", "risk_level": "info", "status": "clean", "finding_count": 0},
    )

    assert get_latest_user_finding_for_target(2012, "localhost (127.0.0.1)", sources={"nmap", "nmap_xml"}) == nmap_finding


def test_scan_history_is_saved() -> None:
    clear_user_findings(2007)
    finding = add_finding(
        user_id=2007,
        finding={
            "source": "nuclei",
            "target": "https://example.com",
            "risk_level": "high",
            "finding_count": 2,
            "summary": "Nuclei findings were identified.",
            "nuclei_findings": [{"template_id": "one"}, {"template_id": "two"}],
        },
    )

    scan_runs = get_user_scan_runs(2007)

    assert len(scan_runs) == 1
    assert scan_runs[0]["scan_run_id"] == finding["scan_run_id"]
    assert scan_runs[0]["source"] == "nuclei"
    assert scan_runs[0]["target"] == "https://example.com"
    assert scan_runs[0]["risk_level"] == "high"
    assert scan_runs[0]["finding_count"] == 2


def test_findings_are_loaded_from_sqlite_after_connection_reload() -> None:
    clear_user_findings(2008)
    finding = add_finding(
        user_id=2008,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
            "comparison": {"has_previous": False, "summary": "No previous scan found for this target."},
        },
    )

    close_findings_database()

    assert get_user_findings(2008) == [finding]
    assert get_latest_user_finding_for_target(2008, "127.0.0.1") == finding


def test_clean_nuclei_scan_is_stored() -> None:
    clear_user_findings(2009)
    finding = add_finding(
        user_id=2009,
        finding={
            "source": "nuclei",
            "target": "hellosundaykids.com",
            "risk_level": "info",
            "finding_count": 0,
            "status": "clean",
            "summary": "No matching Nuclei findings were identified using the fast scan profile.",
        },
    )

    stored_findings = get_user_findings(2009)
    scan_runs = get_user_scan_runs(2009)

    assert stored_findings == [finding]
    assert scan_runs[0]["status"] == "clean"
    assert scan_runs[0]["finding_count"] == 0
    assert scan_runs[0]["summary"] == "No matching Nuclei findings were identified using the fast scan profile."


def test_add_and_get_report_metadata() -> None:
    clear_user_reports(2010)
    report = add_report_metadata(
        user_id=2010,
        metadata={
            "target": "example.com",
            "report_type": "deterministic",
            "title": "Deterministic Security Report",
            "summary": "Generated from one scan.",
            "overall_risk": "medium",
            "source_count": 1,
            "scan_count": 1,
        },
    )

    assert report["id"]
    assert report["user_id"] == 2010
    assert get_user_reports(2010) == [report]
    assert get_user_report(2010, report["id"]) == report
    assert get_latest_user_report(2010) == report


def test_report_metadata_survives_connection_reload() -> None:
    clear_user_reports(2011)
    report = add_report_metadata(
        user_id=2011,
        metadata={
            "target": "all targets",
            "report_type": "ai_assessment",
            "title": "AI Assessment Report",
            "summary": "Generated from two scans.",
            "overall_risk": "high",
            "source_count": 2,
            "scan_count": 2,
        },
    )

    close_findings_database()

    assert get_user_reports(2011) == [report]
    assert get_latest_user_report(2011) == report
