import pytest

from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.investigation_store import (
    add_investigation_event,
    clear_user_investigations,
    complete_investigation,
    create_investigation,
    get_investigation,
    get_investigation_events,
    get_latest_investigation_for_target,
    get_user_investigations,
    update_investigation_summary,
)


@pytest.fixture(autouse=True)
def sqlite_findings_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_create_investigation() -> None:
    clear_user_investigations(12001)

    investigation = create_investigation(
        user_id=12001,
        target="hellosundaykids.com",
        name="Hello Sunday Kids Website",
        client_name="Hello Sunday Kids",
    )

    assert investigation["id"]
    assert investigation["name"] == "Hello Sunday Kids Website"
    assert investigation["client_name"] == "Hello Sunday Kids"
    assert investigation["target"] == "hellosundaykids.com"
    assert investigation["status"] == "open"
    assert get_user_investigations(12001) == [investigation]


def test_auto_generated_investigation_name() -> None:
    investigation = create_investigation(user_id=12002, target="127.0.0.1")

    assert investigation["name"].startswith("Investigation - 127.0.0.1 - ")


def test_add_and_get_investigation_events() -> None:
    investigation = create_investigation(user_id=12003, target="127.0.0.1")

    event = add_investigation_event(
        investigation_id=investigation["id"],
        user_id=12003,
        target="127.0.0.1",
        event_type="nmap_scan_started",
        tool="nmap",
        status="started",
        summary="Nmap scan started",
    )

    assert get_investigation_events(investigation["id"], 12003) == [event]


def test_get_latest_investigation_for_target() -> None:
    create_investigation(user_id=12004, target="localhost (127.0.0.1)")
    latest = create_investigation(user_id=12004, target="127.0.0.1")

    assert get_latest_investigation_for_target(12004, "127.0.0.1") == latest


def test_complete_and_update_investigation() -> None:
    investigation = create_investigation(user_id=12005, target="example.com")

    updated = update_investigation_summary(investigation["id"], 12005, summary="High risk exposure.", overall_risk="high")
    completed = complete_investigation(investigation["id"], 12005)

    assert updated["summary"] == "High risk exposure."
    assert updated["overall_risk"] == "high"
    assert completed["status"] == "completed"
    assert completed["completed_at"] is not None


def test_investigations_survive_connection_reload() -> None:
    investigation = create_investigation(user_id=12006, target="example.com")
    event = add_investigation_event(
        investigation_id=investigation["id"],
        user_id=12006,
        target="example.com",
        event_type="report_generated",
        tool="report",
        status="completed",
        summary="Report generated",
    )

    close_findings_database()

    assert get_investigation(investigation["id"], 12006) == investigation
    assert get_investigation_events(investigation["id"], 12006) == [event]
