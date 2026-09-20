from datetime import UTC, datetime

import pytest

from app.bot.handlers.assessment import build_assessment_dashboard_text, build_assessment_history_text
from app.services.assessment_conversation_context import _build_recommendation_context
from app.services.assessment_markdown_report import generate_assessment_markdown_report
from app.bot.handlers.scan import _record_assessment_scan, _scan_event_outcome
from app.services.assessment_store import (
    create_assessment,
    list_assessment_scans,
    record_assessment_scan,
    start_assessment_scan,
)
from app.services.findings_store import _get_connection, close_findings_database, configure_findings_database
from app.services.mongrel_self_knowledge import get_mongrel_tool_names
from app.services.scan_status import normalize_scan_status, scan_status_from_result, scan_status_label


@pytest.fixture(autouse=True)
def isolated_database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


@pytest.mark.parametrize(
    ("stored", "canonical"),
    [
        ("active", "running"),
        ("in_progress", "running"),
        ("complete", "completed"),
        ("succeeded", "completed"),
        ("error", "failed"),
        ("timeout", "timed_out"),
        ("timed out", "timed_out"),
        ("canceled", "cancelled"),
        ("aborted", "interrupted"),
    ],
)
def test_legacy_scan_statuses_normalize_only_when_read(stored: str, canonical: str) -> None:
    assessment = create_assessment(f"Legacy {stored}", user_id=10)
    scan = record_assessment_scan(assessment["id"], "nmap", "failed")
    with _get_connection() as connection:
        connection.execute("UPDATE assessment_scans SET status = ? WHERE id = ?", (stored, scan["id"]))

    assert list_assessment_scans(assessment["id"])[0]["status"] == canonical
    raw_status = _get_connection().execute(
        "SELECT status FROM assessment_scans WHERE id = ?", (scan["id"],)
    ).fetchone()["status"]
    assert raw_status == stored


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"success": True}, "completed"),
        ({"success": False}, "failed"),
        ({"success": False, "partial": True, "error_type": "timeout"}, "partial"),
        ({"success": False, "error_type": "timeout"}, "timed_out"),
        ({"success": False, "timed_out": True}, "timed_out"),
        ({"success": False, "error_type": "cancelled"}, "cancelled"),
    ],
)
def test_result_classification_preserves_truthful_terminal_state(result: dict, expected: str) -> None:
    assert scan_status_from_result(result) == expected


def test_all_canonical_statuses_render_consistently_in_dashboard_history_report_and_ask() -> None:
    assessment = create_assessment("Status matrix", user_id=20)
    statuses = (
        ("nmap", "running"),
        ("bbot", "completed"),
        ("nuclei", "failed"),
        ("httpx", "partial"),
        ("katana", "timed_out"),
        ("playwright", "cancelled"),
        ("ffuf", "interrupted"),
    )
    for tool, status in statuses:
        record_assessment_scan(assessment["id"], tool, status)
    scans = list_assessment_scans(assessment["id"])

    dashboard = build_assessment_dashboard_text(assessment, [], scans)
    history = build_assessment_history_text(assessment, scans)
    report = generate_assessment_markdown_report(
        {"assessment": assessment, "targets": [], "scans": scans, "artifacts": []}
    )
    ask_context = _build_recommendation_context("Which tools have run?", {"scans": scans})

    expected_states = {
        "nmap": "RUNNING",
        "bbot": "COMPLETED",
        "nuclei": "FAILED",
        "httpx": "PARTIAL",
        "katana": "TIMED_OUT",
        "playwright": "CANCELLED",
        "ffuf": "INTERRUPTED",
    }
    assert ask_context["tool_states"] | expected_states == ask_context["tool_states"]
    for tool, status in statuses:
        label = scan_status_label(status)
        assert label in dashboard
        assert label in history
        assert label in report
    assert "Completion records execution state" not in report
    assert "does not establish" in report


def test_completed_status_is_execution_state_not_security_outcome() -> None:
    assessment = create_assessment("Completion boundary", user_id=30)
    record_assessment_scan(assessment["id"], "nmap", "completed")
    report = generate_assessment_markdown_report(
        {
            "assessment": {**assessment, "created_at": datetime.now(UTC), "updated_at": datetime.now(UTC)},
            "targets": [],
            "scans": list_assessment_scans(assessment["id"]),
            "artifacts": [],
        }
    )
    assert "Completed" in report
    assert "Absence of findings is not evidence of security" in report
    assert "target is secure" not in report.lower()


def test_scan_status_labels_do_not_expose_storage_spelling() -> None:
    assert normalize_scan_status("TIMED-OUT") == "timed_out"
    assert scan_status_label("timed_out") == "Timed out"


def test_all_twelve_tools_share_the_same_canonical_timeout_status() -> None:
    assessment = create_assessment("All tool statuses", user_id=40)
    tools = [name.lower().removesuffix(".sh") for name in get_mongrel_tool_names()]
    assert len(tools) == 12
    for tool in tools:
        record_assessment_scan(assessment["id"], tool, "timed_out")

    scans = list_assessment_scans(assessment["id"])
    assert {scan["tool"] for scan in scans} == set(tools)
    assert {scan["status"] for scan in scans} == {"timed_out"}
    states = _build_recommendation_context("Which tools timed out?", {"scans": scans})["tool_states"]
    assert all(states[tool] == "TIMED_OUT" for tool in tools)


@pytest.mark.parametrize("tool", [name.lower().removesuffix(".sh") for name in get_mongrel_tool_names()])
def test_all_twelve_assessment_writers_persist_timeout_without_partial_evidence(tool: str) -> None:
    assessment = create_assessment(f"Timeout {tool}", user_id=41)
    running = start_assessment_scan(assessment["id"], tool)
    context = {"assessment_id": assessment["id"], "tool": tool, "assessment_scan_id": running["id"]}

    terminal = _record_assessment_scan(
        context,
        tool=tool,
        result={"success": False, "error_type": "timeout"},
    )

    assert terminal is not None
    assert terminal["id"] == running["id"]
    assert terminal["status"] == "timed_out"
    assert len(list_assessment_scans(assessment["id"])) == 1


def test_usable_partial_evidence_precedes_timeout_status() -> None:
    assessment = create_assessment("Partial timeout", user_id=42)
    running = start_assessment_scan(assessment["id"], "nuclei")

    terminal = _record_assessment_scan(
        {"assessment_id": assessment["id"], "tool": "nuclei", "assessment_scan_id": running["id"]},
        tool="nuclei",
        result={"success": False, "partial": True, "error_type": "timeout"},
    )

    assert terminal is not None
    assert terminal["status"] == "partial"


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"success": True}, ("completed", "completed", "completed")),
        ({"success": False, "partial": True, "error_type": "timeout"}, ("partial", "partial", "completed partially")),
        ({"success": False, "error_type": "timeout"}, ("timed_out", "timed_out", "timed out")),
        ({"success": False, "error_type": "cancelled"}, ("cancelled", "cancelled", "cancelled")),
        ({"success": False, "error_type": "execution_failed"}, ("failed", "failed", "failed")),
    ],
)
def test_investigation_event_outcome_preserves_canonical_result_status(result: dict, expected: tuple[str, str, str]) -> None:
    assert _scan_event_outcome(result) == expected
