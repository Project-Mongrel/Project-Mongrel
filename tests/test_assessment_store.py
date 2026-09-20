import asyncio
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.bot.bot import run_bot
from app.bot.handlers.assessment import ASSESSMENT_SCAN_CONTEXT_KEY, build_assessment_dashboard_text
from app.bot.handlers.scan import (
    ASSESSMENT_RUNNING_SCAN_GUARD_KEY,
    _finalize_assessment_scan_context_if_running,
    _record_assessment_scan,
    _start_current_assessment_scan,
    scan_target_handler,
)
from app.bot.handlers.upload import (
    _finalize_tshark_assessment_scan_if_running,
    _persist_tshark_assessment_evidence,
    _start_tshark_assessment_scan,
)
from app.core.config import Settings
from app.services.assessment_store import (
    add_assessment_artifact,
    add_assessment_note,
    add_assessment_target,
    create_assessment,
    finalize_assessment_scan,
    get_assessment,
    get_user_assessment,
    list_assessment_artifacts,
    list_assessment_notes,
    list_assessment_scans,
    list_assessment_targets,
    list_assessments,
    list_user_assessments,
    record_assessment_scan,
    recover_interrupted_assessment_scans,
    start_assessment_scan,
)
from app.services.findings_store import add_finding, close_findings_database, configure_findings_database, get_user_findings


@pytest.fixture(autouse=True)
def sqlite_assessment_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_create_assessment() -> None:
    assessment = create_assessment("External Pentest", description="Q3 perimeter review", user_id=101)

    assert isinstance(assessment["id"], int)
    assert assessment["user_id"] == 101
    assert assessment["name"] == "External Pentest"
    assert assessment["description"] == "Q3 perimeter review"
    assert assessment["status"] == "active"
    assert isinstance(assessment["created_at"], datetime)
    assert isinstance(assessment["updated_at"], datetime)
    assert get_assessment(assessment["id"]) == assessment
    assert get_user_assessment(101, assessment["id"]) == assessment
    assert get_user_assessment(202, assessment["id"]) is None


def test_list_assessments_and_status_filter() -> None:
    active = create_assessment("Active Assessment", user_id=101)
    create_assessment("Another Assessment", user_id=202)

    assessments = list_assessments()
    assert [assessment["name"] for assessment in assessments] == ["Active Assessment", "Another Assessment"]
    assert list_assessments(status="active")[0]["id"] == active["id"]
    assert list_assessments(status="archived") == []
    assert [assessment["name"] for assessment in list_user_assessments(101)] == ["Active Assessment"]


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
    playwright_scan = record_assessment_scan(assessment["id"], tool="playwright", status="completed", elapsed_seconds=6, risk="info")
    ffuf_scan = record_assessment_scan(assessment["id"], tool="ffuf", status="completed", elapsed_seconds=8, risk="info")

    assert nmap_scan["target_id"] == target["id"]
    assert nmap_scan["tool"] == "nmap"
    assert nmap_scan["status"] == "completed"
    assert nmap_scan["completed_at"] is not None
    assert nmap_scan["finding_id"] == "finding-nmap"
    assert bbot_scan["tool"] == "bbot"
    assert nuclei_scan["tool"] == "nuclei"
    assert httpx_scan["tool"] == "httpx"
    assert katana_scan["tool"] == "katana"
    assert playwright_scan["tool"] == "playwright"
    assert ffuf_scan["tool"] == "ffuf"
    assert [scan["tool"] for scan in list_assessment_scans(assessment["id"])] == ["nmap", "bbot", "nuclei", "httpx", "katana", "playwright", "ffuf"]


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


def test_startup_recovery_marks_only_abandoned_scans_interrupted() -> None:
    assessment = create_assessment("Restart Recovery", user_id=501)
    target = add_assessment_target(assessment["id"], address="example.com")
    running = start_assessment_scan(assessment["id"], "bbot", target_id=target["id"])
    completed = record_assessment_scan(assessment["id"], "nmap", "completed", target_id=target["id"])
    failed = record_assessment_scan(assessment["id"], "testssl", "failed", target_id=target["id"])
    cancelled = record_assessment_scan(assessment["id"], "ffuf", "cancelled", target_id=target["id"])

    assert recover_interrupted_assessment_scans() == 1
    scans = {scan["id"]: scan for scan in list_assessment_scans(assessment["id"])}
    assert scans[running["id"]]["status"] == "interrupted"
    assert scans[running["id"]]["completed_at"] is not None
    assert scans[running["id"]]["assessment_id"] == assessment["id"]
    assert scans[running["id"]]["target_id"] == target["id"]
    assert scans[completed["id"]]["status"] == "completed"
    assert scans[failed["id"]]["status"] == "failed"
    assert scans[cancelled["id"]]["status"] == "cancelled"


def test_startup_recovery_is_idempotent_and_preserves_ownership_isolation() -> None:
    first = create_assessment("First owner", user_id=601)
    second = create_assessment("Second owner", user_id=602)
    first_scan = start_assessment_scan(first["id"], "nmap")
    second_scan = start_assessment_scan(second["id"], "bbot")

    assert recover_interrupted_assessment_scans() == 2
    assert recover_interrupted_assessment_scans() == 0
    assert get_user_assessment(601, first["id"]) is not None
    assert get_user_assessment(601, second["id"]) is None
    assert list_assessment_scans(first["id"])[0]["id"] == first_scan["id"]
    assert list_assessment_scans(second["id"])[0]["id"] == second_scan["id"]
    assert list_assessment_scans(first["id"])[0]["status"] == "interrupted"
    assert list_assessment_scans(second["id"])[0]["status"] == "interrupted"


def test_completion_and_recovery_use_one_atomic_terminal_transition() -> None:
    assessment = create_assessment("Transition race", user_id=701)

    completion_wins = start_assessment_scan(assessment["id"], "nmap")
    finalized = finalize_assessment_scan(
        assessment["id"],
        completion_wins["id"],
        "completed",
        elapsed_seconds=7,
        raw_reference="finding:one",
    )
    assert finalized["status"] == "completed"
    assert recover_interrupted_assessment_scans() == 0
    assert list_assessment_scans(assessment["id"])[0]["status"] == "completed"

    recovery_wins = start_assessment_scan(assessment["id"], "bbot")
    assert recover_interrupted_assessment_scans() == 1
    stale_completion = finalize_assessment_scan(
        assessment["id"],
        recovery_wins["id"],
        "completed",
        elapsed_seconds=9,
    )
    assert stale_completion["status"] == "interrupted"
    assert stale_completion["elapsed_seconds"] is None


def test_bot_startup_recovers_abandoned_scan_without_retrying_it() -> None:
    assessment = create_assessment("Service restart", user_id=801)
    abandoned = start_assessment_scan(assessment["id"], "testssl")
    application = SimpleNamespace(run_polling=lambda **_kwargs: None, bot_data={})

    with patch("app.bot.bot.build_application", return_value=application):
        run_bot(Settings(_env_file=None, telegram_bot_token="123456:TEST"))

    recovered = list_assessment_scans(assessment["id"])
    assert len(recovered) == 1
    assert recovered[0]["id"] == abandoned["id"]
    assert recovered[0]["status"] == "interrupted"
    dashboard = build_assessment_dashboard_text(assessment, [], recovered)
    assert "testssl.sh: Interrupted" in dashboard


def test_assessment_handler_lifecycle_updates_one_durable_scan_row() -> None:
    assessment = create_assessment("Durable handler scan", user_id=901)
    target = add_assessment_target(assessment["id"], address="example.com")
    assessment_context = {
        "assessment_id": assessment["id"],
        "target_id": target["id"],
        "tool": "ffuf",
    }
    context = SimpleNamespace(user_data={ASSESSMENT_SCAN_CONTEXT_KEY: assessment_context})

    _start_current_assessment_scan(context, "ffuf")
    running = list_assessment_scans(assessment["id"])
    assert len(running) == 1
    assert running[0]["status"] == "running"

    terminal = _record_assessment_scan(
        assessment_context,
        tool="ffuf",
        result={"success": False, "error_type": "cancelled", "elapsed_seconds": 4},
    )
    scans = list_assessment_scans(assessment["id"])
    assert len(scans) == 1
    assert terminal is not None
    assert terminal["id"] == running[0]["id"]
    assert terminal["status"] == "cancelled"
    assert terminal["completed_at"] is not None


def test_tshark_assessment_persistence_finalizes_its_durable_scan_row() -> None:
    assessment = create_assessment("Durable TShark scan", user_id=902)
    assessment_context = {"assessment_id": assessment["id"]}

    _start_tshark_assessment_scan(assessment_context)
    assert list_assessment_scans(assessment["id"])[0]["status"] == "running"

    _persist_tshark_assessment_evidence(
        assessment_context,
        {"success": True, "elapsed_seconds": 3},
        {"packet_count": 0, "total_bytes": 0, "protocols": [], "endpoints": []},
    )
    scans = list_assessment_scans(assessment["id"])
    assert len(scans) == 1
    assert scans[0]["status"] == "completed"
    artifacts = list_assessment_artifacts(assessment["id"])
    assert len(artifacts) == 1
    assert artifacts[0]["scan_id"] == scans[0]["id"]


@pytest.mark.parametrize("failure_stage", ["validation", "runner", "parser", "delivery", "unexpected"])
def test_scan_handler_exception_guard_finalizes_one_running_row(failure_stage: str) -> None:
    assessment = create_assessment(f"Guard {failure_stage}", user_id=903)
    running = start_assessment_scan(assessment["id"], "ffuf")
    assessment_context = {
        "assessment_id": assessment["id"],
        "tool": "ffuf",
        "assessment_scan_id": running["id"],
    }
    context = SimpleNamespace(user_data={ASSESSMENT_RUNNING_SCAN_GUARD_KEY: assessment_context})

    with patch("app.bot.handlers.scan._scan_target_handler_impl", side_effect=RuntimeError(failure_stage)):
        with pytest.raises(RuntimeError, match=failure_stage):
            asyncio.run(scan_target_handler(SimpleNamespace(), context))

    scans = list_assessment_scans(assessment["id"])
    assert len(scans) == 1
    assert scans[0]["id"] == running["id"]
    assert scans[0]["status"] == "failed"
    assert ASSESSMENT_RUNNING_SCAN_GUARD_KEY not in context.user_data


def test_fallback_finalization_never_overwrites_existing_terminal_state() -> None:
    assessment = create_assessment("Terminal winner", user_id=904)
    running = start_assessment_scan(assessment["id"], "bbot")
    context = {"assessment_id": assessment["id"], "assessment_scan_id": running["id"]}
    finalize_assessment_scan(assessment["id"], running["id"], "completed", elapsed_seconds=2)

    terminal = _finalize_assessment_scan_context_if_running(context, status="failed")

    assert terminal is not None
    assert terminal["status"] == "completed"
    assert terminal["elapsed_seconds"] == 2
    assert len(list_assessment_scans(assessment["id"])) == 1


def test_tshark_exception_guard_finalizes_without_creating_second_row() -> None:
    assessment = create_assessment("TShark exception", user_id=905)
    context = {"assessment_id": assessment["id"]}
    _start_tshark_assessment_scan(context)

    terminal = _finalize_tshark_assessment_scan_if_running(context)

    assert terminal is not None
    assert terminal["status"] == "failed"
    assert len(list_assessment_scans(assessment["id"])) == 1
