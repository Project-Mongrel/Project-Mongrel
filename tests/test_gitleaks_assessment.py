import pytest

from app.bot.handlers.assessment import build_assessment_dashboard_keyboard, build_assessment_dashboard_text
from app.bot.handlers.scan import build_gitleaks_result_text, store_gitleaks_scan_result
from app.parsers.gitleaks_parser import contains_unredacted_secret, normalize_gitleaks_output
from app.services.assessment_ai import build_assessment_ai_prompt
from app.services.assessment_context import build_assessment_context
from app.services.assessment_guard import build_assessment_guard
from app.services.assessment_markdown_report import generate_assessment_markdown_report
from app.services.assessment_store import add_assessment_target, create_assessment, list_assessment_scans, record_assessment_scan
from app.services.findings_store import close_findings_database, configure_findings_database

RAW_SECRET = "ghp_1234567890abcdefghijklmnopqrstuv"
GITLEAKS_JSON = f"""
[
  {{
    "RuleID": "github-pat",
    "Description": "GitHub Personal Access Token",
    "File": "src/config.py",
    "StartLine": 12,
    "Secret": "{RAW_SECRET}",
    "Entropy": 4.9,
    "Fingerprint": "abc123"
  }}
]
"""


@pytest.fixture(autouse=True)
def sqlite_gitleaks_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _stored_context() -> dict:
    assessment = create_assessment("Secrets Assessment")
    target = add_assessment_target(assessment["id"], address="/tmp/artifact", target_type="artifact_dir")
    evidence = normalize_gitleaks_output(GITLEAKS_JSON, scan_root="/tmp/artifact")
    result = {"success": True, "target": "/tmp/artifact", "elapsed_seconds": 2, "returncode": 1, "command": ["gitleaks"]}
    finding = store_gitleaks_scan_result(user_id=9200, result=result, evidence=evidence)
    record_assessment_scan(
        assessment["id"],
        tool="gitleaks",
        status="completed",
        target_id=target["id"],
        finding_id=finding["id"],
        risk="high",
    )
    return build_assessment_context(assessment["id"], user_id=9200)


def test_assessment_context_includes_redacted_gitleaks_evidence() -> None:
    context = _stored_context()

    assert context["scans"][0]["tool"] == "gitleaks"
    assert context["findings"][0]["source"] == "gitleaks"
    assert context["findings"][0]["gitleaks_evidence"]["findings"][0]["rule_id"] == "github-pat"
    assert not contains_unredacted_secret(context, RAW_SECRET)


def test_guard_recognizes_gitleaks_and_removes_locked_limitation() -> None:
    guard = build_assessment_guard(_stored_context())

    assert "gitleaks" in guard["completed_tools"]
    assert "Gitleaks not run" not in guard["locked_tool_limitations"]
    assert any("gitleaks github-pat" in value for value in guard["observed_assets"]["services"])


def test_dashboard_shows_gitleaks_status_and_button() -> None:
    assessment = create_assessment("Dashboard Secrets")
    record_assessment_scan(assessment["id"], tool="gitleaks", status="completed", elapsed_seconds=2, risk="high")
    dashboard = build_assessment_dashboard_text(assessment, [{"address": "/tmp/artifact"}], list_assessment_scans(assessment["id"]))
    keyboard = build_assessment_dashboard_keyboard(assessment["id"])
    buttons = [button.text for row in keyboard.inline_keyboard for button in row]

    assert "Gitleaks: Completed" in dashboard
    assert "Run Gitleaks" in buttons


def test_gitleaks_telegram_card_never_displays_raw_secret() -> None:
    evidence = normalize_gitleaks_output(GITLEAKS_JSON, scan_root="/tmp/artifact")
    card = build_gitleaks_result_text(
        {"success": True, "target": "/tmp/artifact", "elapsed_seconds": 2, "output": RAW_SECRET},
        evidence,
    )

    assert "Gitleaks Scan Complete" in card
    assert "Secret findings: 1" in card
    assert "Affected files: 1" in card
    assert "github-pat" in card
    assert "<REDACTED>" in card
    assert RAW_SECRET not in card


def test_markdown_report_includes_redacted_gitleaks_section() -> None:
    report = generate_assessment_markdown_report(_stored_context())

    assert "### Gitleaks" in report
    assert "Secret findings: 1" in report
    assert "github-pat" in report
    assert "<REDACTED>" in report
    assert RAW_SECRET not in report


def test_assessment_ai_prompt_includes_redacted_gitleaks_constraints() -> None:
    prompt = build_assessment_ai_prompt("What secrets were found?", _stored_context())

    assert "Treat Gitleaks detections as redacted secret-exposure evidence only." in prompt
    assert "Never include raw secret values" in prompt
    assert "Gitleaks redacted secret-exposure evidence" in prompt
    assert "<REDACTED>" in prompt
    assert RAW_SECRET not in prompt
