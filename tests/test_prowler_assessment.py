import pytest

from app.bot.handlers.assessment import build_assessment_dashboard_keyboard, build_assessment_dashboard_text
from app.bot.handlers.scan import store_prowler_scan_result
from app.parsers.prowler_parser import normalize_prowler_output
from app.services.assessment_context import build_assessment_context
from app.services.assessment_guard import build_assessment_guard
from app.services.assessment_markdown_report import generate_assessment_markdown_report
from app.services.assessment_store import add_assessment_target, create_assessment, list_assessment_scans, record_assessment_scan
from app.services.findings_store import close_findings_database, configure_findings_database


@pytest.fixture(autouse=True)
def sqlite_prowler_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _stored_prowler_context() -> dict:
    assessment = create_assessment("Cloud Assessment")
    target = add_assessment_target(assessment["id"], address="aws", target_type="cloud_provider")
    evidence = normalize_prowler_output(
        [
            {
                "metadata": {"event_code": "iam_check", "product": {"feature": {"name": "iam"}}},
                "cloud": {"provider": "aws", "region": "global"},
                "finding_info": {"uid": "finding-001", "title": "IAM check"},
                "status_code": "FAIL",
                "severity": "Medium",
                "resources": [{"uid": "resource-001", "name": "synthetic-resource", "region": "global"}],
            }
        ],
        provider="aws",
    )
    result = {"success": True, "provider": "aws", "cloud_context": "assessment-aws", "elapsed_seconds": 3, "returncode": 0, "command": ["prowler", "aws"]}
    evidence["cloud_context"] = "assessment-aws"
    finding = store_prowler_scan_result(user_id=9400, result=result, evidence=evidence)
    record_assessment_scan(
        assessment["id"],
        tool="prowler",
        status="completed",
        target_id=target["id"],
        finding_id=finding["id"],
        risk="info",
    )
    return build_assessment_context(assessment["id"], user_id=9400)


def test_dashboard_shows_prowler_status_and_button() -> None:
    assessment = create_assessment("Cloud Dashboard")
    record_assessment_scan(assessment["id"], tool="prowler", status="completed", elapsed_seconds=3, risk="info")
    dashboard = build_assessment_dashboard_text(assessment, [{"address": "aws"}], list_assessment_scans(assessment["id"]))
    keyboard = build_assessment_dashboard_keyboard(assessment["id"])
    buttons = [button.text for row in keyboard.inline_keyboard for button in row]

    assert "Prowler: Completed" in dashboard
    assert "Run Prowler" in buttons


def test_assessment_context_contains_normalized_prowler_evidence_only() -> None:
    context = _stored_prowler_context()
    finding = context["findings"][0]

    assert context["scans"][0]["tool"] == "prowler"
    assert finding["source"] == "prowler"
    assert finding["provider"] == "aws"
    assert finding["cloud_context"] == "assessment-aws"
    assert finding["target"] == "assessment-aws"
    assert finding["prowler_evidence"]["findings"][0]["status"] == "FAIL"
    assert finding["prowler_evidence"]["findings"][0]["status_interpretation"] == "scanner_reported_failed_check"
    assert "secret" not in str(context).lower()
    assert "token" not in str(context).lower()


def test_guard_recognizes_prowler_and_preserves_scanner_confidence() -> None:
    guard = build_assessment_guard(_stored_prowler_context())

    assert "prowler" in guard["completed_tools"]
    assert "ScoutSuite/Prowler not run" not in guard["locked_tool_limitations"]
    assert any("prowler FAIL iam_check iam" in value for value in guard["observed_assets"]["services"])


def test_assessment_markdown_report_includes_prowler_provider_context_and_failed_checks() -> None:
    report = generate_assessment_markdown_report(_stored_prowler_context())

    assert "### Prowler" in report
    assert "- Provider: AWS" in report
    assert "- Context: assessment-aws" in report
    assert "- Total checks/findings parsed: 1" in report
    assert "- Failed checks: 1" in report
    assert "- Highest scanner-reported severity: Medium" in report
    assert "- FAIL iam_check severity=Medium service=iam" in report
    assert "PASS results are specific check passes, not proof" in report
    assert "FAIL results are scanner-reported failed checks, not confirmed exploitability, compromise, attacker access, data exposure" in report
    assert "Prowler severity and compliance mappings are scanner metadata" in report
    assert "organization-wide non-compliance" in report
    assert "resource/account is secure" in report
    assert "{\"" not in report
