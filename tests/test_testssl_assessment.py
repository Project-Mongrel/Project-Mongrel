import pytest

from app.bot.handlers.assessment import build_assessment_dashboard_keyboard, build_assessment_dashboard_text
from app.bot.handlers.scan import build_testssl_result_text, store_testssl_scan_result
from app.parsers.testssl_parser import normalize_testssl_output
from app.services.assessment_ai import build_assessment_ai_prompt
from app.services.assessment_context import build_assessment_context
from app.services.assessment_guard import build_assessment_guard
from app.services.assessment_markdown_report import generate_assessment_markdown_report
from app.services.assessment_store import add_assessment_target, create_assessment, list_assessment_scans, record_assessment_scan
from app.services.findings_store import close_findings_database, configure_findings_database


TESTSSL_JSON = """
[
  {"id":"cert_commonName","severity":"INFO","finding":"example.com"},
  {"id":"cert_issuer","severity":"INFO","finding":"Example CA"},
  {"id":"cert_notAfter","severity":"INFO","finding":"2030-01-01 00:00 +0000"},
  {"id":"TLS1","severity":"LOW","finding":"offered"},
  {"id":"TLS1_2","severity":"OK","finding":"offered"},
  {"id":"heartbleed","severity":"OK","finding":"not vulnerable"},
  {"id":"HSTS","severity":"INFO","finding":"max-age=31536000"}
]
"""


@pytest.fixture(autouse=True)
def sqlite_testssl_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _stored_context() -> dict:
    assessment = create_assessment("TLS Assessment")
    target = add_assessment_target(assessment["id"], address="example.com", target_type="hostname")
    evidence = normalize_testssl_output(TESTSSL_JSON, target="example.com:443")
    result = {"success": True, "target": "example.com:443", "elapsed_seconds": 4, "returncode": 0, "command": ["testssl.sh"]}
    finding = store_testssl_scan_result(user_id=9100, result=result, evidence=evidence)
    record_assessment_scan(
        assessment["id"],
        tool="testssl",
        status="completed",
        target_id=target["id"],
        finding_id=finding["id"],
        risk="info",
    )
    return build_assessment_context(assessment["id"], user_id=9100)


def test_assessment_context_includes_testssl_evidence_when_present() -> None:
    context = _stored_context()

    assert context["scans"][0]["tool"] == "testssl"
    assert context["findings"][0]["source"] == "testssl"
    assert context["findings"][0]["testssl_evidence"]["certificate"]["issuer"] == "Example CA"


def test_assessment_guard_recognizes_testssl_and_observed_tls_assets() -> None:
    guard = build_assessment_guard(_stored_context())

    assert "testssl" in guard["completed_tools"]
    assert "testssl.sh not run" not in guard["locked_tool_limitations"]
    assert "example.com" in guard["observed_assets"]["hosts"]
    assert "weak TLS: TLS 1.0: offered" in guard["observed_assets"]["services"]


def test_dashboard_shows_testssl_status_and_button() -> None:
    assessment = create_assessment("Dashboard TLS")
    record_assessment_scan(assessment["id"], tool="testssl", status="completed", elapsed_seconds=4, risk="info")
    dashboard = build_assessment_dashboard_text(assessment, [{"address": "example.com"}], list_assessment_scans(assessment["id"]))
    keyboard = build_assessment_dashboard_keyboard(assessment["id"])
    buttons = [button.text for row in keyboard.inline_keyboard for button in row]

    assert "testssl.sh: Completed" in dashboard
    assert "testssl.sh TLS" in buttons


def test_testssl_telegram_card_is_deterministic_and_not_raw_stdout() -> None:
    evidence = normalize_testssl_output(TESTSSL_JSON, target="example.com:443")
    card = build_testssl_result_text(
        {"success": True, "target": "example.com:443", "elapsed_seconds": 3, "output": "very noisy stdout"},
        evidence,
    )

    assert "testssl.sh Scan Complete" in card
    assert "Certificate: CN=example.com; Issuer=Example CA" in card
    assert "TLS 1.0" in card
    assert "Weak/deprecated" in card
    assert "very noisy stdout" not in card
    assert "TLS configuration evidence only" in card


def test_markdown_report_includes_testssl_section() -> None:
    report = generate_assessment_markdown_report(_stored_context())

    assert "### testssl.sh" in report
    assert "Certificate issuer: Example CA" in report
    assert "Weak/deprecated items: TLS 1.0: offered" in report
    assert "TLS configuration evidence only" in report


def test_ai_prompt_includes_grounded_testssl_constraints_and_evidence() -> None:
    prompt = build_assessment_ai_prompt("What does TLS evidence show?", _stored_context())

    assert "Treat testssl.sh results as TLS configuration evidence only." in prompt
    assert "Do not invent TLS vulnerabilities" in prompt
    assert "Preserve testssl.sh severity, scanner wording, and uncertainty exactly" in prompt
    assert "testssl.sh TLS evidence" in prompt
    assert "issuer=Example CA" in prompt


def test_testssl_report_and_assessment_context_preserve_severity_and_uncertainty() -> None:
    finding = {
        "summary": "testssl.sh recorded TLS evidence for example.com.",
        "target": "example.com:443",
        "risk_level": "info",
        "testssl_evidence": {
            "target": "example.com:443",
            "host": "example.com",
            "port": 443,
            "scan_status": "completed",
            "protocols": [{"id": "TLS1_3", "name": "TLS 1.3", "finding": "offered", "severity": "OK"}],
            "vulnerabilities": [{"id": "BREACH", "finding": "potentially VULNERABLE, uses HTTP compression", "severity": "MEDIUM"}],
            "notable_findings": [{"id": "early_data", "finding": "supported", "severity": "HIGH"}],
            "limitations": [
                "Scanner labels are not automatic exploit confirmation; potential findings require validation in context."
            ],
        },
        "testssl_summary": {"supported_protocols": ["TLS 1.3"], "notable_count": 2, "weak_protocol_count": 0},
    }
    context = {
        "assessment": {"name": "TLS Truthfulness", "status": "active"},
        "targets": [{"address": "example.com"}],
        "scans": [{"tool": "testssl", "status": "completed", "risk": "info", "finding": finding}],
        "findings": [finding],
        "artifacts": [],
        "notes": [],
    }

    prompt = build_assessment_ai_prompt("Summarize TLS evidence.", context)
    report = generate_assessment_markdown_report(context)
    card = build_testssl_result_text({"success": True, "target": "example.com:443", "elapsed_seconds": 3}, finding["testssl_evidence"])

    assert "BREACH severity=MEDIUM finding=potentially VULNERABLE, uses HTTP compression" in prompt
    assert "early_data severity=HIGH finding=supported" in prompt
    assert "potential findings are not confirmed exploitability" in prompt
    assert "BREACH severity=MEDIUM finding=potentially VULNERABLE, uses HTTP compression" in report
    assert "early_data severity=HIGH finding=supported" in report
    assert "TLS configuration evidence only; this does not establish overall site security." in report
    assert "BREACH: severity=MEDIUM finding=potentially VULNERABLE, uses HTTP compression" in card
    assert "site is vulnerable to breach" not in report.lower()
    assert "robust" not in report.lower()
