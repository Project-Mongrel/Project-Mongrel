from unittest.mock import patch

import pytest

from app.services.testssl_ai_assessment import (
    FALLBACK_LINES,
    TRUTHFULNESS_FALLBACK_LINES,
    build_testssl_ai_assessment_prompt,
    generate_testssl_ai_assessment,
)


def test_testssl_ai_prompt_uses_only_stored_tls_evidence() -> None:
    prompt = build_testssl_ai_assessment_prompt(
        {
            "target": "example.com:443",
            "status": "completed",
            "finding_count": 2,
            "testssl_summary": {
                "supported_protocols": ["TLS 1.2", "TLS 1.3"],
                "weak_protocol_count": 1,
                "notable_count": 2,
            },
            "testssl_evidence": {
                "host": "example.com",
                "port": 443,
                "certificate": {
                    "common_name": "example.com",
                    "issuer": "Example CA",
                    "not_after": "2030-01-01",
                    "subject_alt_names": "DNS:example.com",
                },
                "protocols": [{"id": "TLS1_2", "name": "TLS 1.2", "finding": "offered", "severity": "OK"}],
                "weak_protocols": ["TLS 1.0: offered"],
                "vulnerabilities": [{"id": "heartbleed", "finding": "not vulnerable", "severity": "OK"}],
                "notable_findings": [{"id": "early_data", "finding": "supported", "severity": "HIGH"}],
            },
        }
    )

    assert "Use only the supplied observed testssl.sh evidence." in prompt
    assert "Do not invent TLS vulnerabilities" in prompt
    assert "Do not claim the overall site is safe or secure from TLS evidence alone." in prompt
    assert "Do not characterize TLS configuration as robust" in prompt
    assert "early_data, LUCKY13" in prompt
    assert "scanner-reported evidence requiring context and validation" in prompt
    assert "Preserve scanner wording, severity labels, confidence, and uncertainty exactly." in prompt
    assert "Absence of reported TLS findings does not prove the endpoint is secure" in prompt
    assert "Certificate issuer: Example CA" in prompt
    assert "Supported protocols: TLS 1.2, TLS 1.3" in prompt
    assert "early_data severity=HIGH finding=supported" in prompt
    assert "Evidence boundary: testssl.sh observations are TLS scanner evidence only" in prompt


def test_testssl_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- TLS evidence reviewed.\n\nConfidence\nMedium"

    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        assert generate_testssl_ai_assessment({"target": "example.com:443"}) == response.splitlines()


def test_testssl_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.testssl_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_testssl_ai_assessment({"target": "example.com:443"}) == FALLBACK_LINES


def test_testssl_prompt_preserves_potential_breach_and_early_data_uncertainty() -> None:
    prompt = build_testssl_ai_assessment_prompt(
        {
            "target": "example.com:443",
            "status": "completed",
            "testssl_summary": {"supported_protocols": ["TLS 1.2", "TLS 1.3"], "notable_count": 2},
            "testssl_evidence": {
                "host": "example.com",
                "port": 443,
                "protocols": [
                    {"id": "TLS1_2", "name": "TLS 1.2", "finding": "offered", "severity": "OK"},
                    {"id": "TLS1_3", "name": "TLS 1.3", "finding": "offered", "severity": "OK"},
                ],
                "vulnerabilities": [{"id": "BREACH", "finding": "potentially VULNERABLE, uses HTTP compression", "severity": "MEDIUM"}],
                "notable_findings": [{"id": "early_data", "finding": "supported", "severity": "HIGH"}],
            },
        }
    )

    assert "Preserve 'potentially VULNERABLE' as scanner-reported potential evidence requiring validation" in prompt
    assert "BREACH severity=MEDIUM finding=potentially VULNERABLE, uses HTTP compression" in prompt
    assert "early_data severity=HIGH finding=supported" in prompt
    assert "early_data severity must be described as scanner severity" in prompt
    assert "do not infer practical exploitability or compromise" in prompt


def test_testssl_prompt_empty_clean_scan_does_not_imply_secure_tls() -> None:
    prompt = build_testssl_ai_assessment_prompt({"target": "example.com:443", "status": "completed"})

    assert "No structured testssl.sh evidence was stored." in prompt
    assert "Absence of structured TLS evidence does not prove the endpoint is secure" in prompt
    assert "no TLS vulnerabilities exist" in prompt
    assert "TLS appears robust" not in prompt


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "TLS configuration appears robust.",
        "The TLS configuration is secure.",
        "All supported ciphers are strong.",
        "The site is vulnerable to BREACH.",
        "BREACH can be exploited against this target.",
        "HIGH early_data means the server is exploitable.",
        "No TLS vulnerabilities were found.",
    ],
)
def test_testssl_unsupported_generated_conclusions_are_withheld(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        lines = generate_testssl_ai_assessment({"target": "example.com:443"})

    assert lines == TRUTHFULNESS_FALLBACK_LINES
    assert unsupported_line not in "\n".join(lines)


@pytest.mark.parametrize(
    "legitimate_line",
    [
        "testssl.sh reported the endpoint as potentially vulnerable to BREACH.",
        "This is scanner-reported potential evidence and does not by itself establish practical exploitability.",
        "TLS 1.2 and TLS 1.3 were observed as supported.",
        "The scanner assigned HIGH severity to the early_data observation; practical risk depends on application and replay-sensitive behavior.",
        "The scan did not report notable TLS findings within its tested scope; this does not prove the endpoint is secure.",
    ],
)
def test_testssl_scanner_scoped_uncertainty_wording_is_allowed(legitimate_line: str) -> None:
    response = f"Executive Summary\n- {legitimate_line}"

    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        lines = generate_testssl_ai_assessment({"target": "example.com:443"})

    assert lines == response.splitlines()
