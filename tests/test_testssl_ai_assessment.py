from unittest.mock import patch

from app.services.testssl_ai_assessment import FALLBACK_LINES, build_testssl_ai_assessment_prompt, generate_testssl_ai_assessment


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
            },
        }
    )

    assert "Use only the supplied observed testssl.sh evidence." in prompt
    assert "Do not invent TLS vulnerabilities" in prompt
    assert "Do not claim the overall site is safe or secure from TLS evidence alone." in prompt
    assert "Certificate issuer: Example CA" in prompt
    assert "Supported protocols: TLS 1.2, TLS 1.3" in prompt


def test_testssl_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- TLS evidence reviewed.\n\nConfidence\nMedium"

    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        assert generate_testssl_ai_assessment({"target": "example.com:443"}) == response.splitlines()


def test_testssl_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.testssl_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_testssl_ai_assessment({"target": "example.com:443"}) == FALLBACK_LINES
