from unittest.mock import patch

import pytest

from app.services.testssl_ai_assessment import (
    FALLBACK_LINES,
    TESTSSL_AI_NUM_PREDICT,
    build_testssl_ai_assessment_prompt,
    generate_testssl_ai_assessment,
)
from app.ui.ai_summary import render_ai_summary_card


def _live_shaped_testssl_finding() -> dict:
    return {
        "target": "btjoinery.ie:443",
        "status": "completed",
        "risk_level": "info",
        "finding_count": 9,
        "testssl_summary": {
            "certificate_summary": "CN=btjoinery.ie; Expires=2026-11-27 14:05",
            "notable_count": 9,
            "protocol_count": 6,
            "supported_protocols": ["TLS 1.2", "TLS 1.3"],
            "weak_protocol_count": 0,
        },
        "testssl_evidence": {
            "target": "btjoinery.ie:443",
            "host": "btjoinery.ie",
            "port": 443,
            "scan_status": "completed",
            "protocols": [
                {"id": "SSLv2", "name": "SSLv2", "finding": "not offered", "severity": "OK"},
                {"id": "SSLv3", "name": "SSLv3", "finding": "not offered", "severity": "OK"},
                {"id": "TLS1", "name": "TLS 1.0", "finding": "not offered", "severity": "INFO"},
                {"id": "TLS1_1", "name": "TLS 1.1", "finding": "not offered", "severity": "INFO"},
                {"id": "TLS1_2", "name": "TLS 1.2", "finding": "offered", "severity": "OK"},
                {"id": "TLS1_3", "name": "TLS 1.3", "finding": "offered with final", "severity": "OK"},
            ],
            "certificate": {
                "common_name": "btjoinery.ie",
                "not_after": "2026-11-27 14:05",
            },
            "weak_protocols": [],
            "vulnerabilities": [
                {"id": "heartbleed", "finding": "not vulnerable, no heartbeat extension", "severity": "OK"},
                {"id": "CCS", "finding": "not vulnerable", "severity": "OK"},
                {"id": "ticketbleed", "finding": "not vulnerable", "severity": "OK"},
                {"id": "ROBOT", "finding": "not vulnerable, no RSA key transport cipher", "severity": "OK"},
                {"id": "secure_renego", "finding": "supported", "severity": "OK"},
                {"id": "secure_client_renego", "finding": "not vulnerable", "severity": "OK"},
                {"id": "CRIME_TLS", "finding": "not vulnerable", "severity": "OK"},
                {"id": "BREACH", "finding": "not vulnerable, no gzip/deflate/compress/br HTTP compression  - only supplied '/' tested", "severity": "OK"},
                {"id": "POODLE_SSL", "finding": "not vulnerable, no SSLv3", "severity": "OK"},
                {"id": "fallback_SCSV", "finding": "no protocol below TLS 1.2 offered", "severity": "OK"},
                {"id": "SWEET32", "finding": "not vulnerable", "severity": "OK"},
                {"id": "FREAK", "finding": "not vulnerable", "severity": "OK"},
                {"id": "DROWN", "finding": "not vulnerable on this host and port", "severity": "OK"},
                {
                    "id": "DROWN_hint",
                    "finding": "Make sure you don't use this certificate elsewhere with SSLv2 enabled services",
                    "severity": "INFO",
                },
                {"id": "LOGJAM", "finding": "not vulnerable, no DH EXPORT ciphers,", "severity": "OK"},
                {"id": "LOGJAM-common_primes", "finding": "no DH key with <= TLS 1.2", "severity": "OK"},
                {"id": "BEAST", "finding": "not vulnerable, no SSL3 or TLS1", "severity": "OK"},
                {"id": "LUCKY13", "finding": "potentially vulnerable, uses TLS CBC ciphers", "severity": "LOW"},
                {"id": "RC4", "finding": "not vulnerable", "severity": "OK"},
            ],
            "cipher_findings": [
                {"id": "cipherlist_NULL", "finding": "not offered", "severity": "OK"},
                {"id": "cipherlist_aNULL", "finding": "not offered", "severity": "OK"},
                {"id": "cipherlist_EXPORT", "finding": "not offered", "severity": "OK"},
                {"id": "cipherlist_LOW", "finding": "not offered", "severity": "OK"},
                {"id": "cipherlist_3DES_IDEA", "finding": "not offered", "severity": "INFO"},
                {"id": "cipherlist_OBSOLETED", "finding": "offered", "severity": "LOW"},
                {"id": "cipherlist_STRONG_NOFS", "finding": "not offered", "severity": "INFO"},
                {"id": "cipherlist_STRONG_FS", "finding": "offered", "severity": "OK"},
            ],
            "notable_findings": [
                {"id": "cert_trust_wildcard", "finding": "trust is via wildcard", "severity": "LOW"},
                {"id": "QUIC", "finding": "not tested due to lack of local OpenSSL support", "severity": "WARN"},
            ],
            "limitations": [
                "testssl.sh evidence reflects TLS configuration only.",
                "Findings are not proof of overall site security.",
            ],
        },
    }


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
    assert "Observed Facts" in prompt
    assert "Observed TLS Facts" not in prompt
    assert "Vulnerabilities/misconfigurations" not in prompt
    assert "Scanner OK/INFO observations" in prompt
    assert "Potential scanner findings requiring context/validation" in prompt


def test_testssl_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- TLS evidence reviewed.\n\nConfidence\nMedium"

    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response) as ask_ai:
        assert generate_testssl_ai_assessment({"target": "example.com:443"}) == response.splitlines()
    ask_ai.assert_called_once()
    assert ask_ai.call_args.kwargs["num_predict"] == TESTSSL_AI_NUM_PREDICT
    assert ask_ai.call_args.kwargs["path"] == "testssl_ai_assessment"


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
        "The TLS configuration for btjoinery.ie appears robust.",
        "This endpoint appears safe.",
        "The service looks hardened.",
        "All supported ciphers are strong.",
        "The site is vulnerable to BREACH.",
        "BREACH can be exploited against this target.",
        "HIGH early_data means the server is exploitable.",
        "No TLS vulnerabilities were found.",
        "Secure Renegotiation is supported and not vulnerable.",
        "DROWN is not vulnerable.",
    ],
)
def test_testssl_unsupported_generated_conclusions_are_withheld(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        lines = generate_testssl_ai_assessment({"target": "example.com:443"})

    assert "unsupported TLS security conclusion" in "\n".join(lines)
    assert unsupported_line not in "\n".join(lines)
    rendered = render_ai_summary_card(lines, title="testssl.sh AI Assessment")
    assert "Observed Facts" in rendered
    assert "Potential Risks" in rendered
    assert "Recommended Next Actions" in rendered


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


def test_testssl_live_shaped_truthfulness_fallback_preserves_notable_scanner_records() -> None:
    response = "\n".join(
        [
            "Executive Summary",
            "- The TLS configuration appears robust and secure.",
            "Potential Risks",
            "- LOW LUCKY13 means the server is exploitable.",
        ]
    )

    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        lines = generate_testssl_ai_assessment(_live_shaped_testssl_finding())

    joined = "\n".join(lines)
    assert "unsupported TLS security conclusion" in joined
    assert "TLS 1.2, TLS 1.3" in joined
    assert "Certificate common name: btjoinery.ie" in joined
    assert "Certificate expiry: 2026-11-27 14:05" in joined
    assert "Notable scanner records: 9" in joined
    for record_id in (
        "secure_renego",
        "fallback_SCSV",
        "DROWN_hint",
        "LOGJAM-common_primes",
        "LUCKY13",
        "cert_trust_wildcard",
        "QUIC",
        "cipherlist_OBSOLETED",
        "cipherlist_STRONG_FS",
    ):
        assert record_id in joined
    assert "severity=LOW finding=potentially vulnerable, uses TLS CBC ciphers" in joined
    assert "overall secure, safe, robust, or hardened TLS verdict" in joined
    assert "The TLS configuration appears robust and secure" not in joined
    assert "LOW LUCKY13 means the server is exploitable" not in joined

    rendered = render_ai_summary_card(lines, title="testssl.sh AI Assessment")
    assert "Observed Facts" in rendered
    assert "Observed Assets" in rendered
    assert "Potential Risks" in rendered
    assert "Confidence" in rendered
    assert "Recommended Next Actions" in rendered


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "LOW LUCKY13 means the server is exploitable.",
        "WARN QUIC proves the endpoint is vulnerable.",
        "LUCKY13 confirms practical exploitation.",
    ],
)
def test_testssl_low_warn_observations_cannot_be_promoted_to_exploitability(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        lines = generate_testssl_ai_assessment(_live_shaped_testssl_finding())

    joined = "\n".join(lines)
    assert "unsupported TLS security conclusion" in joined
    assert unsupported_line not in joined


def test_testssl_exact_live_escaped_response_is_replaced_by_grounded_fallback() -> None:
    response = "\n".join(
        [
            "Executive Summary",
            "- The TLS configuration for btjoinery.ie appears robust based on the scanner output.",
            "",
            "Observed Facts",
            "- TLS 1.2 and TLS 1.3 are supported.",
            "- Secure Renegotiation is supported and not vulnerable.",
            "- DROWN is not",
        ]
    )

    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        lines = generate_testssl_ai_assessment(_live_shaped_testssl_finding())

    joined = "\n".join(lines)
    assert "unsupported TLS security conclusion" in joined
    assert "Notable scanner records: 9" in joined
    assert "secure_renego severity=OK finding=supported" in joined
    assert "DROWN is not" not in joined
    assert "appears robust" not in joined
    assert "supported and not vulnerable" not in joined


@pytest.mark.parametrize(
    "response",
    [
        "Executive Summary\n- testssl.sh reported secure_renego severity=OK finding=supported.",
        "Observed Facts\n- Scanner reported DROWN severity=OK finding=not vulnerable on this host and port.",
        "Observed Facts\n- testssl.sh reported heartbleed severity=OK finding=not vulnerable, no heartbeat extension.",
    ],
)
def test_testssl_scanner_negative_observations_are_allowed_when_attributed(response: str) -> None:
    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        assert generate_testssl_ai_assessment(_live_shaped_testssl_finding()) == response.splitlines()


@pytest.mark.parametrize(
    "response",
    [
        "Observed Facts\n- DROWN is not vulnerable.",
        "Observed Facts\n- Secure Renegotiation is supported and not vulnerable.",
        "Observed Facts\n- The endpoint is not vulnerable to Heartbleed.",
    ],
)
def test_testssl_scanner_negative_observations_require_attribution(response: str) -> None:
    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        lines = generate_testssl_ai_assessment(_live_shaped_testssl_finding())

    joined = "\n".join(lines)
    assert "unsupported TLS security conclusion" in joined
    assert response.splitlines()[-1] not in joined


@pytest.mark.parametrize(
    "response",
    [
        "Executive Summary\n- Evidence reviewed.\n\nObserved Facts\n- DROWN is not",
        "Executive Summary\n- Evidence reviewed.\n\nRecommended Next Actions",
        "Executive Summary\n- Evidence reviewed.\n\nObserved Facts\n- The scan reported TLS records with",
    ],
)
def test_testssl_incomplete_or_truncated_generated_output_uses_grounded_fallback(response: str) -> None:
    with patch("app.services.testssl_ai_assessment.ask_ai", return_value=response):
        lines = generate_testssl_ai_assessment(_live_shaped_testssl_finding())

    joined = "\n".join(lines)
    assert "unsupported TLS security conclusion" in joined
    assert "Notable scanner records: 9" in joined
