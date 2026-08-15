from unittest.mock import patch

import pytest

from app.services.httpx_ai_assessment import (
    FALLBACK_LINES,
    TRUTHFULNESS_FALLBACK_LINES,
    build_httpx_ai_assessment_prompt,
    generate_httpx_ai_assessment,
)


def test_httpx_ai_prompt_uses_only_stored_httpx_evidence() -> None:
    prompt = build_httpx_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "status": "completed",
            "finding_count": 1,
            "httpx_services": [
                {
                    "url": "https://example.com",
                    "status_code": 200,
                    "title": "Example",
                    "web_server": "nginx",
                    "technologies": ["React"],
                    "redirect_location": "https://www.example.com",
                }
            ],
            "httpx_summary": {"status_codes": {"200": 1}, "technologies": ["React"]},
        }
    )

    assert "Use only the supplied observed httpx evidence." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not call HTTP 429 a misconfiguration" in prompt
    assert "HTTP 200 means a response was observed" in prompt
    assert "HTTP 401 means an authentication-required response was observed" in prompt
    assert "HTTP 403 means a forbidden response was observed" in prompt
    assert "HTTP 404 means the tested resource returned Not Found" in prompt
    assert "HTTP 429 means a rate-limited response was observed" in prompt
    assert "HTTP 5xx means a server-error response was observed" in prompt
    assert "Technology fingerprints are observations, not vulnerability findings." in prompt
    assert "Headers are contextual observations" in prompt
    assert "no usable response was obtained" in prompt
    assert "Interpretation" in prompt
    assert "Limitations" in prompt
    assert "rate-limit, challenge, or access-control uncertainty" in prompt
    assert "url=https://example.com status=200 title=Example server=nginx tech=React redirect=https://www.example.com" in prompt


def test_httpx_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- One HTTP response was observed.\n\nConfidence\nMedium"

    with patch("app.services.httpx_ai_assessment.ask_ai", return_value=response):
        assert generate_httpx_ai_assessment({"target": "https://example.com"}) == response.splitlines()


def test_httpx_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.httpx_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_httpx_ai_assessment({"target": "https://example.com"}) == FALLBACK_LINES


@pytest.mark.parametrize(
    ("status_code", "legitimate_line"),
    [
        (200, "httpx received an HTTP 200 response from the tested URL."),
        (401, "httpx received an HTTP 401 authentication-required response from the tested URL."),
        (403, "httpx received an HTTP 403 forbidden response from the tested URL."),
        (404, "httpx received an HTTP 404 Not Found response for the tested resource."),
        (429, "httpx received an HTTP 429 rate-limited response; the cause is unknown from this evidence."),
        (500, "httpx received an HTTP 500 server-error response from the tested URL."),
    ],
)
def test_httpx_status_code_evidence_scoped_wording_is_allowed(status_code: int, legitimate_line: str) -> None:
    finding = _finding(status_code=status_code)
    response = f"Observed Facts\n- {legitimate_line}\nLimitations\n- This response metadata does not establish a vulnerability."

    with patch("app.services.httpx_ai_assessment.ask_ai", return_value=response):
        assert generate_httpx_ai_assessment(finding) == response.splitlines()


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "HTTP 200 proves the application is functioning normally.",
        "HTTP 401 means the authentication is secure.",
        "HTTP 403 shows a WAF blocked the request.",
        "HTTP 404 proves no web application exists.",
        "HTTP 429 occurred after 100 requests.",
        "HTTP 500 is a vulnerability.",
        "The server is vulnerable because nginx was detected.",
        "A missing security header is a confirmed vulnerability.",
        "The target is secure.",
        "The target is insecure.",
        "No vulnerabilities were found.",
        "Compromise was detected.",
        "Sensitive data was exposed.",
    ],
)
def test_httpx_unsupported_generated_security_conclusions_are_withheld(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.httpx_ai_assessment.ask_ai", return_value=response):
        lines = generate_httpx_ai_assessment(_finding(status_code=200))

    assert lines == TRUTHFULNESS_FALLBACK_LINES


def test_httpx_no_usable_response_remains_inconclusive() -> None:
    prompt = build_httpx_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "status": "completed",
            "finding_count": 0,
            "httpx_services": [],
            "httpx_summary": {},
        }
    )

    assert "No usable structured httpx response observations were stored for this run." in prompt
    assert "This does not prove the host is down, no web application exists, or the target is safe." in prompt


def test_httpx_legitimate_technology_limitation_wording_is_allowed() -> None:
    response = "\n".join(
        [
            "Observed Facts",
            "- Technology fingerprinting identified nginx.",
            "Limitations",
            "- This fingerprint does not establish that the detected technology is vulnerable.",
        ]
    )

    with patch("app.services.httpx_ai_assessment.ask_ai", return_value=response):
        assert generate_httpx_ai_assessment(_finding(status_code=200, technologies=["nginx"])) == response.splitlines()


def test_httpx_missing_header_contextual_wording_is_allowed() -> None:
    response = "\n".join(
        [
            "Observed Facts",
            "- A missing security header was reported as a contextual HTTP response observation.",
            "Limitations",
            "- This does not establish an exploitable vulnerability.",
        ]
    )

    with patch("app.services.httpx_ai_assessment.ask_ai", return_value=response):
        assert generate_httpx_ai_assessment(_finding(status_code=200)) == response.splitlines()


def _finding(status_code: int = 200, technologies: list[str] | None = None) -> dict:
    technologies = technologies or []
    return {
        "target": "https://example.com",
        "status": "completed",
        "finding_count": 1,
        "httpx_services": [
            {
                "url": "https://example.com",
                "status_code": status_code,
                "title": "Example",
                "web_server": "nginx" if technologies else "",
                "technologies": technologies,
            }
        ],
        "httpx_summary": {"status_codes": {str(status_code): 1}, "technologies": technologies},
    }
