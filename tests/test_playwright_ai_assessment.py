from unittest.mock import patch

import pytest

from app.services.playwright_ai_assessment import (
    FALLBACK_LINES,
    TRUTHFULNESS_FALLBACK_LINES,
    build_playwright_ai_assessment_prompt,
    generate_playwright_ai_assessment,
)


def test_playwright_ai_prompt_uses_only_stored_playwright_evidence() -> None:
    prompt = build_playwright_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "status": "completed",
            "playwright_observation": {
                "requested_url": "https://example.com",
                "final_url": "https://www.example.com",
                "title": "Example",
                "load_status": "loaded",
                "status_code": 200,
                "forms_count": 1,
                "inputs_count": 3,
                "links_count": 8,
                "console_issue_count": 2,
                "network_issue_count": 1,
                "page_error_count": 0,
                "link_samples": ["https://www.example.com/about"],
                "limitations": ["Passive browser observation only."],
            },
            "playwright_summary": {"forms_count": 1, "inputs_count": 3, "links_count": 8},
        }
    )

    assert "Use only the supplied observed Playwright evidence." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not say the site is safe or vulnerable from page load alone." in prompt
    assert "HTTP 429 means a rate-limited response was observed" in prompt
    assert "Passive browser observation does not test for XSS, SQL injection, CSRF" in prompt
    assert "Do not infer form field meanings or page content" in prompt
    assert "forms, inputs, or links were observed" in prompt
    assert "Final URL: https://www.example.com" in prompt
    assert "Forms observed during returned browser state: 1" in prompt
    assert "https://www.example.com/about" in prompt


def test_playwright_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- Browser observation was collected.\n\nConfidence\nMedium"

    with patch("app.services.playwright_ai_assessment.ask_ai", return_value=response):
        assert generate_playwright_ai_assessment({"target": "https://example.com"}) == response.splitlines()


def test_playwright_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.playwright_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_playwright_ai_assessment({"target": "https://example.com"}) == FALLBACK_LINES


def test_playwright_ai_prompt_preserves_429_as_unknown_cause_limitation() -> None:
    prompt = build_playwright_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "playwright_observation": {
                "requested_url": "https://example.com",
                "final_url": "https://example.com",
                "load_status": "domcontentloaded",
                "status_code": 429,
            },
        }
    )

    assert "Status code: 429" in prompt
    assert "HTTP 429 was observed as a rate-limited response; cause is unknown" in prompt
    assert "Restricted or partial browser state limited visibility" in prompt
    assert "too many requests were sent" not in prompt.lower()


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "HTTP 429 means too many requests were sent.",
        "HTTP 429 occurred because 100 requests were sent.",
        "The page has no forms.",
        "The application contains no JavaScript.",
        "The site is functioning normally.",
        "No XSS vulnerabilities exist.",
        "No SQL injection vulnerabilities exist.",
        "No CSRF vulnerabilities exist.",
        "The site is secure.",
        "The API is rate-limiting malicious traffic.",
    ],
)
def test_playwright_unsupported_generated_conclusions_are_withheld(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.playwright_ai_assessment.ask_ai", return_value=response):
        lines = generate_playwright_ai_assessment({"target": "https://example.com"})

    assert lines == TRUTHFULNESS_FALLBACK_LINES
    assert unsupported_line not in "\n".join(lines)


@pytest.mark.parametrize(
    "legitimate_line",
    [
        "The browser received an HTTP 429 response; the cause is unknown from the supplied evidence.",
        "No forms were observed in the returned browser state.",
        "JavaScript activity was not observed in this capture.",
        "This passive observation does not test for XSS, SQL injection, or CSRF.",
        "The restricted response limited visibility into the application.",
    ],
)
def test_playwright_evidence_scoped_limitations_are_allowed(legitimate_line: str) -> None:
    response = f"Executive Summary\n- {legitimate_line}"

    with patch("app.services.playwright_ai_assessment.ask_ai", return_value=response):
        lines = generate_playwright_ai_assessment({"target": "https://example.com"})

    assert lines == response.splitlines()
