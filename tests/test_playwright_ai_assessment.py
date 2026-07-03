from unittest.mock import patch

from app.services.playwright_ai_assessment import (
    FALLBACK_LINES,
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
    assert "Final URL: https://www.example.com" in prompt
    assert "Forms: 1" in prompt
    assert "https://www.example.com/about" in prompt


def test_playwright_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- Browser observation was collected.\n\nConfidence\nMedium"

    with patch("app.services.playwright_ai_assessment.ask_ai", return_value=response):
        assert generate_playwright_ai_assessment({"target": "https://example.com"}) == response.splitlines()


def test_playwright_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.playwright_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_playwright_ai_assessment({"target": "https://example.com"}) == FALLBACK_LINES
