from unittest.mock import patch

from app.services.httpx_ai_assessment import FALLBACK_LINES, build_httpx_ai_assessment_prompt, generate_httpx_ai_assessment


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
    assert "url=https://example.com status=200 title=Example server=nginx tech=React redirect=https://www.example.com" in prompt


def test_httpx_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- One HTTP service was observed.\n\nConfidence\nMedium"

    with patch("app.services.httpx_ai_assessment.ask_ai", return_value=response):
        assert generate_httpx_ai_assessment({"target": "https://example.com"}) == response.splitlines()


def test_httpx_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.httpx_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_httpx_ai_assessment({"target": "https://example.com"}) == FALLBACK_LINES
