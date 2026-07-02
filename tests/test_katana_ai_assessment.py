from unittest.mock import patch

from app.services.katana_ai_assessment import FALLBACK_LINES, build_katana_ai_assessment_prompt, generate_katana_ai_assessment


def test_katana_ai_prompt_uses_only_stored_katana_evidence() -> None:
    prompt = build_katana_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "status": "completed",
            "finding_count": 1,
            "katana_observations": [
                {
                    "url": "https://example.com/search?q=test",
                    "endpoint_type": "parameterized_url",
                    "method": "GET",
                    "status_code": 200,
                    "depth": 2,
                    "source": "https://example.com",
                    "query_parameters": ["q"],
                }
            ],
            "katana_summary": {"host_count": 1, "query_parameter_count": 1, "max_depth": 2},
        }
    )

    assert "Use only the supplied observed Katana evidence." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Describe discovered URLs and endpoints as attack surface, not confirmed risk." in prompt
    assert "url=https://example.com/search?q=test type=parameterized_url method=GET status=200 depth=2 source=https://example.com params=q" in prompt


def test_katana_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- Crawl surface was observed.\n\nConfidence\nMedium"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        assert generate_katana_ai_assessment({"target": "https://example.com"}) == response.splitlines()


def test_katana_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.katana_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_katana_ai_assessment({"target": "https://example.com"}) == FALLBACK_LINES
