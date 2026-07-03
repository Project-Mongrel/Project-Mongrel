from unittest.mock import patch

from app.services.ffuf_ai_assessment import (
    FALLBACK_LINES,
    build_ffuf_ai_assessment_prompt,
    generate_ffuf_ai_assessment,
)


def test_ffuf_ai_prompt_uses_only_stored_ffuf_evidence() -> None:
    prompt = build_ffuf_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "status": "completed",
            "finding_count": 1,
            "ffuf_summary": {"status_codes": {"200": 1}, "redirect_count": 0, "forbidden_count": 0, "server_error_count": 0},
            "ffuf_results": [
                {
                    "url": "https://example.com/admin",
                    "status_code": 200,
                    "content_length": 120,
                    "words": 10,
                    "lines": 3,
                    "classification": "public",
                    "input_word": "admin",
                }
            ],
            "metadata": {"wordlist_count": 19, "fuzz_url": "https://example.com/FUZZ"},
        }
    )

    assert "Use only the supplied observed ffuf evidence." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not claim discovered admin, backup, API, or config-looking paths are exploitable." in prompt
    assert "https://example.com/admin" in prompt
    assert "status=200" in prompt
    assert "word=admin" in prompt


def test_ffuf_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- Hidden-content observations were collected.\n\nConfidence\nMedium"

    with patch("app.services.ffuf_ai_assessment.ask_ai", return_value=response):
        assert generate_ffuf_ai_assessment({"target": "https://example.com"}) == response.splitlines()


def test_ffuf_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.ffuf_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_ffuf_ai_assessment({"target": "https://example.com"}) == FALLBACK_LINES
