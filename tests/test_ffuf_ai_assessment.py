from unittest.mock import patch

import pytest

from app.services.ffuf_ai_assessment import (
    FALLBACK_LINES,
    TRUTHFULNESS_FALLBACK_LINES,
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
    assert "Do not infer that a parameter is injectable or vulnerable" in prompt
    assert "complete discovery coverage" in prompt
    assert "no paths were discovered with the selected wordlist/profile" in prompt
    assert "does not imply a static site" in prompt
    assert "resistance to injection" in prompt
    assert "ffuf response observations during this fuzzing run: 1" in prompt
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


def test_ffuf_ai_prompt_empty_fuzzing_preserves_uncertainty() -> None:
    prompt = build_ffuf_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "status": "completed",
            "finding_count": 0,
            "ffuf_summary": {"status_codes": {}},
            "ffuf_results": [],
        }
    )

    assert "No structured ffuf observations were stored." in prompt
    assert "does not prove hidden content, endpoints, directories, files, parameters, virtual hosts, or vulnerabilities do not exist" in prompt
    assert "no hidden content exists" not in prompt.lower()


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "The application is insecure.",
        "The admin directory is vulnerable.",
        "The id parameter is injectable.",
        "The id parameter is vulnerable to SQL injection.",
        "Sensitive files are exposed.",
        "The backup file contains sensitive data.",
        "Authentication bypass was discovered.",
        "The fuzzing discovered every endpoint.",
        "ffuf achieved complete coverage.",
        "No hidden content exists.",
    ],
)
def test_ffuf_unsupported_generated_conclusions_are_withheld(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.ffuf_ai_assessment.ask_ai", return_value=response):
        lines = generate_ffuf_ai_assessment({"target": "https://example.com"})

    assert lines == TRUTHFULNESS_FALLBACK_LINES
    assert unsupported_line not in "\n".join(lines)


@pytest.mark.parametrize(
    "legitimate_line",
    [
        "ffuf discovered a response for /admin during this fuzzing run.",
        "The endpoint returned HTTP 403 as a fuzzing observation.",
        "A parameter responded differently during fuzzing; this does not prove injection.",
        "No matching responses were observed during this fuzzing run; undiscovered content may still exist.",
        "The response metadata does not establish sensitive exposure.",
    ],
)
def test_ffuf_evidence_scoped_limitations_are_allowed(legitimate_line: str) -> None:
    response = f"Executive Summary\n- {legitimate_line}"

    with patch("app.services.ffuf_ai_assessment.ask_ai", return_value=response):
        lines = generate_ffuf_ai_assessment({"target": "https://example.com"})

    assert lines == response.splitlines()
