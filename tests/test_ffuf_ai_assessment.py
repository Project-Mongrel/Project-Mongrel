from unittest.mock import patch

import pytest

from app.services.ffuf_ai_assessment import (
    FALLBACK_LINES,
    TRUTHFULNESS_FALLBACK_LINES,
    ZERO_OBSERVATION_TRUTHFULNESS_FALLBACK_LINES,
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

    assert "ffuf recorded no matching response observations during this run" in prompt
    assert "does not establish that hidden content does not exist" in prompt
    assert "does not establish security or vulnerability absence" in prompt
    assert "selected wordlist, target/FUZZ position, runtime, response filtering, and execution conditions" in prompt
    assert "Further discovery may be appropriate only if justified by the assessment context" in prompt
    assert "no hidden content exists" not in prompt.lower()


def test_ffuf_zero_observation_prompt_includes_profile_runtime_context() -> None:
    prompt = build_ffuf_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "status": "completed",
            "finding_count": 0,
            "ffuf_summary": {"status_codes": {}},
            "ffuf_results": [],
            "metadata": {
                "wordlist_count": 29999,
                "ffuf_profile_label": "Deep",
                "fuzz_url": "https://example.com/FUZZ",
                "timeout_seconds": 1500,
            },
        }
    )

    assert "ffuf response observations during this fuzzing run: 0" in prompt
    assert "Wordlist entries: 29999" in prompt
    assert "Fuzz URL: https://example.com/FUZZ" in prompt
    assert "Zero discoveries does not imply" in prompt
    assert "do not fill Potential Risks with security conclusions" in prompt


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


def test_ffuf_compliant_zero_observation_ai_wording_is_allowed() -> None:
    response = "\n".join(
        [
            "Executive Summary",
            "- ffuf recorded no matching response observations during this run.",
            "",
            "Observed Facts",
            "- The structured evidence contains zero ffuf response observations.",
            "",
            "Interpretation",
            "- This result does not establish that hidden content does not exist.",
            "- It does not establish security or vulnerability absence.",
            "",
            "Limitations / Uncertainty",
            "- Coverage is bounded by the selected wordlist, target/FUZZ position, runtime, response filtering, and execution conditions.",
            "",
            "Recommended Next Actions",
            "- Further discovery may be appropriate only if justified by the assessment context.",
        ]
    )

    with patch("app.services.ffuf_ai_assessment.ask_ai", return_value=response):
        lines = generate_ffuf_ai_assessment(
            {
                "target": "https://example.com",
                "status": "completed",
                "finding_count": 0,
                "ffuf_results": [],
                "ffuf_summary": {"status_codes": {}},
            }
        )

    assert lines == response.splitlines()


def test_ffuf_zero_observation_unsafe_generated_conclusion_uses_zero_result_fallback() -> None:
    response = "Executive Summary\n- No vulnerabilities were found."

    with patch("app.services.ffuf_ai_assessment.ask_ai", return_value=response):
        lines = generate_ffuf_ai_assessment(
            {
                "target": "https://example.com",
                "status": "completed",
                "finding_count": 0,
                "ffuf_results": [],
                "ffuf_summary": {"status_codes": {}},
            }
        )

    assert lines == ZERO_OBSERVATION_TRUTHFULNESS_FALLBACK_LINES
    assert "No vulnerabilities were found" not in "\n".join(lines)
    assert "does not establish security or vulnerability absence" in "\n".join(lines)
