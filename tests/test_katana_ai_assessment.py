from unittest.mock import patch

import pytest

from app.services.katana_ai_assessment import (
    FALLBACK_LINES,
    TRUTHFULNESS_FALLBACK_LINES,
    build_katana_ai_assessment_prompt,
    generate_katana_ai_assessment,
)


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
    assert "Describe discovered URLs and endpoints as crawl observations, not confirmed risk." in prompt
    assert "Do not infer that a parameter is injectable or vulnerable" in prompt
    assert "Do not infer that a form is exploitable" in prompt
    assert "complete application coverage" in prompt
    assert "crawl visibility was limited" in prompt
    assert "not that site structure is limited" in prompt
    assert "URLs/endpoints observed during this crawl: 1" in prompt
    assert "Query parameters observed during this crawl: 1" in prompt
    assert "url=https://example.com/search?q=test type=parameterized_url method=GET status=200 depth=2 source=https://example.com params=q" in prompt


def test_katana_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- Crawl surface was observed.\n\nConfidence\nMedium"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        assert generate_katana_ai_assessment({"target": "https://example.com"}) == response.splitlines()


def test_katana_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.katana_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_katana_ai_assessment({"target": "https://example.com"}) == FALLBACK_LINES


def test_katana_ai_prompt_empty_crawl_preserves_absence_uncertainty() -> None:
    prompt = build_katana_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "status": "completed",
            "finding_count": 0,
            "katana_observations": [],
            "katana_summary": {"form_count": 0, "query_parameter_count": 0, "javascript_count": 0},
        }
    )

    assert "No structured Katana crawl observations were stored." in prompt
    assert "does not prove forms, endpoints, parameters, scripts, paths, or hidden content do not exist" in prompt
    assert "crawl found all" not in prompt.lower()


def _single_url_katana_finding() -> dict:
    return {
        "target": "https://example.com",
        "status": "completed",
        "finding_count": 1,
        "katana_observations": [
            {
                "url": "https://example.com/",
                "host": "example.com",
                "endpoint_type": "url",
                "depth": 0,
            }
        ],
        "katana_summary": {
            "url_count": 1,
            "unique_hosts": ["example.com"],
            "host_count": 1,
            "javascript_count": 0,
            "query_parameter_count": 0,
            "form_count": 0,
            "max_depth": 0,
        },
    }


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "The site is secure.",
        "The application is insecure.",
        "The id parameter is vulnerable to SQL injection.",
        "The id parameter is injectable.",
        "The login form is exploitable.",
        "The JavaScript file is vulnerable.",
        "Sensitive data was exposed.",
        "The crawl found all application routes.",
        "The site has no hidden endpoints.",
        "The endpoint is publicly accessible at all times.",
        "The site has a single observed URL and no unique hosts.",
        "The maximum depth reached by the crawl is 0, indicating that all pages have been fully crawled according to the configured depth.",
        "No pages beyond the initial one were crawled due to the maximum depth limit.",
        "The site appears to have a basic structure with no apparent exploitation points.",
        "There is an absence of any suspicious elements such as forms, parameters, or JavaScript files.",
    ],
)
def test_katana_unsupported_generated_conclusions_are_withheld(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    assert lines == TRUTHFULNESS_FALLBACK_LINES
    assert unsupported_line not in "\n".join(lines)


@pytest.mark.parametrize(
    "legitimate_line",
    [
        "Katana discovered 24 URLs during this crawl.",
        "A parameter named id was present in a discovered URL; this does not prove injection.",
        "The crawl observed a form at /login; this does not establish exploitability.",
        "No forms were observed during this crawl.",
        "No additional endpoints were observed during this crawl; coverage was limited.",
        "A JavaScript file was observed during this crawl; this is discovery metadata only.",
        "Restricted crawl visibility was limited, so undiscovered content may still exist.",
        "The maximum observed crawl depth was 0.",
        "Only one URL was observed during this crawl, so coverage was limited.",
        "Configured crawl depth was not supplied.",
    ],
)
def test_katana_evidence_scoped_limitations_are_allowed(legitimate_line: str) -> None:
    response = f"Executive Summary\n- {legitimate_line}"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    assert lines == response.splitlines()


def test_katana_prompt_represents_observed_depth_without_configuration_causation() -> None:
    prompt = build_katana_ai_assessment_prompt(_single_url_katana_finding())

    assert "URLs/endpoints observed during this crawl: 1" in prompt
    assert "Unique hosts: 1" in prompt
    assert "JavaScript files observed during this crawl: 0" in prompt
    assert "Query parameters observed during this crawl: 0" in prompt
    assert "Forms/actions observed during this crawl: 0" in prompt
    assert "Max observed crawl depth: 0" in prompt
    assert "Configured crawl depth: not supplied" in prompt
    assert "max_depth as maximum observed crawl depth only" in prompt
    assert "does not prove configured crawl depth, complete crawling, or why no deeper URLs were observed" in prompt


def test_katana_multiple_observed_values_remain_reportable() -> None:
    finding = {
        "target": "https://example.com",
        "status": "completed",
        "finding_count": 3,
        "katana_observations": [
            {"url": "https://example.com/", "host": "example.com", "endpoint_type": "url", "depth": 0},
            {"url": "https://example.com/app.js", "host": "example.com", "endpoint_type": "javascript", "depth": 1},
            {"url": "https://cdn.example.net/lib.js", "host": "cdn.example.net", "endpoint_type": "javascript", "depth": 2},
        ],
        "katana_summary": {
            "host_count": 2,
            "javascript_count": 2,
            "query_parameter_count": 0,
            "form_count": 0,
            "max_depth": 2,
        },
    }
    response = "\n".join([
        "Executive Summary",
        "- Katana observed 3 URLs during this crawl.",
        "- Two unique hosts were represented in the observed crawl evidence.",
        "- The maximum observed crawl depth was 2.",
    ])

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(finding)

    assert lines == response.splitlines()
