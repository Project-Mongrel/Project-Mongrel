from unittest.mock import patch

import pytest

from app.services.katana_ai_assessment import (
    FALLBACK_LINES,
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
    assert "Do not write that there are no risks, no issues, no exploitation points, or no attack surface" in prompt
    assert "Follow-up Investigation Areas" in prompt
    assert "Potential Risks" not in prompt
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


def _single_url_katana_finding_with_configured_depth() -> dict:
    finding = _single_url_katana_finding()
    finding["metadata"] = {"crawl_depth": "3"}
    return finding


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
        "The crawl revealed a single URL with no observed endpoints, forms, parameters, JavaScript files, or unique hosts.",
        "Given these observations and the absence of evidence for vulnerabilities or sensitive data exposure, there are no confirmed risks at this time.",
        "There are no indications of complex interactions such as forms, parameters, or JavaScript files that could indicate vulnerabilities or sensitive data exposure.",
        "The absence of unique hosts and JavaScript files further supports the notion that the site's core functionality is straightforward.",
    ],
)
def test_katana_unsupported_generated_conclusions_are_withheld(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    rendered = "\n".join(lines)
    assert lines != response.splitlines()
    assert unsupported_line not in rendered
    assert "Katana stored 1 URL/endpoint crawl observation(s) across 1 observed host(s)" in rendered
    assert "does not establish configured crawl depth or complete crawl coverage" in rendered


def test_katana_exact_live_generated_assessment_is_rejected_with_grounded_fallback() -> None:
    response = "\n".join([
        "Executive Summary",
        "- The crawl revealed a single URL with no observed endpoints, forms, parameters, JavaScript files, or unique hosts.",
        "- The max observed crawl depth was 0, indicating that Katana did not reach any deeper URLs within the configured depth limit (3).",
        "- Given these observations and the absence of evidence for vulnerabilities or sensitive data exposure, there are no confirmed risks at this time.",
        "- The max observed crawl depth was 0, which is consistent with the configured depth limit of 3.",
        "- The single URL observed during this crawl suggests a relatively simple structure.",
        "- There are no indications of complex interactions such as forms, parameters, or JavaScript files that could indicate vulnerabilities or sensitive data exposure.",
        "- The absence of unique hosts and JavaScript files further supports the notion that the site's core functionality is straightforward.",
    ])

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding_with_configured_depth())

    rendered = "\n".join(lines)
    assert lines != response.splitlines()
    assert "no observed endpoints" not in rendered
    assert "no unique hosts" not in rendered
    assert "configured depth limit" not in rendered
    assert "no confirmed risks" not in rendered
    assert "simple structure" not in rendered
    assert "straightforward" not in rendered
    assert "Katana stored 1 URL/endpoint crawl observation(s) across 1 observed host(s)" in rendered
    assert "Maximum observed crawl depth: 0" in rendered


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
        "Depth 0 does not establish configured crawl depth or complete coverage.",
        "The crawl does not prove complete coverage.",
        "Zero observations do not establish absence.",
        "Katana crawl evidence does not establish vulnerability or exploitability.",
        "Katana did not establish a vulnerability.",
        "This crawl does not prove vulnerability or sensitive exposure.",
        "No vulnerability is confirmed by this crawl alone.",
    ],
)
def test_katana_evidence_scoped_limitations_are_allowed(legitimate_line: str) -> None:
    response = f"Executive Summary\n- {legitimate_line}"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    assert lines == response.splitlines()


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "No endpoints were observed.",
        "There was an absence of endpoints.",
        "No URLs were observed.",
        "No unique hosts were observed.",
        "There was an absence of unique hosts.",
        "No hosts were observed.",
    ],
)
def test_katana_count_contradictions_use_normalized_counts(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    rendered = "\n".join(lines)
    assert lines != response.splitlines()
    assert unsupported_line not in rendered
    assert "Katana stored 1 URL/endpoint crawl observation(s) across 1 observed host(s)" in rendered


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "The max observed crawl depth was 0, indicating that Katana did not reach deeper URLs within the configured depth limit (3).",
        "The max observed crawl depth was 0, which is consistent with the configured depth limit of 3.",
        "Depth 0 means Katana stopped because of the configured depth limit.",
    ],
)
def test_katana_depth_limit_causation_is_rejected_even_when_configured_depth_is_stored(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding_with_configured_depth())

    rendered = "\n".join(lines)
    assert lines != response.splitlines()
    assert unsupported_line not in rendered
    assert "Maximum observed crawl depth: 0" in rendered


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "There are no confirmed risks at this time.",
        "There are no security issues.",
        "There are no indications of vulnerabilities.",
        "The absence of evidence for vulnerabilities means there are no confirmed risks.",
        "No sensitive data exposure was observed.",
    ],
)
def test_katana_security_absence_conclusions_are_rejected(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    assert lines != response.splitlines()
    assert unsupported_line not in "\n".join(lines)


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "The single URL suggests a relatively simple structure.",
        "The site has straightforward functionality.",
        "The absence of unique hosts supports the notion that the core functionality is straightforward.",
        "Sparse crawl artifacts indicate a basic application.",
    ],
)
def test_katana_complexity_inferences_are_rejected(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    assert lines != response.splitlines()
    assert unsupported_line not in "\n".join(lines)


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "No forms, parameters, or JavaScript files indicates fewer vulnerabilities.",
        "There are no indications of complex interactions such as forms, parameters, or JavaScript files that could indicate vulnerabilities.",
        "The absence of forms and parameters suggests no sensitive data exposure.",
    ],
)
def test_katana_absence_to_security_inferences_are_rejected(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    assert lines != response.splitlines()
    assert unsupported_line not in "\n".join(lines)


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "The crawl achieved complete coverage.",
        "All pages were crawled.",
        "Every page was crawled.",
        "The site was fully crawled.",
        "The entire site was crawled.",
        "The whole site was crawled.",
        "The application was fully crawled.",
        "The crawl covered all pages.",
        "Complete crawl coverage was achieved.",
        "There is no doubt the crawl achieved complete coverage.",
        "Not only was the crawl complete, it covered all pages.",
    ],
)
def test_katana_affirmative_complete_coverage_claims_remain_rejected(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    rendered = "\n".join(lines)
    assert lines != response.splitlines()
    assert unsupported_line not in rendered
    assert "Katana stored 1 URL/endpoint crawl observation(s) across 1 observed host(s)" in rendered


def test_katana_sparse_compliant_generated_assessment_is_accepted() -> None:
    response = "\n".join([
        "Executive Summary",
        "- This run observed one URL on one host.",
        "",
        "Observed Facts",
        "- No JavaScript files were observed during this crawl.",
        "- No query parameters were observed during this crawl.",
        "- No forms/actions were observed during this crawl.",
        "- The maximum observed crawl depth was 0.",
        "",
        "Limitations / Uncertainty",
        "- Zero observations do not establish absence, and depth 0 does not establish configured crawl depth or complete coverage.",
        "",
        "Recommended Next Actions",
        "- Browser/runtime review or additional authorized crawling can add evidence.",
    ])

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    assert lines == response.splitlines()


def test_katana_sparse_rejected_generation_returns_grounded_observed_facts() -> None:
    response = "\n".join([
        "Executive Summary",
        "- The site appears to have a basic structure with no apparent exploitation points.",
    ])

    with patch("app.services.katana_ai_assessment.ask_ai", return_value=response):
        lines = generate_katana_ai_assessment(_single_url_katana_finding())

    rendered = "\n".join(lines)
    assert "basic structure" not in rendered
    assert "exploitation points" not in rendered
    assert "Katana stored 1 URL/endpoint crawl observation(s) across 1 observed host(s)" in rendered
    assert "JavaScript files observed during this crawl: 0" in rendered
    assert "Query parameters observed during this crawl: 0" in rendered
    assert "Forms/actions observed during this crawl: 0" in rendered
    assert "Maximum observed crawl depth: 0" in rendered
    assert "Zero counts mean those items were not observed during this crawl" in rendered


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
