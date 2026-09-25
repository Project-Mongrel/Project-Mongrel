from unittest.mock import patch

import pytest

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


def _live_playwright_finding() -> dict:
    return {
        "target": "https://btjoinery.ie",
        "status": "completed",
        "playwright_observation": {
            "requested_url": "https://btjoinery.ie",
            "final_url": "https://www.btjoinery.ie/",
            "load_status": "loaded",
            "status_code": 200,
            "forms_count": 0,
            "inputs_count": 12,
            "links_count": 56,
            "network_events": [{"url": f"https://www.btjoinery.ie/{index}"} for index in range(25)],
            "console_issue_count": 8,
            "network_issue_count": 0,
            "page_error_count": 0,
            "screenshot": {"path": "redacted.png"},
        },
        "playwright_summary": {
            "requested_url": "https://btjoinery.ie",
            "final_url": "https://www.btjoinery.ie/",
            "load_status": "loaded",
            "status_code": 200,
            "forms_count": 0,
            "inputs_count": 12,
            "links_count": 56,
            "network_events_count": 25,
            "console_issue_count": 8,
            "network_issue_count": 0,
            "page_error_count": 0,
            "screenshot_present": True,
        },
    }


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

    rendered = "\n".join(lines)
    assert lines != response.splitlines()
    assert unsupported_line not in rendered
    assert "Playwright stored passive browser-observation evidence" in rendered


@pytest.mark.parametrize(
    "legitimate_line",
    [
        "The browser received an HTTP 429 response; the cause is unknown from the supplied evidence.",
        "No forms were observed in the returned browser state.",
        "JavaScript activity was not observed in this capture.",
        "This passive observation does not test for XSS, SQL injection, or CSRF.",
        "The restricted response limited visibility into the application.",
        "Zero forms observed does not establish absence.",
        "Status 200 does not establish security or complete functionality.",
        "Console messages do not establish vulnerability or exploitability.",
        "This observation does not establish a vulnerability.",
        "Passive observation does not prove vulnerability or vulnerability absence.",
        "No vulnerability is confirmed by this observation alone.",
    ],
)
def test_playwright_evidence_scoped_limitations_are_allowed(legitimate_line: str) -> None:
    response = f"Executive Summary\n- {legitimate_line}"

    with patch("app.services.playwright_ai_assessment.ask_ai", return_value=response):
        lines = generate_playwright_ai_assessment({"target": "https://example.com"})

    assert lines == response.splitlines()


def test_playwright_live_sparse_specialist_overclaim_returns_grounded_fallback() -> None:
    response = "\n".join([
        "Executive Summary",
        "- Status 200 and load success show the site is functioning normally and secure.",
        "- The 12 inputs indicate a login or checkout workflow that may expose business risk.",
        "- Console events suggest vulnerabilities in the application.",
        "- No forms were found, so there are no form-related security issues.",
    ])

    with patch("app.services.playwright_ai_assessment.ask_ai", return_value=response):
        lines = generate_playwright_ai_assessment(_live_playwright_finding())

    rendered = "\n".join(lines)
    assert lines != response.splitlines()
    assert "functioning normally" not in rendered
    assert "login or checkout" not in rendered
    assert "suggest vulnerabilities" not in rendered
    assert "no form-related security issues" not in rendered
    assert "Final URL observed: https://www.btjoinery.ie/" in rendered
    assert "Status/load observed: status 200, load status loaded" in rendered
    assert "0 forms, 12 inputs, 56 links" in rendered
    assert "25 network event(s), 8 console issue(s), 0 network issue(s), 0 page error(s)" in rendered
    assert "Screenshot metadata present: yes" in rendered


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "No inputs were observed.",
        "There was an absence of links.",
        "No network events were observed.",
        "There were no console issues.",
    ],
)
def test_playwright_count_contradictions_use_observed_counts(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.playwright_ai_assessment.ask_ai", return_value=response):
        lines = generate_playwright_ai_assessment(_live_playwright_finding())

    assert lines != response.splitlines()
    assert unsupported_line not in "\n".join(lines)


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "There are no confirmed risks.",
        "There are no security issues.",
        "There are no indications of vulnerabilities.",
        "There are no indications of security issues.",
        "There is no evidence of vulnerabilities.",
        "There are no signs of XSS.",
        "This shows no evidence of SQL injection.",
        "The absence of evidence means the page is secure.",
    ],
)
def test_playwright_security_absence_conclusions_are_rejected(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.playwright_ai_assessment.ask_ai", return_value=response):
        lines = generate_playwright_ai_assessment(_live_playwright_finding())

    assert lines != response.splitlines()
    assert unsupported_line not in "\n".join(lines)


@pytest.mark.parametrize(
    "unsupported_line",
    [
        "The 12 inputs indicate a login workflow.",
        "The links suggest business functionality.",
        "The DOM fields show authentication behavior.",
        "Console events indicate vulnerabilities.",
        "Network events suggest security issues.",
        "Status 200 proves the site is secure.",
        "Load success shows complete functionality.",
    ],
)
def test_playwright_semantic_overclaims_are_rejected(unsupported_line: str) -> None:
    response = f"Executive Summary\n- {unsupported_line}"

    with patch("app.services.playwright_ai_assessment.ask_ai", return_value=response):
        lines = generate_playwright_ai_assessment(_live_playwright_finding())

    assert lines != response.splitlines()
    assert unsupported_line not in "\n".join(lines)


def test_playwright_compliant_live_shaped_response_is_accepted() -> None:
    response = "\n".join([
        "Executive Summary",
        "- Playwright observed a loaded browser state at the final URL.",
        "",
        "Observed Facts",
        "- The returned browser state had status 200 and load status loaded.",
        "- Zero forms, 12 inputs, 56 links, 25 network events, 8 console issues, 0 network issues, and 0 page errors were observed.",
        "",
        "Limitations / Uncertainty",
        "- These observations do not establish vulnerability, absence, security, or complete functionality.",
    ])

    with patch("app.services.playwright_ai_assessment.ask_ai", return_value=response):
        lines = generate_playwright_ai_assessment(_live_playwright_finding())

    assert lines == response.splitlines()
