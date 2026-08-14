from unittest.mock import patch

from app.services.nmap_ai_assessment import (
    FALLBACK_LINES,
    build_nmap_ai_assessment_prompt,
    generate_nmap_ai_assessment,
)
from app.ui.ai_summary import render_ai_summary_card


def test_nmap_ai_prompt_includes_observed_ports_and_constraints() -> None:
    prompt = build_nmap_ai_assessment_prompt(
        {
            "target": "scanme.nmap.org",
            "host_status": "Up",
            "risk_level": "medium",
            "risk_notes": ["SSH exposed"],
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        }
    )

    assert "Use only the supplied observed Nmap evidence." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not recommend exploitation." in prompt
    assert "Do not claim the target is safe or secure." in prompt
    assert "Never contradict the supplied evidence." in prompt
    assert "Never say no open services were observed if open ports are supplied." in prompt
    assert "Observed Assets must include the target host or IP when supplied." in prompt
    assert "Observed Assets must include observed services when open ports are supplied." in prompt
    assert "22/tcp ssh" in prompt
    assert "Host: scanme.nmap.org" in prompt
    assert "Services: 22/tcp ssh" in prompt
    assert "SSH exposed" in prompt
    assert "State only observed ports, services, and reachability" in prompt
    assert 'Do not say "no significant vulnerabilities"' in prompt
    assert "overall low-risk verdict" in prompt


def test_nmap_ai_prompt_includes_comparison_and_impact() -> None:
    prompt = build_nmap_ai_assessment_prompt(
        {
            "target": "example.com",
            "open_ports": [{"port": "80", "protocol": "tcp", "service": "http"}],
            "comparison": {
                "summary": "New HTTP service observed.",
                "new_ports": [{"port": "80", "protocol": "tcp", "service": "http"}],
                "removed_ports": [],
                "risk_changed": True,
            },
            "impact": {"summary": "Public web exposure changed.", "impact_level": "medium"},
        }
    )

    assert "New HTTP service observed." in prompt
    assert "80/tcp http" in prompt
    assert "Public web exposure changed." in prompt
    assert "Impact level: medium" in prompt


def test_nmap_ai_prompt_handles_no_open_ports() -> None:
    prompt = build_nmap_ai_assessment_prompt({"target": "example.com", "host_status": "Up", "open_ports": []})

    assert "no open TCP services were observed by this scan" in prompt
    assert "Open ports and services: none observed by this scan" in prompt


def test_nmap_ai_prompt_marks_unknown_host_status_inconclusive() -> None:
    prompt = build_nmap_ai_assessment_prompt(
        {
            "target": "this-host-does-not-exist-123456.example",
            "host_status": None,
            "risk_level": "unknown",
            "open_ports": [],
            "assessment_result": "inconclusive",
        }
    )

    assert "Target: this-host-does-not-exist-123456.example" in prompt
    assert "Assessment result: inconclusive" in prompt
    assert "not established by this scan" in prompt
    assert "Do not describe this as a clean scan, low-risk result, or absence of vulnerabilities." in prompt


def test_nmap_ai_assessment_inconclusive_guard_avoids_clean_or_low_risk_claims() -> None:
    with patch("app.services.nmap_ai_assessment.ask_ai", return_value="No significant vulnerabilities detected. Low risk."):
        lines = generate_nmap_ai_assessment(
            {
                "target": "this-host-does-not-exist-123456.example",
                "host_status": None,
                "risk_level": "unknown",
                "open_ports": [],
                "assessment_result": "inconclusive",
            }
        )

    text = "\n".join(lines)
    assert "this-host-does-not-exist-123456.example" in text
    assert "not establish a reachable or assessable target" in text
    assert "No conclusion about exposed services, vulnerabilities, or security posture" in text
    assert "No significant vulnerabilities detected" not in text
    assert "Low risk" not in text


def test_nmap_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- SSH was observed.\n\nConfidence\nMedium"

    with patch("app.services.nmap_ai_assessment.ask_ai", return_value=response):
        assert generate_nmap_ai_assessment({"target": "example.com"}) == response.splitlines()


def test_nmap_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.nmap_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_nmap_ai_assessment({"target": "example.com"}) == FALLBACK_LINES


def test_nmap_ai_assessment_renderer_uses_polished_title() -> None:
    card = render_ai_summary_card(
        ["Executive Summary:", "- Evidence reviewed.", "", "Confidence:", "Low"],
        title="Nmap AI Assessment",
    )

    assert "Nmap AI Assessment" in card
    assert "Executive Summary:" not in card
    assert "Executive Summary\n- Evidence reviewed." in card
