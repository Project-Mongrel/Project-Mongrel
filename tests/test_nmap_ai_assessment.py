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
    assert "Interpretation" in prompt
    assert "Limitations / Uncertainty" in prompt
    assert "Treat service and version strings as identification evidence only" in prompt


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
    prompt = build_nmap_ai_assessment_prompt({"target": "example.com", "host_status": "Up", "risk_level": "low", "open_ports": []})

    assert "no open TCP services were observed by this scan" in prompt
    assert "Open ports and services: none observed by this scan" in prompt
    assert "this does not prove no services or vulnerabilities exist" in prompt
    assert "not a safety or vulnerability-absence verdict" in prompt


def test_nmap_ai_prompt_includes_filtered_ports_without_safety_inference() -> None:
    prompt = build_nmap_ai_assessment_prompt(
        {
            "target": "example.com",
            "host_status": "Up",
            "risk_level": "low",
            "open_ports": [],
            "filtered_ports": [{"port": "443", "protocol": "tcp", "state": "filtered", "service": "https"}],
        }
    )

    assert "Filtered ports:" in prompt
    assert "443/tcp filtered https" in prompt
    assert "Do not claim a firewall is protecting the host from Nmap output alone." in prompt


def test_nmap_ai_prompt_includes_service_version_as_identification_only() -> None:
    prompt = build_nmap_ai_assessment_prompt(
        {
            "target": "example.com",
            "host_status": "Up",
            "risk_level": "medium",
            "open_ports": [{"port": "80", "protocol": "tcp", "service": "http", "version": "Apache httpd 2.4.58"}],
        }
    )

    assert "80/tcp http version=Apache httpd 2.4.58" in prompt
    assert "identification evidence only, not vulnerability proof" in prompt


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


def test_nmap_ai_prompt_service_presence_does_not_permit_vulnerability_claim() -> None:
    prompt = build_nmap_ai_assessment_prompt(
        {
            "target": "example.com",
            "host_status": "Up",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        }
    )

    assert "22/tcp ssh" in prompt
    assert "Do not say a service is vulnerable unless explicit evidence supports it." in prompt
    assert "Do not invent vulnerabilities." in prompt


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


def test_nmap_ai_assessment_withholds_unsupported_safety_claims() -> None:
    response = "\n".join(
        [
            "Executive Summary",
            "- The host is secure and no significant vulnerabilities were detected.",
            "",
            "Observed Facts",
            "- 22/tcp ssh",
        ]
    )

    with patch("app.services.nmap_ai_assessment.ask_ai", return_value=response):
        lines = generate_nmap_ai_assessment(
            {
                "target": "example.com",
                "host_status": "Up",
                "risk_level": "medium",
                "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
            }
        )

    text = "\n".join(lines)
    assert "withheld" in text.lower()
    assert "The host is secure" not in text
    assert "no significant vulnerabilities were detected" not in text
    assert "does not prove that a target is safe" in text


def test_nmap_ai_assessment_withholds_unsupported_safety_variants() -> None:
    unsupported_claims = [
        "The host is secure.",
        "The target appears safe.",
        "No security issues were found.",
        "No security risks were detected.",
        "The system is not vulnerable.",
        "No vulnerabilities were found.",
        "No threats detected.",
        "The host is fully protected.",
    ]

    for claim in unsupported_claims:
        with patch("app.services.nmap_ai_assessment.ask_ai", return_value=f"Executive Summary\n- {claim}"):
            lines = generate_nmap_ai_assessment(
                {
                    "target": "example.com",
                    "host_status": "Up",
                    "risk_level": "medium",
                    "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
                }
            )

        text = "\n".join(lines)
        assert "withheld" in text.lower()
        assert claim not in text


def test_nmap_ai_assessment_allows_evidence_scoped_negative_statements() -> None:
    legitimate_responses = [
        "Observed Facts\n- No open TCP ports were observed in this scan.",
        "Observed Facts\n- Nmap did not report vulnerability evidence.",
        "Limitations / Uncertainty\n- The evidence is insufficient to determine whether vulnerabilities exist.",
    ]

    for response in legitimate_responses:
        with patch("app.services.nmap_ai_assessment.ask_ai", return_value=response):
            lines = generate_nmap_ai_assessment(
                {
                    "target": "example.com",
                    "host_status": "Up",
                    "risk_level": "low",
                    "open_ports": [],
                }
            )

        assert lines == response.splitlines()


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
