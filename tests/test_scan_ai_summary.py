from unittest.mock import patch

from app.services.scan_ai_summary import FALLBACK_SUMMARY_LINES, build_scan_ai_summary_prompt, generate_scan_ai_summary


def test_scan_ai_summary_prompt_is_evidence_based() -> None:
    prompt = build_scan_ai_summary_prompt(
        {
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "medium",
            "finding_count": 1,
            "summary": "SSH was observed.",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        }
    )

    assert "Use only the supplied stored scan evidence." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Executive Summary" in prompt
    assert "Observed Facts" in prompt
    assert "22/tcp ssh" in prompt


def test_scan_ai_summary_success_returns_lines() -> None:
    response = "Executive Summary\n- Evidence reviewed.\n\nConfidence\nLow"

    with patch("app.services.scan_ai_summary.ask_ai", return_value=response):
        assert generate_scan_ai_summary({"source": "nmap", "target": "example.com"}) == response.splitlines()


def test_scan_ai_summary_failure_returns_deterministic_fallback() -> None:
    with patch("app.services.scan_ai_summary.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_scan_ai_summary({"source": "nmap", "target": "example.com"}) == FALLBACK_SUMMARY_LINES
