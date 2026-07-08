from unittest.mock import patch

from app.services.nuclei_ai_assessment import (
    CLEAN_SCAN_FACT,
    CLEAN_SCAN_LIMITATION,
    FALLBACK_LINES,
    build_nuclei_ai_assessment_prompt,
    generate_nuclei_ai_assessment,
)
from app.ui.ai_summary import render_ai_summary_card


def test_nuclei_ai_prompt_includes_target_and_finding_count() -> None:
    prompt = build_nuclei_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "finding_count": 2,
            "risk_level": "high",
            "metadata": {"scan_profile": "fast", "elapsed": "9s"},
        }
    )

    assert "Target URL: https://example.com" in prompt
    assert "Finding count: 2" in prompt
    assert "Risk level: high" in prompt
    assert "Scan profile/templates: fast" in prompt
    assert "Elapsed time: 9s" in prompt
    assert "no selected templates matched" in prompt
    assert "does not establish that no exploitable vulnerabilities exist" in prompt


def test_nuclei_ai_prompt_includes_matched_findings_and_templates() -> None:
    prompt = build_nuclei_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "finding_count": 1,
            "nuclei_findings": [
                {
                    "template_id": "git-config-exposure",
                    "severity": "high",
                    "name": "Exposed Git Repository",
                    "host": "https://example.com",
                    "matched_at": "https://example.com/.git/config",
                    "tags": ["git", "exposure"],
                }
            ],
        }
    )

    assert "git-config-exposure" in prompt
    assert "Exposed Git Repository" in prompt
    assert "https://example.com/.git/config" in prompt
    assert "tags=git, exposure" in prompt


def test_nuclei_ai_prompt_includes_evidence_only_constraints() -> None:
    prompt = build_nuclei_ai_assessment_prompt({"target": "https://example.com"})

    assert "Use only the supplied observed Nuclei evidence." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not recommend exploitation." in prompt
    assert "Do not claim the target is safe or secure." in prompt


def test_nuclei_ai_prompt_clean_scan_includes_template_limitation() -> None:
    prompt = build_nuclei_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "finding_count": 0,
            "nuclei_findings": [],
        }
    )

    assert CLEAN_SCAN_FACT in prompt
    assert CLEAN_SCAN_LIMITATION in prompt
    assert "should not be interpreted as confirmation" in prompt


def test_nuclei_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- One matched finding was observed.\n\nConfidence\nMedium"

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        assert generate_nuclei_ai_assessment({"target": "https://example.com"}) == response.splitlines()


def test_nuclei_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.nuclei_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_nuclei_ai_assessment({"target": "https://example.com"}) == FALLBACK_LINES


def test_nuclei_ai_assessment_renderer_uses_polished_title() -> None:
    card = render_ai_summary_card(
        ["Executive Summary:", "- Evidence reviewed.", "", "Confidence:", "Low"],
        title="Nuclei AI Assessment",
    )

    assert "Nuclei AI Assessment" in card
    assert "Executive Summary:" not in card
    assert "Executive Summary\n- Evidence reviewed." in card
