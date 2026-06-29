from unittest.mock import patch

import pytest

from app.services.bbot_ai_assessment import (
    FALLBACK_LINES,
    build_bbot_ai_assessment_prompt,
    generate_bbot_ai_assessment,
)
from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.investigation_store import create_investigation
from app.services.observation_store import add_observation


@pytest.fixture(autouse=True)
def sqlite_observation_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_prompt_is_grounded() -> None:
    prompt = build_bbot_ai_assessment_prompt(
        observations=[_observation("subdomain", "admin.example.com")],
        recon_summary="BBOT Recon Summary\n- admin.example.com",
        investigation={"id": "inv-1", "name": "Investigation", "target": "example.com", "status": "open"},
        target="example.com",
    )

    assert "senior penetration tester preparing reconnaissance notes for another security consultant" in prompt
    assert "Only use the supplied normalized evidence and deterministic Recon Summary." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not invent assets, findings, technologies, ports, or certificates." in prompt
    assert "Do not claim compromise." in prompt
    assert "Do not recommend exploitation." in prompt
    assert "Do not say a service is vulnerable unless evidence supports it." in prompt
    assert "Use cautious language" in prompt
    assert "Confidence must be High, Medium, or Low" in prompt
    assert "Executive Summary" in prompt
    assert "Key Findings" in prompt
    assert "Observed Assets" in prompt
    assert "Potential Risks" in prompt
    assert "Recommended Next Actions" in prompt


def test_prompt_uses_normalized_evidence_not_raw_output() -> None:
    observation = _observation("subdomain", "app.example.com")
    observation["metadata"] = {
        "raw_output": "RAW BBOT STDOUT SHOULD NOT APPEAR",
        "module": "spasmodic_melvin",
        "scan_name": "spasmodic_melvin",
    }

    prompt = build_bbot_ai_assessment_prompt(
        observations=[observation],
        recon_summary="BBOT Recon Summary",
        target="example.com",
    )

    assert "app.example.com" in prompt
    assert "RAW BBOT STDOUT SHOULD NOT APPEAR" not in prompt
    assert "spasmodic_melvin" not in prompt
    assert "metadata" not in prompt.lower()


def test_prompt_never_contains_tool_or_internal_terms() -> None:
    observation = _observation("technology", "nginx")
    observation["source"] = "bbot"
    observation["summary"] = "BBOT identified technology from module httpx"

    prompt = build_bbot_ai_assessment_prompt(
        observations=[observation],
        recon_summary="BBOT Recon Summary\nRaw Events: 2\nstdout: hidden\nstderr: hidden",
        investigation={"id": "internal-id", "name": "spasmodic_melvin", "target": "example.com", "status": "open"},
        target="example.com",
    )
    forbidden_terms = [
        "bbot",
        "spasmodic_melvin",
        "module",
        "stdout",
        "stderr",
        "json",
        "ansible",
        "dependency installation",
        "implementation details",
        "internal-id",
        "observation store",
    ]

    assert "nginx" in prompt
    assert all(term not in prompt.lower() for term in forbidden_terms)


def test_successful_ai_response() -> None:
    investigation = create_investigation(user_id=11001, target="example.com")
    add_observation(
        user_id=11001,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="admin.example.com",
        target="example.com",
    )
    ai_response = "\n".join(
        [
            "Executive Summary",
            "- Several externally visible assets were observed.",
            "Key Findings",
            "- admin.example.com may indicate an administrative surface.",
            "Confidence:",
            "Medium",
        ]
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=ai_response):
        lines = generate_bbot_ai_assessment(11001, investigation_id=investigation["id"], target="example.com")

    assert lines == ai_response.splitlines()


def test_ai_disabled_fallback() -> None:
    investigation = create_investigation(user_id=11002, target="example.com")
    add_observation(
        user_id=11002,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="app.example.com",
        target="example.com",
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value="AI integration is not configured yet."):
        assert generate_bbot_ai_assessment(11002, investigation_id=investigation["id"], target="example.com") == FALLBACK_LINES


def test_ai_error_fallback() -> None:
    investigation = create_investigation(user_id=11003, target="example.com")
    add_observation(
        user_id=11003,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="url",
        value="https://app.example.com",
        target="example.com",
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_bbot_ai_assessment(11003, investigation_id=investigation["id"], target="example.com") == FALLBACK_LINES


def test_empty_observations_returns_limited_evidence_assessment() -> None:
    lines = generate_bbot_ai_assessment(11004, target="example.com")
    text = "\n".join(lines)

    assert "Executive Summary" in text
    assert "Key Findings" in text
    assert "Observed Assets" in text
    assert "Potential Risks" in text
    assert "Confidence:\nLow" in text
    assert "Recommended Next Actions" in text
    assert "Evidence is limited" in text
    assert "BBOT" not in text
    assert "Observation Store" not in text


def test_confidence_section_exists() -> None:
    lines = generate_bbot_ai_assessment(11005, target="example.com")

    assert "Confidence:" in lines


def test_ai_response_scanner_internals_are_removed() -> None:
    investigation = create_investigation(user_id=11006, target="example.com")
    add_observation(
        user_id=11006,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="app.example.com",
        target="example.com",
    )
    ai_response = "\n".join(
        [
            "Executive Summary",
            "- app.example.com was observed.",
            "- BBOT module spasmodic_melvin wrote JSON to stdout.",
            "Confidence:",
            "Medium",
            "Recommended Next Actions",
            "- Enumerate discovered web applications.",
        ]
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=ai_response):
        lines = generate_bbot_ai_assessment(11006, investigation_id=investigation["id"], target="example.com")

    text = "\n".join(lines)
    assert "app.example.com was observed" in text
    assert "Enumerate discovered web applications" in text
    assert "BBOT" not in text
    assert "spasmodic_melvin" not in text
    assert "stdout" not in text


def _observation(observation_type: str, value: str) -> dict:
    return {
        "source": "bbot",
        "observation_type": observation_type,
        "value": value,
        "target": "example.com",
        "confidence": "medium",
        "risk_level": "info",
        "summary": f"BBOT identified {observation_type}: {value}",
    }
