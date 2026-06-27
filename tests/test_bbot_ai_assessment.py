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

    assert "Only use the supplied observations and recon summary." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not claim compromise." in prompt
    assert "Do not recommend exploitation." in prompt
    assert "Do not say a service is vulnerable unless evidence supports it." in prompt
    assert "Use cautious language" in prompt
    assert "Include confidence level." in prompt


def test_prompt_uses_observations_not_raw_output() -> None:
    observation = _observation("subdomain", "app.example.com")
    observation["metadata"] = {"raw_output": "RAW BBOT STDOUT SHOULD NOT APPEAR"}

    prompt = build_bbot_ai_assessment_prompt(
        observations=[observation],
        recon_summary="BBOT Recon Summary",
        target="example.com",
    )

    assert "app.example.com" in prompt
    assert "RAW BBOT STDOUT SHOULD NOT APPEAR" not in prompt


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
            "AI Recon Assessment",
            "Overall Recon Posture:",
            "MEDIUM",
            "Confidence:",
            "MEDIUM",
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

    assert "AI Recon Assessment" in text
    assert "Overall Recon Posture:\nUNKNOWN" in text
    assert "Confidence:\nLOW" in text
    assert "Evidence is limited" in text


def test_confidence_section_exists() -> None:
    lines = generate_bbot_ai_assessment(11005, target="example.com")

    assert "Confidence:" in lines


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
