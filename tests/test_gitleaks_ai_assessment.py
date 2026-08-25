from unittest.mock import patch

import pytest

from app.services.gitleaks_ai_assessment import (
    FALLBACK_LINES,
    TRUTHFULNESS_FALLBACK_LINES,
    build_gitleaks_ai_assessment_prompt,
    generate_gitleaks_ai_assessment,
)


def test_gitleaks_ai_prompt_uses_only_redacted_evidence() -> None:
    prompt = build_gitleaks_ai_assessment_prompt(
        {
            "target": "/tmp/artifact",
            "status": "completed",
            "gitleaks_summary": {
                "finding_count": 1,
                "affected_files_count": 1,
                "rule_summary": {"github-pat": 1},
                "provider_summary": {"github": 1},
                "severity_summary": {"high": 1},
            },
            "gitleaks_evidence": {
                "scan_root": "/tmp/artifact",
                "findings": [
                    {
                        "rule_id": "github-pat",
                        "file_path": "src/config.py",
                        "line_number": 12,
                        "provider": "github",
                        "severity": "high",
                        "fingerprint": "abc123",
                        "redacted_secret_preview": "<REDACTED> len=36",
                    }
                ],
            },
        }
    )

    assert "Use only the supplied redacted Gitleaks evidence." in prompt
    assert "Never include or infer raw secret values." in prompt
    assert "Do not claim compromise." in prompt
    assert "Do not claim detected values are valid, active, usable, owned by the target, or known to provide access." in prompt
    assert "Recommend review and rotation/revocation if the potential secret is confirmed." in prompt
    assert "secret=<REDACTED> len=36" in prompt
    assert "validity, current usability, ownership, access, compromise, exfiltration, and repository security were not established" in prompt


def test_gitleaks_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- Redacted secret exposure observed.\n\nConfidence\nMedium"

    with patch("app.services.gitleaks_ai_assessment.ask_ai", return_value=response):
        assert generate_gitleaks_ai_assessment({"target": "/tmp/artifact"}) == response.splitlines()


def test_gitleaks_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.gitleaks_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_gitleaks_ai_assessment({"target": "/tmp/artifact"}) == FALLBACK_LINES


def test_gitleaks_zero_findings_prompt_preserves_uncertainty() -> None:
    prompt = build_gitleaks_ai_assessment_prompt(
        {
            "target": "/tmp/artifact",
            "status": "completed",
            "gitleaks_summary": {"finding_count": 0},
            "gitleaks_evidence": {"scan_root": "/tmp/artifact", "finding_count": 0, "findings": []},
        }
    )

    assert "Zero findings only means Gitleaks reported no matches within the scanned scope and configured rules." in prompt
    assert "do not say no secrets exist" in prompt


@pytest.mark.parametrize(
    "unsafe_response",
    [
        "Executive Summary\nActive credentials were exposed.",
        "Executive Summary\nThe repository is compromised.",
        "Executive Summary\nThis token can be used by attackers.",
        "Executive Summary\nThe detected credential is valid.",
        "Executive Summary\nThe repository is secure because zero secrets were detected.",
        "Executive Summary\nSensitive data was leaked.",
    ],
)
def test_gitleaks_unsupported_generated_conclusions_are_withheld(unsafe_response: str) -> None:
    with patch("app.services.gitleaks_ai_assessment.ask_ai", return_value=unsafe_response):
        lines = generate_gitleaks_ai_assessment({"target": "/tmp/artifact"})

    assert lines == TRUTHFULNESS_FALLBACK_LINES


def test_gitleaks_legitimate_potential_secret_match_wording_is_allowed() -> None:
    response = "\n".join(
        [
            "Executive Summary",
            "Gitleaks reported a potential secret match for the configured rule.",
            "Validity and current usability were not established.",
        ]
    )

    with patch("app.services.gitleaks_ai_assessment.ask_ai", return_value=response):
        lines = generate_gitleaks_ai_assessment({"target": "/tmp/artifact"})

    assert lines == response.splitlines()
