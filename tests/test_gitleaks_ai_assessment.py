from unittest.mock import patch

from app.services.gitleaks_ai_assessment import FALLBACK_LINES, build_gitleaks_ai_assessment_prompt, generate_gitleaks_ai_assessment


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
    assert "Recommend rotation/revocation" in prompt
    assert "secret=<REDACTED> len=36" in prompt


def test_gitleaks_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- Redacted secret exposure observed.\n\nConfidence\nMedium"

    with patch("app.services.gitleaks_ai_assessment.ask_ai", return_value=response):
        assert generate_gitleaks_ai_assessment({"target": "/tmp/artifact"}) == response.splitlines()


def test_gitleaks_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.gitleaks_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_gitleaks_ai_assessment({"target": "/tmp/artifact"}) == FALLBACK_LINES
