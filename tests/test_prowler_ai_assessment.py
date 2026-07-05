from unittest.mock import patch

from app.services.prowler_ai_assessment import (
    FALLBACK_LINES,
    build_prowler_ai_assessment_prompt,
    generate_prowler_ai_assessment,
)


def _finding() -> dict:
    return {
        "source": "prowler",
        "target": "standalone-aws",
        "provider": "aws",
        "cloud_context": "standalone-aws",
        "status": "completed",
        "prowler_summary": {
            "finding_count": 2,
            "failed_count": 1,
            "passed_count": 1,
            "highest_severity": "High",
            "top_failed_services": ["iam: 1"],
        },
        "prowler_evidence": {
            "provider": "aws",
            "cloud_context": "standalone-aws",
            "finding_count": 2,
            "findings": [
                {
                    "status": "FAIL",
                    "status_interpretation": "scanner_reported_failed_check",
                    "severity": "High",
                    "check_id": "iam_policy_check",
                    "check_title": "IAM policy check",
                    "service": "iam",
                    "region": "global",
                    "resource_identifier": "AKIAABCDEFGHIJKLMNOP",
                },
                {
                    "status": "PASS",
                    "status_interpretation": "scanner_reported_passed_check",
                    "severity": "informational",
                    "check_id": "s3_check",
                    "service": "s3",
                },
            ],
            "limitations": ["FAIL results are failed checks, not confirmed exploitability or compromise."],
        },
    }


def test_prowler_ai_prompt_uses_normalized_evidence_and_preserves_scanner_wording() -> None:
    prompt = build_prowler_ai_assessment_prompt(_finding())

    assert "Use only the supplied normalized Prowler evidence." in prompt
    assert "PASS means Prowler reported the check as passed." in prompt
    assert "FAIL means Prowler reported a failed check." in prompt
    assert "FAIL does not automatically mean confirmed exploitable vulnerability." in prompt
    assert "Do not invent exploitability, breach, attack paths, account compromise, or attacker access." in prompt
    assert "Do not claim a compliance breach unless Prowler evidence explicitly includes compliance metadata." in prompt
    assert "status=FAIL" in prompt
    assert "status=PASS" in prompt
    assert "severity=High" in prompt
    assert "AKIAABCDEFGHIJKLMNOP" not in prompt
    assert "<REDACTED>" in prompt
    assert "raw JSON" in prompt


def test_prowler_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- Prowler evidence reviewed.\n\nEvidence Confidence / Limitations\nMedium"
    with patch("app.services.prowler_ai_assessment.ask_ai", return_value=response):
        assert generate_prowler_ai_assessment(_finding()) == response.splitlines()


def test_prowler_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.prowler_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_prowler_ai_assessment(_finding()) == FALLBACK_LINES
