from unittest.mock import patch

import pytest

from app.services.prowler_ai_assessment import (
    FALLBACK_LINES,
    TRUTHFULNESS_FALLBACK_LINES,
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
    assert "specific tested check as passed" in prompt
    assert "FAIL means Prowler reported a failed check" in prompt
    assert "not proof of exploitability, compromise, unauthorized access, data exposure" in prompt
    assert "Severity is Prowler scanner-reported severity" in prompt
    assert "Compliance mappings are check/control mappings only" in prompt
    assert "do not say no misconfigurations or vulnerabilities exist" in prompt
    assert "status=FAIL" in prompt
    assert "status=PASS" in prompt
    assert "severity=High" in prompt
    assert "AKIAABCDEFGHIJKLMNOP" not in prompt
    assert "<REDACTED>" in prompt
    assert "raw JSON" in prompt
    assert "organization-wide compliance" in prompt


def test_prowler_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- Prowler evidence reviewed.\n\nEvidence Confidence / Limitations\nMedium"
    with patch("app.services.prowler_ai_assessment.ask_ai", return_value=response):
        assert generate_prowler_ai_assessment(_finding()) == response.splitlines()


def test_prowler_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.prowler_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_prowler_ai_assessment(_finding()) == FALLBACK_LINES


@pytest.mark.parametrize(
    "unsafe_response",
    [
        "Executive Summary\n- The AWS account is secure.",
        "Executive Summary\n- This resource is exploitable.",
        "Executive Summary\n- A confirmed vulnerability was found.",
        "Executive Summary\n- The failed check confirms compromise.",
        "Executive Summary\n- Sensitive data is exposed.",
        "Executive Summary\n- The organization is non-compliant with CIS.",
        "Executive Summary\n- No misconfigurations exist.",
    ],
)
def test_prowler_unsupported_generated_conclusions_are_withheld(unsafe_response: str) -> None:
    with patch("app.services.prowler_ai_assessment.ask_ai", return_value=unsafe_response):
        lines = generate_prowler_ai_assessment(_finding())

    assert lines == TRUTHFULNESS_FALLBACK_LINES
    assert unsafe_response not in "\n".join(lines)


def test_prowler_legitimate_check_scoped_wording_is_allowed() -> None:
    response = "\n".join(
        [
            "Executive Summary",
            "- Prowler reported FAIL for this check.",
            "- Prowler reported PASS for another specific check.",
            "- HIGH severity is the scanner-reported severity for the failed check.",
            "- This check is mapped by Prowler to a listed compliance framework/control.",
            "- This does not establish exploitability, compromise, data exposure, or organization-wide non-compliance.",
        ]
    )

    with patch("app.services.prowler_ai_assessment.ask_ai", return_value=response):
        assert generate_prowler_ai_assessment(_finding()) == response.splitlines()


def test_prowler_all_pass_prompt_preserves_uncertainty() -> None:
    finding = _finding()
    finding["prowler_summary"] = {
        "finding_count": 1,
        "failed_count": 0,
        "passed_count": 1,
        "highest_severity": "informational",
        "top_failed_services": [],
    }
    finding["prowler_evidence"]["findings"] = [finding["prowler_evidence"]["findings"][1]]

    prompt = build_prowler_ai_assessment_prompt(finding)

    assert "If no FAIL findings are reported" in prompt
    assert "do not say no misconfigurations or vulnerabilities exist" in prompt
    assert "does not prove the resource, service, account, or environment is secure" in prompt
