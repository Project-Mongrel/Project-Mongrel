import json

import pytest

from app.parsers.prowler_parser import ProwlerParserError, normalize_prowler_output


def _ocsf_fixture() -> str:
    return json.dumps(
        [
            {
                "metadata": {"event_code": "iam_user_no_administrator_access", "product": {"feature": {"name": "iam"}}},
                "cloud": {"provider": "aws", "region": "global"},
                "finding_info": {
                    "uid": "finding-001",
                    "title": "Avoid administrator access",
                    "desc": "Synthetic failed IAM check.",
                },
                "status_code": "FAIL",
                "severity": "medium",
                "risk_details": "Excessive permissions may increase operational risk.",
                "resources": [
                    {
                        "uid": "resource-001",
                        "name": "synthetic-admin-user",
                        "region": "global",
                        "group": {"name": "iam"},
                    }
                ],
                "remediation": {
                    "desc": "Review assigned policies.",
                    "references": ["https://docs.example.invalid/synthetic"],
                },
            },
            {
                "metadata": {"event_code": "s3_bucket_public_access_block", "product": {"feature": {"name": "s3"}}},
                "cloud": {"provider": "aws", "region": "eu-west-1"},
                "finding_info": {"uid": "finding-002", "title": "Block public access enabled"},
                "status_code": "PASS",
                "severity": "informational",
                "resources": [{"uid": "resource-002", "name": "synthetic-bucket", "region": "eu-west-1"}],
            },
        ]
    )


def test_prowler_json_ocsf_fixture_parses() -> None:
    evidence = normalize_prowler_output(_ocsf_fixture())

    assert evidence["provider"] == "aws"
    assert evidence["finding_count"] == 2
    assert evidence["status_summary"] == {"FAIL": 1, "PASS": 1}
    assert evidence["findings"][0]["check_id"] == "iam_user_no_administrator_access"
    assert evidence["findings"][0]["check_title"] == "Avoid administrator access"
    assert evidence["findings"][0]["service"] == "iam"
    assert evidence["findings"][0]["region"] == "global"
    assert evidence["findings"][0]["resource_identifier"] == "resource-001"
    assert evidence["findings"][0]["remediation"]["description"] == "Review assigned policies."


def test_prowler_malformed_input_fails_safely() -> None:
    with pytest.raises(ProwlerParserError):
        normalize_prowler_output("{not json")
    with pytest.raises(ProwlerParserError):
        normalize_prowler_output(["not-object"])


def test_prowler_missing_optional_fields_are_tolerated() -> None:
    evidence = normalize_prowler_output([{"status_code": "PASS"}], provider="gcp")
    finding = evidence["findings"][0]

    assert evidence["provider"] == "gcp"
    assert finding["status"] == "PASS"
    assert finding["check_id"] == ""
    assert finding["resource_identifier"] == ""
    assert finding["remediation"]["references"] == []


def test_prowler_pass_remains_pass_not_vulnerability() -> None:
    evidence = normalize_prowler_output([{"status_code": "PASS", "severity": "low"}], provider="azure")
    finding = evidence["findings"][0]

    assert finding["status"] == "PASS"
    assert finding["status_interpretation"] == "scanner_reported_passed_check"
    assert "vulnerability" not in json.dumps(finding).lower()


def test_prowler_fail_is_failed_check_not_confirmed_exploit() -> None:
    evidence = normalize_prowler_output([{"status_code": "FAIL", "severity": "critical"}], provider="aws")
    finding = evidence["findings"][0]

    assert finding["status"] == "FAIL"
    assert finding["status_interpretation"] == "scanner_reported_failed_check"
    serialized = json.dumps(finding).lower()
    assert "confirmed" not in serialized
    assert "exploit" not in serialized


def test_prowler_severity_preserved_exactly() -> None:
    evidence = normalize_prowler_output([{"status_code": "FAIL", "severity": "Medium"}], provider="aws")

    assert evidence["findings"][0]["severity"] == "Medium"
    assert evidence["severity_summary"] == {"Medium": 1}
