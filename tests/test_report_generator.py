import pytest
from unittest.mock import patch

from app.services.findings_store import add_finding, close_findings_database, configure_findings_database
from app.services.report_generator import build_report_ai_assessment_prompt, generate_markdown_report


@pytest.fixture(autouse=True)
def sqlite_findings_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_report_generation_from_nmap_findings() -> None:
    add_finding(
        user_id=9001,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )

    report = generate_markdown_report(user_id=9001, target="127.0.0.1")

    assert "# Project Mongrel" in report
    assert "Security Assessment Report" in report
    assert "Report ID:\nPM-" in report
    assert "Target / Scope:\n127.0.0.1" in report
    assert "Generated:" in report
    assert "Overall Risk:\nMEDIUM" in report
    assert "## Executive Summary" in report
    assert "## Assessment Statistics" in report
    assert "- Tools Used: Nmap" in report
    assert "- Nmap" in report
    assert "- Highest Risk: MEDIUM" in report
    assert "Nmap identified 1 open port(s)" in report
    assert "22/tcp ssh" in report
    assert "## Appendix / Scan History" in report


def test_report_generation_from_nuclei_findings() -> None:
    add_finding(
        user_id=9002,
        finding={
            "source": "nuclei",
            "target": "https://example.com",
            "risk_level": "high",
            "finding_count": 1,
            "nuclei_findings": [
                {
                    "template_id": "git-config-exposure",
                    "severity": "high",
                    "name": "Exposed Git Repository",
                }
            ],
        },
    )

    report = generate_markdown_report(user_id=9002, target="https://example.com")

    assert "- Nuclei" in report
    assert "- Highest Risk: HIGH" in report
    assert "Nuclei identified 1 finding(s)" in report
    assert "Exposed Git Repository (HIGH) - git-config-exposure" in report
    assert "- Patch or reconfigure affected services identified by Nuclei." in report


def test_report_generation_with_clean_nuclei_scan() -> None:
    add_finding(
        user_id=9003,
        finding={
            "source": "nuclei",
            "target": "hellosundaykids.com",
            "risk_level": "info",
            "finding_count": 0,
            "status": "clean",
            "summary": "No matching Nuclei findings were identified using the fast scan profile.",
        },
    )

    report = generate_markdown_report(user_id=9003, target="hellosundaykids.com")

    assert "Clean scan results recorded: 1." in report
    assert "## Clean Scan Notes" in report
    assert "Nuclei clean result for hellosundaykids.com" in report
    assert "No matching Nuclei findings were identified using the fast scan profile." in report
    assert "- Treat clean scans as point-in-time evidence, not proof that no vulnerabilities exist." in report


def test_report_generation_with_mixed_scan_history() -> None:
    add_finding(
        user_id=9004,
        finding={
            "source": "nmap",
            "target": "example.com",
            "risk_level": "medium",
            "open_ports": [{"port": "443", "protocol": "tcp", "service": "https"}],
        },
    )
    add_finding(
        user_id=9004,
        finding={
            "source": "nuclei",
            "target": "example.com",
            "risk_level": "high",
            "finding_count": 1,
            "nuclei_findings": [{"template_id": "missing-security-headers", "severity": "low"}],
        },
    )
    add_finding(
        user_id=9004,
        finding={
            "source": "nmap_xml",
            "target": "example.com",
            "risk_level": "low",
            "open_ports": [{"port": "80", "protocol": "tcp", "service": "http"}],
        },
    )

    report = generate_markdown_report(user_id=9004, target="example.com")

    assert "example.com has 3 recorded scan run(s)" in report
    assert "- Nmap" in report
    assert "- Nmap XML Upload" in report
    assert "- Nuclei" in report
    assert "- Highest Risk: HIGH" in report
    assert "443/tcp https" in report
    assert "80/tcp http" in report
    assert "missing-security-headers" in report


def test_empty_history_handling() -> None:
    report = generate_markdown_report(user_id=9005, target="missing.example")

    assert "# Project Mongrel" in report
    assert "missing.example" in report
    assert "No scan history is available for this user or target." in report
    assert "- None" in report
    assert "No technical findings were recorded." in report
    assert "No historical scan runs found." in report


def test_ai_assessment_section_included_when_ai_succeeds() -> None:
    add_finding(
        user_id=9006,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )

    with patch("app.services.report_generator.ask_ai", return_value="Overall risk is medium. Prioritize SSH hardening.") as ask_ai:
        report = generate_markdown_report(user_id=9006, target="127.0.0.1", include_ai_assessment=True)

    prompt = ask_ai.call_args.args[0]
    assert "## Executive Assessment" in report
    assert "Overall risk is medium. Prioritize SSH hardening." in report
    assert "Only use the provided scan history and findings." in prompt
    assert "22/tcp ssh" in prompt


def test_ai_assessment_fallback_when_ai_disabled() -> None:
    add_finding(user_id=9007, finding={"source": "nuclei", "target": "example.com", "risk_level": "low"})

    with patch("app.services.report_generator.ask_ai", return_value="AI integration is not configured yet."):
        report = generate_markdown_report(user_id=9007, target="example.com", include_ai_assessment=True)

    assert "## Executive Assessment" in report
    assert "AI assessment unavailable: AI integration is not configured yet." in report
    assert "# Project Mongrel" in report
    assert "## Technical Findings" in report


def test_ai_assessment_fallback_when_ai_errors() -> None:
    add_finding(user_id=9008, finding={"source": "nuclei", "target": "example.com", "risk_level": "high"})

    with patch("app.services.report_generator.ask_ai", side_effect=TimeoutError("timeout")):
        report = generate_markdown_report(user_id=9008, target="example.com", include_ai_assessment=True)

    assert "AI assessment unavailable: timeout" in report
    assert "The deterministic report remains based on persisted scan history." in report


def test_report_generation_still_works_without_ai() -> None:
    add_finding(user_id=9009, finding={"source": "nmap", "target": "127.0.0.1", "risk_level": "low"})

    with patch("app.services.report_generator.ask_ai") as ask_ai:
        report = generate_markdown_report(user_id=9009, target="127.0.0.1")

    ask_ai.assert_not_called()
    assert "## Executive Assessment" not in report
    assert "## Recommendations" in report


def test_report_ai_prompt_is_grounded() -> None:
    prompt = build_report_ai_assessment_prompt(
        [
            {
                "source": "nuclei",
                "target": "example.com",
                "risk_level": "high",
                "finding_count": 1,
                "nuclei_findings": [{"template_id": "git-config-exposure", "severity": "high"}],
            }
        ],
        target="example.com",
    )

    assert "Only use the provided scan history and findings." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not invent CVEs." in prompt
    assert "git-config-exposure" in prompt
    assert "Never recommend closing ports blindly." in prompt
    assert "Review whether the service is required" in prompt or "reviewing whether the service is required" in prompt


def test_report_uses_readable_timestamps_and_header() -> None:
    add_finding(user_id=9010, finding={"source": "nmap", "target": "127.0.0.1", "risk_level": "low"})

    report = generate_markdown_report(user_id=9010, target="127.0.0.1")

    assert "# Project Mongrel\nSecurity Assessment Report" in report
    assert "Target / Scope:\n127.0.0.1" in report
    generated_line = report.split("Generated:\n", 1)[1].split("\n", 1)[0]
    assert "UTC" in generated_line
    assert "+00:00" not in generated_line
    assert "-" not in generated_line


def test_single_target_report_does_not_say_multiple_targets() -> None:
    add_finding(user_id=9011, finding={"source": "nmap", "target": "localhost (127.0.0.1)", "risk_level": "low"})
    add_finding(user_id=9011, finding={"source": "nuclei", "target": "127.0.0.1", "risk_level": "info", "finding_count": 0})

    report = generate_markdown_report(user_id=9011)

    assert "Target / Scope:\n127.0.0.1" in report
    assert "Target / Scope:\nMultiple targets" not in report


def test_finding_aware_recommendations_appear() -> None:
    add_finding(
        user_id=9012,
        finding={
            "source": "nmap",
            "target": "example.com",
            "risk_level": "high",
            "open_ports": [
                {"port": "22", "protocol": "tcp", "service": "ssh"},
                {"port": "445", "protocol": "tcp", "service": "microsoft-ds"},
                {"port": "443", "protocol": "tcp", "service": "https"},
                {"port": "5432", "protocol": "tcp", "service": "postgresql"},
            ],
        },
    )

    report = generate_markdown_report(user_id=9012, target="example.com")

    assert "SSH: restrict access to trusted IPs or VPN" in report
    assert "SMB: block internet exposure" in report
    assert "HTTP/HTTPS: review security headers" in report
    assert "Databases: restrict network access" in report


def test_repeated_nmap_findings_are_deduplicated() -> None:
    ports = [{"port": "22", "protocol": "tcp", "service": "ssh"}]
    add_finding(user_id=9013, finding={"source": "nmap", "target": "127.0.0.1", "risk_level": "high", "open_ports": ports})
    add_finding(user_id=9013, finding={"source": "nmap", "target": "127.0.0.1", "risk_level": "high", "open_ports": ports})

    report = generate_markdown_report(user_id=9013, target="127.0.0.1")

    assert report.count("Nmap identified 1 open port(s)") == 1
    assert "Previous matching Nmap scan found; no port changes detected." in report
    assert "Nmap History" in report
    assert report.count("   - Target: 127.0.0.1") == 2


def test_report_header_supports_investigation_name() -> None:
    add_finding(user_id=9014, finding={"source": "nuclei", "target": "example.com", "risk_level": "low"})

    report = generate_markdown_report(user_id=9014, target="example.com", investigation_name="External perimeter review")

    assert "Investigation:\nExternal perimeter review" in report


def test_repeated_clean_nuclei_scans_are_deduplicated() -> None:
    clean_finding = {
        "source": "nuclei",
        "target": "example.com",
        "risk_level": "info",
        "finding_count": 0,
        "status": "clean",
        "summary": "No matching Nuclei findings were identified using the fast scan profile.",
    }
    add_finding(user_id=9015, finding=clean_finding)
    add_finding(user_id=9015, finding=clean_finding)

    report = generate_markdown_report(user_id=9015, target="example.com")

    assert "Two consecutive Nuclei Fast Scans completed with no findings." in report
    assert "Latest:" in report
    assert "Previous:" in report
    assert report.count("No matching Nuclei findings were identified using the fast scan profile.") < 3


def test_report_appendix_groups_history_by_tool() -> None:
    add_finding(user_id=9016, finding={"source": "nmap", "target": "example.com", "risk_level": "low"})
    add_finding(user_id=9016, finding={"source": "nuclei", "target": "example.com", "risk_level": "info", "finding_count": 0})

    report = generate_markdown_report(user_id=9016, target="example.com")

    assert "Nmap History" in report
    assert "Nuclei History" in report
    assert report.index("Nmap History") < report.index("Nuclei History")


def test_report_generation_includes_prowler_provider_context_counts_and_failed_checks() -> None:
    add_finding(
        user_id=9017,
        finding={
            "source": "prowler",
            "target": "standalone-aws",
            "target_key": "standalone-aws",
            "provider": "aws",
            "cloud_context": "standalone-aws",
            "risk_level": "info",
            "finding_count": 2,
            "status": "completed",
            "summary": "Prowler recorded 2 scanner-reported cloud posture finding(s) for AWS context standalone-aws.",
            "prowler_summary": {
                "finding_count": 2,
                "failed_count": 1,
                "passed_count": 1,
                "highest_severity": "Critical",
                "top_failed_services": ["iam: 1"],
            },
            "prowler_evidence": {
                "provider": "aws",
                "cloud_context": "standalone-aws",
                "finding_count": 2,
                "findings": [
                    {
                        "status": "FAIL",
                        "severity": "Critical",
                        "check_id": "iam_root_mfa",
                        "check_title": "Root MFA check",
                        "service": "iam",
                        "region": "global",
                        "resource_identifier": "AKIAABCDEFGHIJKLMNOP",
                    },
                    {"status": "PASS", "severity": "informational", "check_id": "s3_public_block", "service": "s3"},
                ],
            },
        },
    )

    report = generate_markdown_report(user_id=9017, target="standalone-aws")

    assert "- Prowler" in report
    assert "Provider: AWS" in report
    assert "Context: standalone-aws" in report
    assert "Total checks/findings parsed: 2" in report
    assert "Failed checks: 1" in report
    assert "Passed checks: 1" in report
    assert "Highest scanner-reported severity: Critical" in report
    assert "FAIL iam_root_mfa severity=Critical service=iam" in report
    assert "AKIAABCDEFGHIJKLMNOP" not in report
    assert "{\"" not in report


def test_report_generation_includes_metasploit_validation_without_raw_console_dump() -> None:
    add_finding(
        user_id=9018,
        finding={
            "source": "metasploit",
            "target": "example.com",
            "target_key": "example.com",
            "risk_level": "high",
            "finding_count": 1,
            "status": "completed",
            "summary": "Metasploit reported validation evidence. This is not proof of full compromise.",
            "raw_output": "RAW " * 500,
            "metasploit_evidence": {
                "module": "auxiliary/scanner/http/http_version",
                "action_type": "auxiliary_validation",
                "target": "example.com",
                "port": 80,
                "validation_state": "VALIDATED",
                "summary": "Metasploit reported validation evidence. This is not proof of full compromise.",
                "raw_evidence_excerpt": "The target appears vulnerable",
            },
            "metadata": {
                "proposal_id": "proposal-123",
                "artifact_ref": "assessment_artifact:9",
                "module": "auxiliary/scanner/http/http_version",
                "action_type": "auxiliary_validation",
                "port": 80,
            },
        },
    )

    report = generate_markdown_report(user_id=9018, target="example.com")

    assert "- Metasploit" in report
    assert "Module: auxiliary/scanner/http/http_version" in report
    assert "Action: auxiliary_validation" in report
    assert "Validation State: VALIDATED" in report
    assert "Proposal Reference: proposal-123" in report
    assert "Artifact Reference: assessment_artifact:9" in report
    assert "The target appears vulnerable" in report
    assert "not proof of full compromise" in report
    assert ("RAW " * 20) not in report
