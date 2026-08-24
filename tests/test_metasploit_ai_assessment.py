from unittest.mock import patch

import pytest

from app.services.metasploit_ai_assessment import (
    TRUTHFULNESS_FALLBACK_LINES,
    build_metasploit_ai_assessment_prompt,
    generate_metasploit_ai_assessment,
)


def _finding(validation_state: str = "NOT_REPRODUCED") -> dict:
    return {
        "source": "metasploit",
        "target": "example.com",
        "status": "completed",
        "summary": "Metasploit did not reproduce the condition. This is not proof that the target is secure.",
        "raw_output": "raw console dump should not be included",
        "metasploit_evidence": {
            "module": "auxiliary/scanner/http/http_version",
            "action_type": "auxiliary_validation",
            "target": "example.com",
            "port": 80,
            "validation_state": validation_state,
            "subprocess_success": True,
            "module_executed": True,
            "session_established": validation_state == "SESSION_ESTABLISHED",
            "summary": "Metasploit reported appears vulnerable evidence. This is not proof of full compromise.",
            "evidence_confidence": "tool_reported",
            "raw_evidence_excerpt": "The target appears vulnerable",
            "limitations": [
                "Failed, blocked, timed out, or not reproduced results do not mean the target is secure.",
                "No CVE, session, persistence, impact, or attacker access is inferred unless explicitly present in tool output.",
            ],
        },
        "metadata": {
            "proposal_id": "proposal-1",
            "artifact_ref": "assessment_artifact:7",
            "risk_tier": "low",
            "expected_effect": "version validation",
        },
    }


def test_metasploit_ai_prompt_uses_normalized_evidence_only() -> None:
    prompt = build_metasploit_ai_assessment_prompt(_finding())

    assert "Normalized Metasploit Evidence:" in prompt
    assert "Module: auxiliary/scanner/http/http_version" in prompt
    assert "Proposal Reference: proposal-1" in prompt
    assert "Artifact Reference: assessment_artifact:7" in prompt
    assert "raw console dump should not be included" not in prompt


def test_metasploit_ai_prompt_preserves_validation_uncertainty() -> None:
    prompt = build_metasploit_ai_assessment_prompt(_finding("FAILED"))

    assert "Scanner evidence is not automatically proof of exploitation." in prompt
    assert "Distinguish subprocess success from validation success, exploit success, and session establishment." in prompt
    assert "Module compatibility or successful msfconsole exit does not confirm vulnerability or exploitability." in prompt
    assert "appears vulnerable remains scanner-reported validation evidence" in prompt
    assert "NOT_REPRODUCED does not mean the target is secure." in prompt
    assert "FAILED or BLOCKED does not mean the target is not vulnerable." in prompt
    assert "Failed validation, no session, or timeout does not prove vulnerability absence or target safety." in prompt
    assert "Do not invent CVEs, sessions, persistence" in prompt
    assert "compromise" in prompt


def test_metasploit_ai_prompt_redacts_secret_like_values() -> None:
    finding = _finding()
    finding["metasploit_evidence"]["raw_evidence_excerpt"] = "password=SuperSecret token=abc123"

    prompt = build_metasploit_ai_assessment_prompt(finding)

    assert "<REDACTED>" in prompt
    assert "SuperSecret" not in prompt
    assert "abc123" not in prompt


def test_metasploit_ai_prompt_preserves_detected_without_upgrading_it() -> None:
    prompt = build_metasploit_ai_assessment_prompt(_finding("DETECTED"))

    assert "Validation State: DETECTED" in prompt
    assert "Repeat the supplied Validation State exactly" in prompt
    assert "DETECTED means service, banner, or version metadata was observed only." in prompt
    assert "DETECTED must never be described as vulnerable, exploited, compromised, or VALIDATED." in prompt
    assert "Do not invent access, impact, or vulnerability from DETECTED metadata." in prompt
    assert "did not observe any vulnerabilities" in prompt
    assert "no vulnerabilities observed" in prompt
    assert "no remediation required" in prompt
    assert "Do not infer that a connection is legitimate or unauthorized from an SSH key fingerprint" in prompt
    assert "detected service/banner/key metadata only and did not validate a vulnerability condition" in prompt
    assert "correlate with Nmap or service inventory" in prompt


def test_metasploit_ai_prompt_inconclusive_does_not_claim_metadata_observed() -> None:
    finding = _finding("INCONCLUSIVE")
    finding["metasploit_evidence"]["summary"] = "Metasploit output did not provide a conclusive validation result."
    finding["metasploit_evidence"]["raw_evidence_excerpt"] = "Module completed without structured metadata."

    prompt = build_metasploit_ai_assessment_prompt(finding)

    assert "Validation State: INCONCLUSIVE" in prompt
    assert "INCONCLUSIVE means no conclusive validation evidence was parsed." in prompt
    assert "do not claim service, banner, version, or key metadata was observed" in prompt
    assert "DETECTED means service, banner, or version metadata was observed only." not in prompt
    assert "This action detected service/banner/key metadata only" not in prompt


def test_metasploit_ai_prompt_session_state_allows_only_explicit_session_claim() -> None:
    prompt = build_metasploit_ai_assessment_prompt(_finding("SESSION_ESTABLISHED"))

    assert "Validation State: SESSION_ESTABLISHED" in prompt
    assert "Session Established: True" in prompt
    assert "SESSION_ESTABLISHED means the normalized evidence explicitly reported a session." in prompt
    assert "do not infer persistence, privilege level, lateral movement, data access, or broader compromise" in prompt


def test_metasploit_ai_prompt_preserves_advanced_action_scope() -> None:
    finding = _finding("INCONCLUSIVE")
    finding["metasploit_evidence"]["module"] = "exploit/multi/http/struts2_content_type_ognl"
    finding["metasploit_evidence"]["action_type"] = "exploit_validation"
    finding["metasploit_evidence"]["port"] = 443
    finding["metadata"]["expected_effect"] = "Validate whether the authorized target appears affected by the selected module."

    prompt = build_metasploit_ai_assessment_prompt(finding)

    assert "Module: exploit/multi/http/struts2_content_type_ognl" in prompt
    assert "Action: exploit_validation" in prompt
    assert "Port: 443" in prompt
    assert "Expected Effect: Validate whether the authorized target appears affected by the selected module." in prompt
    assert "Do not invent CVEs, sessions, persistence" in prompt


def test_metasploit_detected_output_replaces_unsafe_ai_wording() -> None:
    unsafe_response = "\n".join(
        [
            "Executive Summary",
            "No vulnerabilities observed and no remediation required.",
            "The SSH fingerprint indicates a legitimate connection.",
        ]
    )

    with patch("app.services.metasploit_ai_assessment.ask_ai", return_value=unsafe_response):
        lines = generate_metasploit_ai_assessment(_finding("DETECTED"))

    output = "\n".join(lines)
    assert "no vulnerabilities observed" not in output.lower()
    assert "no remediation required" not in output.lower()
    assert "legitimate connection" not in output.lower()
    assert "detected service/banner/key metadata only and did not validate a vulnerability condition" in output
    assert "correlate the metadata with Nmap or the service inventory" in output
    assert "No vulnerability conclusion can be made from this result alone." in output


@pytest.mark.parametrize(
    "unsafe_response",
    [
        "Executive Summary\nThe target was compromised.",
        "Executive Summary\nThe exploit succeeded.",
        "Executive Summary\nThe vulnerability has been confirmed.",
        "Executive Summary\nA shell was obtained.",
        "Executive Summary\nThe system is owned.",
        "Executive Summary\nThe target is secure because validation failed.",
    ],
)
def test_metasploit_unsupported_generated_claims_are_withheld_without_session(unsafe_response: str) -> None:
    with patch("app.services.metasploit_ai_assessment.ask_ai", return_value=unsafe_response):
        lines = generate_metasploit_ai_assessment(_finding("VALIDATED"))

    assert lines == TRUTHFULNESS_FALLBACK_LINES


def test_metasploit_legitimate_session_scoped_wording_is_allowed() -> None:
    response = "\n".join(
        [
            "Executive Summary",
            "A session was established according to the normalized Metasploit evidence.",
            "This does not prove persistence, privilege level, lateral movement, or data access.",
        ]
    )

    with patch("app.services.metasploit_ai_assessment.ask_ai", return_value=response):
        lines = generate_metasploit_ai_assessment(_finding("SESSION_ESTABLISHED"))

    assert lines == response.splitlines()


def test_metasploit_failed_validation_safety_claim_is_withheld() -> None:
    response = "Executive Summary\nThe target is safe because the validation failed."

    with patch("app.services.metasploit_ai_assessment.ask_ai", return_value=response):
        lines = generate_metasploit_ai_assessment(_finding("FAILED"))

    assert lines == TRUTHFULNESS_FALLBACK_LINES
