from unittest.mock import patch

from app.services.metasploit_ai_assessment import build_metasploit_ai_assessment_prompt, generate_metasploit_ai_assessment


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
    assert "appears vulnerable remains scanner-reported validation evidence" in prompt
    assert "NOT_REPRODUCED does not mean the target is secure." in prompt
    assert "FAILED or BLOCKED does not mean the target is not vulnerable." in prompt
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
