from unittest.mock import patch

from app.services.nuclei_ai_assessment import (
    CLEAN_SCAN_FACT,
    CLEAN_SCAN_LIMITATION,
    FALLBACK_LINES,
    TRUTHFULNESS_FALLBACK_LINES,
    build_nuclei_ai_assessment_prompt,
    generate_nuclei_ai_assessment,
)
from app.ui.ai_summary import render_ai_summary_card


def test_nuclei_ai_prompt_includes_target_and_finding_count() -> None:
    prompt = build_nuclei_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "finding_count": 2,
            "risk_level": "high",
            "metadata": {"scan_profile": "fast", "elapsed": "9s"},
        }
    )

    assert "Target URL: https://example.com" in prompt
    assert "Finding count: 2" in prompt
    assert "Risk level: high" in prompt
    assert "Scan profile/templates: fast" in prompt
    assert "Elapsed time: 9s" in prompt
    assert "no selected templates matched" in prompt
    assert "does not establish that no exploitable vulnerabilities exist" in prompt


def test_nuclei_ai_prompt_includes_matched_findings_and_templates() -> None:
    prompt = build_nuclei_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "finding_count": 1,
            "nuclei_findings": [
                {
                    "template_id": "git-config-exposure",
                    "severity": "high",
                    "name": "Exposed Git Repository",
                    "host": "https://example.com",
                    "matched_at": "https://example.com/.git/config",
                    "tags": ["git", "exposure"],
                }
            ],
        }
    )

    assert "git-config-exposure" in prompt
    assert "Exposed Git Repository" in prompt
    assert "https://example.com/.git/config" in prompt
    assert "tags=git, exposure" in prompt


def test_nuclei_ai_prompt_includes_evidence_only_constraints() -> None:
    prompt = build_nuclei_ai_assessment_prompt({"target": "https://example.com"})

    assert "Use only the supplied observed Nuclei evidence." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not recommend exploitation." in prompt
    assert "Do not claim the target is safe or secure." in prompt
    assert "Never claim or imply findings are not indicative of a compromised system" in prompt
    assert "Preserve scanner-reported severity exactly" in prompt
    assert "Do not invent scan-profile labels unless execution metadata explicitly supplies them." in prompt
    assert "A deprecated X-XSS-Protection header does not prove or directly enable XSS." in prompt
    assert "GraphQL alias batching" in prompt
    assert "Interpretation" in prompt
    assert "Limitations" in prompt


def test_nuclei_ai_prompt_clean_scan_includes_template_limitation() -> None:
    prompt = build_nuclei_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "finding_count": 0,
            "nuclei_findings": [],
        }
    )

    assert CLEAN_SCAN_FACT in prompt
    assert CLEAN_SCAN_LIMITATION in prompt
    assert "should not be interpreted as confirmation" in prompt


def test_nuclei_ai_prompt_partial_timeout_with_findings_is_not_clean_scan() -> None:
    prompt = build_nuclei_ai_assessment_prompt(
        {
            "target": "https://example.com",
            "finding_count": 2,
            "risk_level": "info",
            "severity_summary": {"info": 2},
            "metadata": {
                "partial": True,
                "timed_out": True,
                "timeout_reason": "Execution time limit reached.",
                "elapsed": "180s",
            },
            "nuclei_findings": [
                {"template_id": "tech-detect", "severity": "info", "name": "Technology Detection", "host": "https://example.com"},
                {"template_id": "panel-detect", "severity": "info", "name": "Panel Detection", "host": "https://example.com"},
            ],
        }
    )

    assert "Scan completion: partial/incomplete" in prompt
    assert "Finding count: 2" in prompt
    assert "info: 2" in prompt
    assert "additional selected templates may not have executed" in prompt
    assert CLEAN_SCAN_FACT not in prompt


def test_nuclei_ai_partial_timeout_response_filters_clean_scan_contradiction() -> None:
    response = "\n".join(
        [
            "Executive Summary",
            "- No matching Nuclei findings were observed using the selected template/profile.",
            "Observed Facts",
            "- Two informational observations were collected.",
        ]
    )

    finding = {
        "target": "https://example.com",
        "finding_count": 2,
        "metadata": {"partial": True, "timed_out": True, "timeout_reason": "Execution time limit reached."},
        "nuclei_findings": [
            {"template_id": "tech-detect", "severity": "info", "name": "Technology Detection", "host": "https://example.com"},
            {"template_id": "panel-detect", "severity": "info", "name": "Panel Detection", "host": "https://example.com"},
        ],
    }

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        lines = generate_nuclei_ai_assessment(finding)

    text = "\n".join(lines)
    assert "configured execution time limit" in text
    assert "2 observations were collected before termination" in text
    assert "additional findings should not be interpreted" in text
    assert "No matching Nuclei findings were observed" not in text


def test_nuclei_ai_assessment_success_returns_response_lines() -> None:
    response = "Executive Summary\n- One matched finding was observed.\n\nConfidence\nMedium"

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        assert generate_nuclei_ai_assessment({"target": "https://example.com"}) == response.splitlines()


def test_nuclei_ai_assessment_failure_returns_fallback() -> None:
    with patch("app.services.nuclei_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_nuclei_ai_assessment({"target": "https://example.com"}) == FALLBACK_LINES


def test_nuclei_ai_assessment_renderer_uses_polished_title() -> None:
    card = render_ai_summary_card(
        ["Executive Summary:", "- Evidence reviewed.", "", "Confidence:", "Low"],
        title="Nuclei AI Assessment",
    )

    assert "Nuclei AI Assessment" in card
    assert "Executive Summary:" not in card
    assert "Executive Summary\n- Evidence reviewed." in card


def test_nuclei_all_info_findings_remain_info_without_low_label() -> None:
    finding = {
        "target": "https://example.com",
        "finding_count": 2,
        "risk_level": "info",
        "severity_summary": {"info": 2},
        "nuclei_findings": [
            {"template_id": "tech-detect", "severity": "info", "name": "Technology Detection", "host": "https://example.com"},
            {"template_id": "graphql-detect", "severity": "info", "name": "GraphQL Endpoint Detection", "host": "https://example.com/graphql"},
        ],
    }

    prompt = build_nuclei_ai_assessment_prompt(finding)

    assert "info: 2" in prompt
    assert "low: 1" not in prompt
    assert "low and info" not in prompt.lower()


def test_nuclei_info_only_low_and_info_ai_claim_is_withheld() -> None:
    response = "Executive Summary\n- The scan found low and informational vulnerabilities."
    finding = {
        "target": "https://example.com",
        "finding_count": 1,
        "severity_summary": {"info": 1},
        "nuclei_findings": [{"template_id": "tech-detect", "severity": "info", "host": "https://example.com"}],
    }

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        lines = generate_nuclei_ai_assessment(finding)

    assert lines == TRUTHFULNESS_FALLBACK_LINES


def test_nuclei_empty_clean_scan_does_not_allow_security_conclusion() -> None:
    response = "Executive Summary\n- The target is secure because Nuclei found no vulnerabilities."

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        lines = generate_nuclei_ai_assessment({"target": "https://example.com", "finding_count": 0, "nuclei_findings": []})

    text = "\n".join(lines)
    assert "unsupported security conclusion" in text
    assert "target is secure" not in text.lower()


def test_nuclei_graphql_detection_without_exploitability_claim() -> None:
    finding = {
        "target": "https://example.com/graphql",
        "finding_count": 1,
        "nuclei_findings": [
            {
                "template_id": "graphql-detect",
                "severity": "info",
                "name": "GraphQL Endpoint Detection",
                "host": "https://example.com/graphql",
                "tags": ["graphql"],
            }
        ],
    }
    response = "Observed Findings\n- Nuclei reported a GraphQL endpoint through template-based detection.\nLimitations\n- This result alone does not establish exploitability."

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        assert generate_nuclei_ai_assessment(finding) == response.splitlines()


def test_nuclei_alias_batching_confirmed_vulnerability_claim_is_withheld() -> None:
    response = "Executive Summary\n- GraphQL alias batching is a confirmed vulnerability that can be exploited."
    finding = {
        "target": "https://example.com/graphql",
        "finding_count": 1,
        "nuclei_findings": [{"template_id": "graphql-alias-batching", "severity": "info", "name": "GraphQL Alias Batching", "host": "https://example.com/graphql"}],
    }

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        lines = generate_nuclei_ai_assessment(finding)

    assert lines == TRUTHFULNESS_FALLBACK_LINES


def test_nuclei_security_header_claims_remain_contextual() -> None:
    response = "Observed Findings\n- A missing security header was reported as a configuration observation.\nLimitations\n- This result alone does not establish a vulnerability."
    finding = {
        "target": "https://example.com",
        "finding_count": 1,
        "nuclei_findings": [{"template_id": "missing-security-headers", "severity": "info", "name": "Missing Security Headers", "host": "https://example.com"}],
    }

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        assert generate_nuclei_ai_assessment(finding) == response.splitlines()


def test_nuclei_deprecated_x_xss_protection_does_not_become_xss_evidence() -> None:
    response = "Executive Summary\n- The deprecated X-XSS-Protection header directly enables XSS."
    finding = {
        "target": "https://example.com",
        "finding_count": 1,
        "nuclei_findings": [{"template_id": "deprecated-x-xss-protection", "severity": "info", "name": "Deprecated X-XSS-Protection Header", "host": "https://example.com"}],
    }

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        lines = generate_nuclei_ai_assessment(finding)

    assert lines == TRUTHFULNESS_FALLBACK_LINES


def test_nuclei_no_invented_scan_profile_without_metadata() -> None:
    response = "Executive Summary\n- The fast profile found one informational result."
    finding = {
        "target": "https://example.com",
        "finding_count": 1,
        "nuclei_findings": [{"template_id": "tech-detect", "severity": "info", "host": "https://example.com"}],
    }

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        lines = generate_nuclei_ai_assessment(finding)

    assert lines == TRUTHFULNESS_FALLBACK_LINES


def test_nuclei_compromise_conclusion_is_withheld() -> None:
    response = "Executive Summary\n- These findings are not indicative of a compromised system."

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        lines = generate_nuclei_ai_assessment({"target": "https://example.com", "finding_count": 1, "nuclei_findings": [{"template_id": "one", "severity": "info"}]})

    assert lines == TRUTHFULNESS_FALLBACK_LINES


def test_nuclei_legitimate_limitation_wording_is_allowed() -> None:
    response = "Limitations\n- The available evidence is insufficient to determine whether vulnerabilities exist."

    with patch("app.services.nuclei_ai_assessment.ask_ai", return_value=response):
        assert generate_nuclei_ai_assessment({"target": "https://example.com"}) == response.splitlines()
