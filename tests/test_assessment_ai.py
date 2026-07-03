from unittest.mock import patch

from app.services.assessment_ai import (
    FALLBACK_ANSWER,
    FALLBACK_REPORT,
    answer_assessment_question,
    build_assessment_ai_prompt,
    build_assessment_ai_report_prompt,
    generate_assessment_ai_report,
)
from app.services.assessment_guard import SECURE_PREAMBLE


def test_assessment_ai_prompt_includes_evidence_and_constraints() -> None:
    context = {
        "assessment": {"name": "Acme Assessment", "status": "active"},
        "targets": [{"address": "scanme.nmap.org", "target_type": "hostname"}],
        "scans": [{"tool": "nmap", "status": "completed", "risk": "medium", "elapsed_seconds": 9, "finding_id": "finding-1"}],
        "findings": [
            {
                "source": "nmap",
                "target": "scanme.nmap.org",
                "risk_level": "medium",
                "summary": "SSH observed.",
                "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
            }
        ],
        "artifacts": [{"artifact_type": "summary", "title": "Nmap Summary", "content": "SSH observed."}],
        "notes": [{"note_type": "scope", "content": "Authorized test."}],
    }

    prompt = build_assessment_ai_prompt("What ports are open?", context)

    assert "You are Mongrel." in prompt
    assert "ONE authorised security assessment" in prompt
    assert "Answer ONLY using evidence supplied." in prompt
    assert "Never invent findings." in prompt
    assert "Never assume vulnerabilities." in prompt
    assert 'Never say the target is "safe" or "secure".' in prompt
    assert SECURE_PREAMBLE in prompt
    assert "Assessment Guardrails:" in prompt
    assert "scanme.nmap.org" in prompt
    assert "22/tcp ssh" in prompt
    assert "Authorized test." in prompt
    assert "What ports are open?" in prompt


def test_assessment_ai_success_returns_ai_answer() -> None:
    with patch("app.services.assessment_ai.ask_ai", return_value="SSH is the main observed service."):
        assert answer_assessment_question("What's the biggest concern?", {"assessment": {"name": "A"}}) == "SSH is the main observed service."


def test_assessment_ai_secure_question_prepends_cautious_finding() -> None:
    with patch("app.services.assessment_ai.ask_ai", return_value="No confirmed vulnerabilities were identified."):
        answer = answer_assessment_question("Is this secure?", {"assessment": {"name": "A"}})

    assert answer.startswith(SECURE_PREAMBLE)
    assert "No confirmed vulnerabilities were identified." in answer


def test_assessment_ai_unavailable_returns_fallback() -> None:
    with patch("app.services.assessment_ai.ask_ai", return_value="AI integration is not configured yet."):
        assert answer_assessment_question("Summarise this assessment.", {"assessment": {"name": "A"}}) == FALLBACK_ANSWER


def test_assessment_ai_secure_question_prompt_is_cautious_and_evidence_based() -> None:
    prompt = build_assessment_ai_prompt(
        "Is this secure?",
        {
            "assessment": {"name": "Secure Question Assessment", "status": "active"},
            "targets": [{"address": "example.com"}],
            "scans": [{"tool": "nmap", "status": "completed"}],
            "findings": [
                {
                    "source": "nmap",
                    "target": "example.com",
                    "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
                }
            ],
            "artifacts": [],
            "notes": [],
        },
    )

    assert SECURE_PREAMBLE in prompt
    assert "explain observed evidence, unassessed areas, whether confirmed vulnerabilities were found" in prompt
    assert 'Never say the target is "safe" or "secure".' in prompt
    assert "22/tcp ssh" in prompt


def test_assessment_ai_report_prompt_includes_required_sections_and_limitations() -> None:
    context = {
        "assessment": {"name": "Report Assessment", "status": "active"},
        "targets": [{"address": "example.com"}],
        "scans": [
            {"tool": "nmap", "status": "completed"},
            {"tool": "bbot", "status": "partial"},
            {"tool": "nuclei", "status": "failed"},
        ],
        "findings": [{"source": "nmap", "target": "example.com", "summary": "SSH observed."}],
        "artifacts": [],
        "notes": [],
    }

    prompt = build_assessment_ai_report_prompt(context)

    assert "Evidence-only." in prompt
    assert "Never invent vulnerabilities." in prompt
    assert 'Never state a target is "safe".' in prompt
    assert "Never imply a clean Nuclei scan means the target is secure." in prompt
    assert "Include completed and partial scans as represented evidence" in prompt
    assert "Assessment Guardrails:" in prompt
    assert "Completed tools: nmap" in prompt
    assert "Partial tools: bbot" in prompt
    assert "Failed tools: nuclei" in prompt
    assert "Core tools not run: httpx, katana, playwright, ffuf" in prompt
    assert "Gitleaks not run" in prompt
    assert "Absence of findings is not evidence of security." in prompt
    assert "explain what has not yet been assessed" in prompt
    assert "\u2726 Assessment AI Report" in prompt
    assert "Completed Activities" in prompt
    assert "Evidence Limitations" in prompt
    assert "tool=nmap status=completed" in prompt
    assert "tool=bbot status=partial" in prompt
    assert "tool=nuclei status=failed" in prompt
    assert "Represented tools:" in prompt
    assert "bbot, nmap" in prompt
    assert "Missing or not represented:" in prompt
    assert "nuclei, httpx, katana, playwright, ffuf" in prompt
    assert "SSH observed." in prompt


def test_generate_assessment_ai_report_success_returns_report() -> None:
    response = "✦ Assessment AI Report\n\nExecutive Summary\nEvidence reviewed."

    with patch("app.services.assessment_ai.ask_ai", return_value=response):
        assert generate_assessment_ai_report({"assessment": {"name": "A"}}) == response


def test_generate_assessment_ai_report_unavailable_returns_fallback() -> None:
    with patch("app.services.assessment_ai.ask_ai", return_value="AI request timed out."):
        assert generate_assessment_ai_report({"assessment": {"name": "A"}}) == FALLBACK_REPORT

