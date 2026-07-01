from unittest.mock import patch

from app.services.assessment_ai import (
    FALLBACK_ANSWER,
    FALLBACK_REPORT,
    answer_assessment_question,
    build_assessment_ai_prompt,
    build_assessment_ai_report_prompt,
    generate_assessment_ai_report,
)


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
    assert "scanme.nmap.org" in prompt
    assert "22/tcp ssh" in prompt
    assert "Authorized test." in prompt
    assert "What ports are open?" in prompt


def test_assessment_ai_success_returns_ai_answer() -> None:
    with patch("app.services.assessment_ai.ask_ai", return_value="SSH is the main observed service."):
        assert answer_assessment_question("What's the biggest concern?", {"assessment": {"name": "A"}}) == "SSH is the main observed service."


def test_assessment_ai_unavailable_returns_fallback() -> None:
    with patch("app.services.assessment_ai.ask_ai", return_value="AI integration is not configured yet."):
        assert answer_assessment_question("Summarise this assessment.", {"assessment": {"name": "A"}}) == FALLBACK_ANSWER


def test_assessment_ai_report_prompt_includes_required_sections_and_limitations() -> None:
    context = {
        "assessment": {"name": "Report Assessment", "status": "active"},
        "targets": [{"address": "example.com"}],
        "scans": [{"tool": "nmap", "status": "completed"}, {"tool": "nuclei", "status": "failed"}],
        "findings": [{"source": "nmap", "target": "example.com", "summary": "SSH observed."}],
        "artifacts": [],
        "notes": [],
    }

    prompt = build_assessment_ai_report_prompt(context)

    assert "Evidence-only." in prompt
    assert "Never invent vulnerabilities." in prompt
    assert 'Never state a target is "safe".' in prompt
    assert "explain what has not yet been assessed" in prompt
    assert "✦ Assessment AI Report" in prompt
    assert "Completed Activities" in prompt
    assert "Evidence Limitations" in prompt
    assert "tool=nmap status=completed" in prompt
    assert "tool=nuclei status=failed" in prompt
    assert "SSH observed." in prompt


def test_generate_assessment_ai_report_success_returns_report() -> None:
    response = "✦ Assessment AI Report\n\nExecutive Summary\nEvidence reviewed."

    with patch("app.services.assessment_ai.ask_ai", return_value=response):
        assert generate_assessment_ai_report({"assessment": {"name": "A"}}) == response


def test_generate_assessment_ai_report_unavailable_returns_fallback() -> None:
    with patch("app.services.assessment_ai.ask_ai", return_value="AI request timed out."):
        assert generate_assessment_ai_report({"assessment": {"name": "A"}}) == FALLBACK_REPORT
