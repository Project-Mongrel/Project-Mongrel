import json
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.services.assessment_conversation_ai import (
    FALLBACK_ANSWER,
    TRUTHFULNESS_FALLBACK_ANSWER,
    answer_assessment_conversation_question,
    build_assessment_conversation_prompt,
    violates_conversation_truthfulness,
)
from app.services.assessment_conversation_context import build_assessment_conversation_context
from app.services.assessment_conversation_store import append_message, create_conversation
from app.services.assessment_store import add_assessment_artifact, add_assessment_target, create_assessment, record_assessment_scan
from app.services.findings_store import add_finding, close_findings_database, configure_findings_database


@pytest.fixture(autouse=True)
def sqlite_assessment_conversation_ai(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_beginner_open_port_question_recommends_and_explains_nmap() -> None:
    assessment = create_assessment("Beginner Assessment", user_id=1001)
    add_assessment_target(assessment["id"], "example.com")
    response = (
        "Observed Facts\nNo Nmap scan is stored yet.\n"
        "Recommended Next Step\nUse Nmap because it is the tool in this assessment for observing reachable TCP ports."
    )

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What tool should I use if I want to see open ports?",
        )

    prompt = ask_ai.call_args.args[0]
    assert "Adapt depth to the user: plain English for beginner questions" in prompt
    assert "You may recommend tools, but every recommendation must explain why" in prompt
    assert "What tool should I use if I want to see open ports?" in prompt
    assert result["answer"] == response
    assert "because" in result["answer"].lower()


def test_novice_next_step_uses_current_evidence() -> None:
    assessment = create_assessment("Novice Next Step", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=22, service="ssh")
    response = (
        "Observed Facts\nNmap observed TCP port 22 identified as SSH.\n"
        "Recommended Next Step\nReview SSH exposure because it is the reachable service in the stored evidence."
    )

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Yo my man, I don't know what I'm doing. What should I do next?",
        )

    assert "port': 22" not in ask_ai.call_args.args[0]
    assert '"port": 22' in ask_ai.call_args.args[0]
    assert "Review SSH exposure" in result["answer"]


def test_advanced_multi_tool_comparison_prompt_includes_selected_evidence() -> None:
    assessment = create_assessment("Advanced Compare", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=443, service="https")
    nuclei = add_finding(
        user_id=1001,
        finding={
            "source": "nuclei",
            "target": "https://example.com",
            "status": "completed",
            "nuclei_findings": [{"template_id": "tech-detect", "severity": "info"}],
        },
    )
    tshark = add_finding(
        user_id=1001,
        finding={
            "source": "tshark",
            "target": "capture.pcap",
            "status": "completed",
            "tshark_evidence": {"packet_count": 4, "observed_protocols": [{"protocol": "tls", "packet_count": 2}]},
        },
    )
    bbot = add_finding(user_id=1001, finding={"source": "bbot", "target": "example.com", "status": "completed"})
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=nuclei["id"])
    record_assessment_scan(assessment["id"], tool="tshark", status="completed", finding_id=tshark["id"])
    record_assessment_scan(assessment["id"], tool="bbot", status="completed", finding_id=bbot["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Observed Facts\nEvidence compared."):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Compare the Nmap, Nuclei and TShark evidence and identify unresolved hypotheses.",
        )

    assert result["evidence_refs"]["selected_tools"] == ["nmap", "nuclei", "tshark"]
    assert result["evidence_refs"]["selection_mode"] == "tool_relevant"
    assert len(result["evidence_refs"]["finding_ids"]) == 3


def test_insufficient_evidence_produces_uncertainty_not_invention() -> None:
    assessment = create_assessment("Empty Assessment", user_id=1001)
    response = "Observed Facts\nNo scans are stored.\nUncertainty\nThere is insufficient evidence to assess exposed services."

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Is anything vulnerable?",
        )

    assert '"scans": []' in ask_ai.call_args.args[0]
    assert "insufficient evidence" in result["answer"].lower()
    assert "vulnerable" not in result["answer"].lower()


def test_stale_assistant_claim_loses_to_newer_evidence() -> None:
    assessment = create_assessment("Stale Answer", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)
    append_message(conversation["id"], user_id=1001, role="assistant", content="Earlier I said no open ports were observed.")
    _add_nmap_scan(assessment["id"], user_id=1001, port=443, service="https")
    response = "Observed Facts\nNewer stored Nmap evidence reports TCP port 443. The older assistant message is superseded."

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=conversation["id"],
            question="Was the old answer still right?",
        )

    prompt = ask_ai.call_args.args[0]
    assert "Conversation history is interpretation only" in prompt
    assert "newer evidence wins" in prompt.lower()
    assert "Earlier I said no open ports were observed." in prompt
    assert '"port": 443' in prompt
    assert "superseded" in result["answer"]


def test_recommendation_includes_rationale() -> None:
    assessment = create_assessment("Recommendation", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=80, service="http")
    response = "Recommended Next Step\nRun Nuclei because Nmap observed an HTTP service that may warrant template-based checks."

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should I run next?",
        )

    assert "because" in result["answer"].lower()


def test_conversation_engine_does_not_execute_tools() -> None:
    assessment = create_assessment("No Execute", user_id=1001)

    with (
        patch("app.services.assessment_conversation_ai.ask_ai", return_value="Recommended Next Step\nRun Nmap because it observes open ports."),
        patch("app.tools.nmap_runner.run_nmap_scan") as run_nmap,
    ):
        answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Run Nmap now.",
        )

    run_nmap.assert_not_called()


def test_metasploit_and_tshark_semantics_remain_correct() -> None:
    assessment = create_assessment("Correlation Semantics", user_id=1001)
    metasploit = add_finding(
        user_id=1001,
        finding={
            "source": "metasploit",
            "target": "example.com",
            "status": "completed",
            "metasploit_evidence": {
                "subprocess_success": True,
                "module_executed": True,
                "session_established": False,
                "validation_state": "NO_SESSION",
            },
        },
    )
    record_assessment_scan(assessment["id"], tool="metasploit", status="completed", finding_id=metasploit["id"])
    add_assessment_artifact(
        assessment["id"],
        artifact_type="tshark_metasploit_correlation",
        title="Correlation",
        content=json.dumps(
            {
                "correlation_confidence": "high",
                "correlation_confidence_meaning": "attribution confidence only; not exploitability confidence",
            }
        ),
    )

    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What do Metasploit and TShark prove together?",
    )
    prompt = build_assessment_conversation_prompt(context)

    assert '"session_established": false' in prompt
    assert "TShark correlation confidence means attribution confidence only" in prompt
    assert "Metasploit subprocess success, module execution, validation state" in prompt


def test_prowler_pass_does_not_become_account_security() -> None:
    assessment = create_assessment("Prowler PASS", user_id=1001)
    prowler = add_finding(
        user_id=1001,
        finding={
            "source": "prowler",
            "target": "aws",
            "status": "completed",
            "prowler_evidence": {
                "findings": [{"check_id": "iam_check", "status": "PASS", "status_interpretation": "scanner_reported_passed_check"}]
            },
        },
    )
    record_assessment_scan(assessment["id"], tool="prowler", status="completed", finding_id=prowler["id"])

    context = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="Is AWS secure?")
    prompt = build_assessment_conversation_prompt(context)

    assert '"status": "PASS"' in prompt
    assert "Prowler PASS/FAIL applies to the specific scanner check only" in prompt
    assert "account/resource security" in prompt


def test_gitleaks_raw_secrets_never_enter_prompt_or_output_context() -> None:
    assessment = create_assessment("Secret Safety", user_id=1001)
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "gitleaks",
            "target": "repo",
            "status": "completed",
            "raw_output": "ghp_raw_secret_value",
            "gitleaks_evidence": {
                "findings": [
                    {
                        "rule_id": "github-pat",
                        "raw_secret": "ghp_raw_secret_value",
                        "redacted_secret_preview": "<REDACTED> len=36",
                    }
                ]
            },
        },
    )
    record_assessment_scan(assessment["id"], tool="gitleaks", status="completed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Observed Facts\nGitleaks reported a redacted potential secret match.") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Review Gitleaks.",
        )

    assert "ghp_raw_secret_value" not in ask_ai.call_args.args[0]
    assert "ghp_raw_secret_value" not in str(result)
    assert "<REDACTED> len=36" in ask_ai.call_args.args[0]


def test_context_digest_and_evidence_refs_are_returned() -> None:
    assessment = create_assessment("Refs", user_id=1001)
    scan = _add_nmap_scan(assessment["id"], user_id=1001, port=22, service="ssh")

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Observed Facts\nNmap observed SSH."):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Summarize.",
        )

    assert result["evidence_context_digest"].startswith("sha256:")
    assert result["evidence_refs"]["scan_ids"] == [scan["id"]]
    assert result["evidence_refs"]["selection_mode"] == "full_assessment"


def test_ai_failure_produces_safe_fallback() -> None:
    assessment = create_assessment("Fallback", user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai", side_effect=RuntimeError("boom")):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Summarize.",
        )

    assert result["answer"] == FALLBACK_ANSWER
    assert result["fallback_reason"] == "exception"


def test_unavailable_ai_response_produces_safe_fallback() -> None:
    assessment = create_assessment("Unavailable", user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="AI request timed out."):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Summarize.",
        )

    assert result["answer"] == FALLBACK_ANSWER
    assert result["fallback_reason"] == "ai_unavailable"


def test_unsupported_broad_security_conclusion_is_withheld() -> None:
    assessment = create_assessment("Guarded", user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="The target is secure. No vulnerabilities were found."):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Is this secure?",
        )

    assert result["answer"] == TRUTHFULNESS_FALLBACK_ANSWER
    assert result["fallback_reason"] == "truthfulness_guard"


def test_guard_allows_evidence_scoped_negative_wording() -> None:
    assert violates_conversation_truthfulness("No open TCP ports were observed in this scan.") is False
    assert violates_conversation_truthfulness("Nmap did not report vulnerability evidence.") is False
    assert (
        violates_conversation_truthfulness("The available scan evidence is insufficient to determine whether vulnerabilities exist.")
        is False
    )


def test_guard_allows_session_statement_when_normalized_evidence_supports_it() -> None:
    context = {
        "assessment_context": {
            "findings": [{"source": "metasploit", "metasploit_evidence": {"session_established": True}}]
        }
    }

    assert violates_conversation_truthfulness("A session was established.", context) is False


def test_conversation_uses_configured_larger_response_budget() -> None:
    assessment = create_assessment("Budget", user_id=1001)
    settings = Settings(ai_enabled=True, ask_mongrel_num_predict=900)

    with (
        patch("app.services.assessment_conversation_ai.get_settings", return_value=settings),
        patch("app.services.assessment_conversation_ai.ask_ai", return_value="Observed Facts\nEvidence reviewed.") as ask_ai,
    ):
        answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Summarize.",
        )

    assert ask_ai.call_args.kwargs["num_predict"] == 900


def _add_nmap_scan(assessment_id: int, *, user_id: int, port: int, service: str) -> dict:
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "nmap",
            "target": "example.com",
            "status": "completed",
            "risk_level": "medium",
            "summary": f"Nmap observed {service}.",
            "open_ports": [{"port": port, "protocol": "tcp", "service": service}],
        },
    )
    return record_assessment_scan(assessment_id, tool="nmap", status="completed", finding_id=finding["id"])
