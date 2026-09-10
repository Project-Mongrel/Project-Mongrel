import json
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.services.assessment_conversation_ai import (
    FALLBACK_ANSWER,
    NATIVE_GUIDANCE_FALLBACK_ANSWER,
    TRUTHFULNESS_FALLBACK_ANSWER,
    answer_assessment_conversation_question,
    build_assessment_conversation_prompt,
    violates_conversation_truthfulness,
    violates_mongrel_native_guidance,
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
    response = "Use Mongrel's httpx next because Nmap observed an HTTP service but has not established which endpoints respond."

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should I run next?",
        )

    assert "because" in result["answer"].lower()


def test_natural_what_is_next_recovers_grounded_advice_from_unsafe_model_output() -> None:
    assessment = create_assessment("Natural Recommendation", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=8080, service="http-proxy")

    with patch(
        "app.services.assessment_conversation_ai.ask_ai",
        return_value="The service is vulnerable, so run httpx next.",
    ):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What is next",
        )

    assert result["fallback_reason"] == "grounded_conversation_fallback"
    assert "httpx next" in result["answer"]
    assert "not evidence of a vulnerability" in result["answer"]
    assert "withheld" not in result["answer"].lower()


@pytest.mark.parametrize(
    "question",
    [
        "is that a vulnerability?",
        "is that a vulnerabilty?",
        "is that a vunerability?",
        "is that a vuln?",
        "does that mean its vulnerable?",
        "can that be exploited?",
        "can that be exploitible?",
        "are we safe?",
        "are we secure?",
    ],
)
def test_casual_uncertainty_questions_recover_bounded_answer(question: str) -> None:
    assessment = create_assessment("Casual uncertainty", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=8080, service="http-proxy")

    with patch(
        "app.services.assessment_conversation_ai.ask_ai",
        return_value="Yes, that is a vulnerability and the target is exploitable.",
    ):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question=question,
        )

    assert result["fallback_reason"] == "grounded_conversation_fallback"
    assert "not enough to conclude" in result["answer"]
    assert "secure or vulnerable overall" in result["answer"]
    assert "withheld" not in result["answer"].lower()


@pytest.mark.parametrize("question", ["Why?", "Which one?", "What will that tell me?", "What did you mean by that?", "And 8080?"])
def test_short_followups_receive_bounded_persisted_history(question: str) -> None:
    assessment = create_assessment("Natural Follow-up", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=8080, service="http-proxy")
    conversation = create_conversation(assessment["id"], user_id=1001)
    append_message(conversation["id"], user_id=1001, role="user", content="What next?")
    append_message(
        conversation["id"],
        user_id=1001,
        role="assistant",
        content="I would investigate the web-associated surface with httpx next.",
    )
    response = "It would record observed HTTP response metadata; that would not prove a vulnerability."

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=conversation["id"],
            question=question,
        )

    prompt = ask_ai.call_args.args[0]
    assert "I would investigate the web-associated surface with httpx next." in prompt
    assert question in prompt
    assert result["answer"] == response
    assert len(result["evidence_refs"]["history_message_ids"]) == 2


def test_domain_recommendation_does_not_blindly_add_repository_or_cloud_tools() -> None:
    assessment = create_assessment("Domain Compatibility", user_id=1001)
    add_assessment_target(assessment["id"], "example.com")
    _add_nmap_scan(assessment["id"], user_id=1001, port=443, service="https")
    response = "Use Mongrel's httpx next because it can characterize observed HTTP responses without claiming a weakness."

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should we investigate next?",
        )

    assert result["answer"] == response
    assert "gitleaks" not in result["answer"].lower()
    assert "prowler" not in result["answer"].lower()


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


def test_live_nmap_service_labels_do_not_prove_cleartext_or_tls_behavior() -> None:
    assessment = create_assessment("Hello Sunday Kids", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)

    unsupported_answers = (
        "Port 80 proves sensitive data is exposed in cleartext and interceptable.",
        "HTTPS on 443 establishes successful encrypted communication and a completed TLS handshake.",
        "HTTP on port 80 proves a man-in-the-middle attack is exploitable.",
    )
    for response in unsupported_answers:
        with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response):
            result = answer_assessment_conversation_question(
                user_id=1001,
                assessment_id=assessment["id"],
                conversation_id=None,
                question="What does the Nmap web-service evidence prove?",
            )

        assert result["answer"] == TRUTHFULNESS_FALLBACK_ANSWER
        assert result["fallback_reason"] == "truthfulness_guard"


def test_prompt_states_precise_nmap_http_and_https_evidence_semantics() -> None:
    assessment = create_assessment("Service Semantics", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What have we learned from these web ports?",
    )
    prompt = build_assessment_conversation_prompt(context)

    assert "does not prove sensitive data is sent in cleartext" in prompt
    assert "do not prove a successful TLS handshake" in prompt
    assert "Do not invent remediation such as CSP, CDN use, or IP allowlisting" in prompt


def test_guard_allows_explicit_service_label_uncertainty() -> None:
    assert violates_conversation_truthfulness(
        "Port 80 does not prove sensitive data is exposed in cleartext or establish MITM risk."
    ) is False
    assert violates_conversation_truthfulness(
        "HTTPS on 443 and 8443 does not prove a successful TLS handshake or completed encrypted communication."
    ) is False
    assert violates_conversation_truthfulness("HTTP exposure is not by itself a security weakness.") is False


def test_generic_remediation_detached_from_evidence_is_withheld() -> None:
    assessment = create_assessment("No Invented Remediation", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)

    with patch(
        "app.services.assessment_conversation_ai.ask_ai",
        return_value="Deploy a CDN, add CSP, and use an IP allowlist to fix the exposed HTTP service.",
    ):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What remediation is required?",
        )

    assert result["answer"] == TRUTHFULNESS_FALLBACK_ANSWER


def test_capability_catalog_contains_locked_competition_toolset() -> None:
    assessment = create_assessment("Capabilities", user_id=1001)
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What can Mongrel do?",
    )

    assert list(context["mongrel_capabilities"]) == [
        "nmap", "bbot", "nuclei", "httpx", "playwright", "katana", "ffuf", "testssl.sh",
        "gitleaks", "prowler", "metasploit", "tshark",
    ]
    assert "uploaded PCAPs" in context["mongrel_capabilities"]["tshark"]
    assert "reachable web responses" in context["mongrel_capabilities"]["httpx"]


def test_web_service_next_step_prefers_httpx_after_nmap_with_rationale() -> None:
    assessment = create_assessment("Web Next Step", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)
    response = (
        "Observed Facts\nNmap classified exposed web-associated services on ports 80, 443, 8080 and 8443.\n"
        "Uncertainty\nThose labels do not establish which HTTP endpoints respond or how they behave.\n"
        "Recommended Next Step\nUse Mongrel's httpx because it fills that gap by probing and characterizing the HTTP(S) endpoints."
    )

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Which Mongrel tool should investigate these web services next?",
        )

    prompt = ask_ai.call_args.args[0]
    assert '"suggested_action": "httpx"' in prompt
    assert "do not simply repeat Nmap" in prompt
    assert "httpx" in result["answer"].lower()
    assert "because" in result["answer"].lower()
    assert "run nmap" not in result["answer"].lower()


def test_traffic_analysis_prefers_tshark_and_explains_modes() -> None:
    assessment = create_assessment("Traffic Next Step", user_id=1001)
    response = (
        "Use Mongrel's TShark because it can analyze an uploaded PCAP, perform a standalone live capture, or capture during "
        "an explicitly approved validation. No packet evidence has been collected yet."
    )

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Can Mongrel inspect the network traffic?",
        )

    assert '"TShark"' in ask_ai.call_args.args[0]
    assert "Analyze PCAP" in ask_ai.call_args.args[0]
    assert "tshark" in result["answer"].lower()
    assert "mitmproxy" not in result["answer"].lower()
    assert "tcpdump" not in result["answer"].lower()


def test_external_traffic_tool_without_tshark_is_withheld_when_tshark_fits() -> None:
    assessment = create_assessment("Internal Traffic Capability", user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Use mitmproxy to inspect the traffic."):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Can Mongrel inspect traffic?",
        )

    assert result["answer"] == TRUTHFULNESS_FALLBACK_ANSWER


def test_novice_guidance_is_plain_mongrel_specific_and_gap_driven() -> None:
    assessment = create_assessment("Novice Web Guidance", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)
    response = (
        "Observed Facts\nIn plain English, the host answered and Nmap saw four web-associated open ports.\n"
        "What this does not prove\nWe do not yet know whether the sites respond, encrypt successfully, or contain a vulnerability.\n"
        "Recommended Next Step\nUse Mongrel's httpx because it checks which web endpoints respond and records basic web details."
    )

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="I'm a complete novice. What have we learned and what should I do next?",
        )

    assert '"suggested_action": "httpx"' in ask_ai.call_args.args[0]
    assert "httpx" in result["answer"].lower()
    assert "because" in result["answer"].lower()
    assert "generic security" not in result["answer"].lower()


def test_live_quality_changes_do_not_execute_any_tool() -> None:
    assessment = create_assessment("Advice Only", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)
    response = "Use httpx because it fills the current web-response evidence gap."

    with (
        patch("app.services.assessment_conversation_ai.ask_ai", return_value=response),
        patch("app.tools.httpx_runner.run_httpx_scan") as httpx_runner,
        patch("app.tools.tshark_runner.run_tshark_offline_analysis") as tshark_runner,
    ):
        answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should I do next for the web services?",
        )

    httpx_runner.assert_not_called()
    tshark_runner.assert_not_called()


def test_httpx_guidance_uses_verified_mongrel_workflow_not_install_or_cli() -> None:
    assessment = create_assessment("Native httpx", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)
    response = (
        "Return to the assessment dashboard and choose Run httpx. This is the next step because Nmap identified "
        "web-associated services but has not established which HTTP endpoints respond."
    )

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=response) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="How do I investigate these web services?",
        )

    prompt = ask_ai.call_args.args[0]
    assert '"assessment_action": "Run httpx"' in prompt
    assert "Never tell the user to install Mongrel's tools" in prompt
    assert result["answer"] == response
    assert "install" not in result["answer"].lower()
    assert "httpx -" not in result["answer"].lower()


@pytest.mark.parametrize(
    "bad_guidance",
    [
        "Install httpx with apt install httpx, then run it yourself.",
        "Run this command:\n```bash\nhttpx -u https://example.com\n```",
    ],
)
def test_internal_httpx_install_and_raw_cli_guidance_is_withheld(bad_guidance: str) -> None:
    assessment = create_assessment("No raw httpx", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=bad_guidance):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="How should I inspect these web services?",
        )

    assert result["answer"] == NATIVE_GUIDANCE_FALLBACK_ANSWER
    assert result["fallback_reason"] == "native_guidance_guard"


def test_tshark_guidance_uses_only_verified_assessment_labels() -> None:
    assessment = create_assessment("Native TShark", user_id=1001)
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="How can Mongrel inspect traffic?",
    )
    guidance = context["telegram_capability_guidance"]["tshark"]

    assert guidance["assessment_action"] == "Run TShark"
    assert guidance["choices"] == ["Capture During Validation", "Analyze PCAP", "Standalone Live Capture"]
    assert "Install" not in guidance["guidance"]


def test_unrelated_unrun_tool_is_not_added_to_preferred_recommendation() -> None:
    assessment = create_assessment("Scoped Recommendation", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What should a novice do next for these web services?",
    )

    assert context["recommendation_context"]["preferred_next_tools"] == ["httpx"]
    assert "nuclei" not in context["recommendation_context"]["preferred_next_tools"]
    assert "katana" not in context["recommendation_context"]["preferred_next_tools"]
    assert violates_mongrel_native_guidance("Use httpx because it fills the web response gap.", context) is False
    assert violates_mongrel_native_guidance("Use httpx, then run Nuclei as another unrun tool.", context) is True


def test_novice_prompt_requires_one_clear_evidence_driven_action() -> None:
    assessment = create_assessment("One novice action", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="I'm a novice. What should I do next?",
    )
    prompt = build_assessment_conversation_prompt(context)

    assert "recommend exactly one clear next action" in prompt
    assert context["recommendation_context"]["preferred_next_tools"] == ["httpx"]


def test_native_guidance_remains_advice_only_and_executes_nothing() -> None:
    assessment = create_assessment("Native advice only", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)
    response = "Choose Run httpx in the assessment because it fills the web-response evidence gap."

    with (
        patch("app.services.assessment_conversation_ai.ask_ai", return_value=response),
        patch("app.tools.httpx_runner.run_httpx_scan") as runner,
    ):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should I do next for these web services?",
        )

    assert result["answer"] == response
    runner.assert_not_called()


def test_hostname_and_resolved_ip_are_not_counted_as_independent_hosts() -> None:
    assessment = create_assessment("Endpoint identity", user_id=1001)
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "nmap",
            "target": "hellosundaykids.com",
            "resolved_ip": "203.0.113.10",
            "host_status": "up",
            "open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
        },
    )
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id=finding["id"])
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="How many hosts did Nmap find?",
    )
    prompt = build_assessment_conversation_prompt(context)

    assert "two identifiers for the same scanned endpoint" in prompt
    assert "Never inflate the host count from DNS resolution alone" in prompt
    assert violates_conversation_truthfulness(
        "Nmap independently discovered two hosts: hostname hellosundaykids.com and resolved IP 203.0.113.10.", context
    ) is True
    assert violates_conversation_truthfulness(
        "The hostname and resolved IP are two identifiers for the same scanned endpoint, not two independently discovered hosts.", context
    ) is False


def test_httpx_language_is_endpoint_characterization_not_vulnerability_proof() -> None:
    assessment = create_assessment("httpx semantics", user_id=1001)
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What would httpx establish?",
    )

    assert "Probe and characterize HTTP/HTTPS endpoints" in context["mongrel_capabilities"]["httpx"]
    assert "does not itself establish vulnerability or misconfiguration" in context["mongrel_capabilities"]["httpx"]
    assert violates_conversation_truthfulness("httpx proves the endpoint is vulnerable and misconfigured.", context) is True
    assert violates_conversation_truthfulness(
        "httpx characterizes the observed response; it does not prove the endpoint is vulnerable or misconfigured.", context
    ) is False


def test_tshark_language_does_not_promise_security_or_compromise_conclusions() -> None:
    assessment = create_assessment("TShark semantics", user_id=1001)
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What can TShark tell us if we capture traffic?",
    )

    capability = context["mongrel_capabilities"]["tshark"]
    assert "packet/capture metadata" in capability
    assert "does not establish encryption security, exploitability, compromise, or application security" in capability
    assert violates_conversation_truthfulness("TShark will prove encryption security and determine exploitability.", context) is True
    assert violates_conversation_truthfulness(
        "TShark can report observed packet metadata, but it cannot prove encryption security or compromise.", context
    ) is False


def test_tshark_answer_is_bounded_to_normalized_packet_observations() -> None:
    assessment = create_assessment("Observed packets only", user_id=1001)
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "tshark",
            "target": "capture.pcap",
            "tshark_evidence": {
                "packet_count": 3,
                "observed_protocols": [{"protocol": "tcp", "packet_count": 3}],
                "evidence_limitations": ["No application payload conclusion was established."],
            },
        },
    )
    record_assessment_scan(assessment["id"], tool="tshark", status="completed", finding_id=finding["id"])

    with patch(
        "app.services.assessment_conversation_ai.ask_ai",
        return_value="Observed Facts\nTShark recorded 3 TCP packet metadata observations. No application-security conclusion is established.",
    ) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What packet evidence was actually observed?",
        )

    assert '"packet_count": 3' in ask_ai.call_args.args[0]
    assert "3 TCP packet metadata observations" in result["answer"]


def test_user_facing_cloud_tool_name_is_only_prowler() -> None:
    assessment = create_assessment("Cloud naming", user_id=1001)
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What cloud tool does Mongrel provide?",
    )
    prompt = build_assessment_conversation_prompt(context)

    assert "The user-facing cloud tool is Prowler" in prompt
    assert "ScoutSuite/Prowler" not in prompt
    assert violates_conversation_truthfulness("Use ScoutSuite/Prowler for cloud checks.", context) is True
    assert violates_conversation_truthfulness("Use Prowler for the relevant supported cloud checks.", context) is False


def test_assessment_answer_returns_safe_latency_stages_and_sizes() -> None:
    assessment = create_assessment("Timing metadata", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)
    append_message(conversation["id"], user_id=1001, role="user", content="Earlier private conversation text")
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Observed Facts\nNmap observed web-associated services."):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=conversation["id"],
            question="Private question text",
        )

    instrumentation = result["instrumentation"]
    assert set(instrumentation) == {
        "context_ms", "prompt_ms", "ai_ms", "postprocess_ms", "engine_ms",
        "prompt_chars", "context_chars", "history_message_count",
        "evidence_scan_count", "evidence_finding_count", "evidence_artifact_count",
        "output_token_budget",
    }
    assert all(instrumentation[key] >= 0 for key in ("context_ms", "prompt_ms", "ai_ms", "postprocess_ms", "engine_ms"))
    assert instrumentation["prompt_chars"] > instrumentation["context_chars"] > 0
    assert instrumentation["history_message_count"] == 1
    assert instrumentation["evidence_scan_count"] == 1
    assert instrumentation["evidence_finding_count"] == 1
    assert instrumentation["evidence_artifact_count"] == 0
    assert instrumentation["output_token_budget"] >= 256


def test_prompt_compaction_preserves_evidence_rules_tools_and_native_guidance() -> None:
    assessment = create_assessment("Compact prompt", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What should I do next for these web services?",
    )

    prompt = build_assessment_conversation_prompt(context)
    encoded_context = prompt.split("Private reference data (use its facts; never quote its labels or format):\n", 1)[1].rsplit("\n\nAnswer:", 1)[0]
    model_context = json.loads(encoded_context)

    assert "does not prove sensitive data is sent in cleartext" in prompt
    assert "do not prove a successful TLS handshake" in prompt
    assert model_context["suggested_action"] == "httpx"
    assert model_context["user_actions"]["httpx"]["assessment_action"] == "Run httpx"
    assert model_context["stored_evidence"]["scans"]
    assert model_context["stored_evidence"]["findings"]
    assert "provenance" not in model_context
    assert "evidence_context_digest" not in model_context
    assert "budget" not in model_context["stored_evidence"]
    assert "prompt_section" not in model_context
    assert "tool_boundaries" not in model_context
    assert len(encoded_context) < len(json.dumps(context, default=str, sort_keys=True, indent=2))


def test_default_assessment_ask_budget_is_isolated_and_conservative() -> None:
    assessment = create_assessment("Ask-only budget", user_id=1001)
    settings = Settings(ai_enabled=True)

    with (
        patch("app.services.assessment_conversation_ai.get_settings", return_value=settings),
        patch("app.services.assessment_conversation_ai.ask_ai", return_value="Observed Facts\nNo evidence yet.") as ask_ai,
    ):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Summarize.",
        )

    assert settings.ask_mongrel_num_predict == 384
    assert ask_ai.call_args.kwargs["num_predict"] == 384
    assert result["instrumentation"]["output_token_budget"] == 384


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


def _add_live_web_nmap_scan(assessment_id: int, *, user_id: int) -> dict:
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "nmap",
            "target": "hellosundaykids.com",
            "status": "completed",
            "summary": "Host reachable; web-associated services observed.",
            "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http"},
                {"port": 443, "protocol": "tcp", "service": "https"},
                {"port": 8080, "protocol": "tcp", "service": "http-proxy"},
                {"port": 8443, "protocol": "tcp", "service": "https-alt"},
            ],
        },
    )
    return record_assessment_scan(assessment_id, tool="nmap", status="completed", finding_id=finding["id"])
