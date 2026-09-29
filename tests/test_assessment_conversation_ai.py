import json
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.services.assessment_conversation_ai import (
    ASSESSMENT_PROMPT_MAX_CHARS,
    FALLBACK_ANSWER,
    NATIVE_GUIDANCE_FALLBACK_ANSWER,
    TRUTHFULNESS_FALLBACK_ANSWER,
    answer_assessment_conversation_question,
    _apply_prompt_budget,
    _build_prompt_context,
    _testssl_authoritative_count,
    _recover_rejected_assessment_answer,
    build_assessment_conversation_prompt,
    violates_conversation_truthfulness,
    violates_mongrel_native_guidance,
)
from app.services.assessment_conversation_context import build_assessment_conversation_context, classify_assessment_conversation_intent
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

    ask_ai.assert_not_called()
    assert "Nmap has not been run" in result["answer"]
    assert "host reachability" in result["answer"]


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

    ask_ai.assert_not_called()
    assert "executes nothing" in result["answer"]


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

    ask_ai.assert_not_called()
    assert "does not establish" in result["answer"].lower()
    assert "confirmed vulnerability" in result["answer"].lower()


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

    assert result["fallback_reason"] is None
    assert "httpx next" in result["answer"]
    assert "not evidence of a vulnerability" in result["answer"]
    assert "withheld" not in result["answer"].lower()


def test_empty_website_summary_recommends_initial_recon_without_prowler() -> None:
    assessment = create_assessment("Mongrel final assessment test", user_id=1001)
    add_assessment_target(assessment["id"], "Btjoinery.ie")

    with patch(
        "app.services.assessment_conversation_ai.ask_ai",
        return_value="Use Prowler next to discover operating systems, services, and vulnerabilities for the hostname.",
    ) as model:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What have we learned about this target so far?",
        )

    model.assert_not_called()
    answer = result["answer"].lower()
    assert "not stored any scans or findings" in answer
    assert "not enough evidence" in answer
    assert "nmap" in answer and "httpx" in answer
    assert "prowler" not in answer
    assert "does not run any tool" in answer


def test_empty_website_next_step_starts_with_nmap_or_httpx_not_evidence_review() -> None:
    assessment = create_assessment("Empty Website Next", user_id=1001)
    add_assessment_target(assessment["id"], "https://btjoinery.ie")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Yo what should we do first?",
        )

    model.assert_not_called()
    answer = result["answer"].lower()
    assert "no stored scans or findings yet" in answer
    assert "nmap" in answer and "reachable ports" in answer
    assert "httpx" in answer and "http" in answer
    assert "review the latest stored evidence" not in answer
    assert "prowler" not in answer
    assert "does not run any tool" in answer


def test_generated_empty_website_prowler_recommendation_is_replaced_by_supported_guidance() -> None:
    assessment = create_assessment("Generated Bad Prowler", user_id=1001)
    add_assessment_target(assessment["id"], "btjoinery.ie")
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What should we do next?",
    )

    assert context["recommendation_context"]["empty_assessment"] is True
    assert context["recommendation_context"]["preferred_next_tools"] == ["nmap", "httpx"]
    assert violates_conversation_truthfulness(
        "I recommend Prowler to discover operating systems and services for this website.",
        context,
    ) is True

    with patch(
        "app.services.assessment_conversation_ai.ask_ai",
        return_value="I recommend Prowler to discover operating systems and services for this website.",
    ):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should we do next?",
        )

    answer = result["answer"].lower()
    assert "nmap" in answer and "httpx" in answer
    assert "prowler" not in answer
    assert result["fallback_reason"] is None


def test_prowler_capability_is_cloud_scoped_not_website_recon() -> None:
    assessment = create_assessment("Prowler scope", user_id=1001)
    add_assessment_target(assessment["id"], "btjoinery.ie")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What about Prowler?",
        )

    model.assert_not_called()
    answer = result["answer"].lower()
    assert "prowler has not been run in this assessment" in answer
    assert "cloud security" in answer or "cloud" in answer
    assert "requires authorized cloud context" in answer or "authorized cloud" in answer
    assert "operating system" not in answer
    assert "website reconnaissance" not in answer
    assert "no cloud issues" not in answer


def test_cloud_context_can_prefer_prowler_initial_recommendation() -> None:
    assessment = create_assessment("Authorized AWS review", user_id=1001, description="Authorized AWS cloud account assessment")
    add_assessment_target(assessment["id"], "aws-account-123456789012", target_type="cloud")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should we do first?",
        )

    model.assert_not_called()
    answer = result["answer"].lower()
    assert "prowler" in answer
    assert "cloud" in answer
    assert "pass/fail" in answer
    assert "does not run any tool" in answer


def test_tool_decision_contract_covers_all_tools_and_blocks_unsuitable_website_tools() -> None:
    assessment = create_assessment("Decision Contract", user_id=1001)
    add_assessment_target(assessment["id"], "btjoinery.ie")

    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What should we do first?",
    )
    decisions = context["recommendation_context"]["tool_decisions"]

    assert set(decisions) == {
        "nmap", "bbot", "nuclei", "httpx", "playwright", "katana", "ffuf", "testssl",
        "gitleaks", "prowler", "metasploit", "tshark",
    }
    assert context["recommendation_context"]["preferred_next_tools"] == ["nmap", "httpx"]
    assert decisions["prowler"]["recommendation_allowed"] is False
    assert "cloud" in decisions["prowler"]["prerequisites"].lower()
    assert decisions["gitleaks"]["recommendation_allowed"] is False
    assert decisions["metasploit"]["recommendation_allowed"] is False
    assert decisions["tshark"]["recommendation_allowed"] is False


def test_empty_network_assessment_prefers_nmap_initial_recon() -> None:
    assessment = create_assessment("Network baseline", user_id=1001)
    add_assessment_target(assessment["id"], "192.0.2.44", target_type="ip")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should we do first?",
        )

    model.assert_not_called()
    answer = result["answer"].lower()
    assert "nmap" in answer
    assert "reachable ports" in answer
    assert "prowler" not in answer
    assert "does not run any tool" in answer


def test_empty_repository_assessment_can_prefer_gitleaks_without_secret_absence_claims() -> None:
    assessment = create_assessment("Repository review", user_id=1001)
    add_assessment_target(assessment["id"], "https://github.com/example/project", target_type="repository")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should we do first?",
        )

    model.assert_not_called()
    answer = result["answer"].lower()
    assert "gitleaks" in answer
    assert "repository" in answer or "filesystem" in answer
    assert "not prove secrets are absent" in answer
    assert "does not run any tool" in answer


def test_unsupported_generated_validation_or_capture_recommendations_are_replaced() -> None:
    assessment = create_assessment("Unsupported generated next", user_id=1001)
    add_assessment_target(assessment["id"], "btjoinery.ie")

    with patch(
        "app.services.assessment_conversation_ai.ask_ai",
        return_value="I recommend Metasploit and TShark next for this website hostname.",
    ):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should we investigate next?",
        )

    answer = result["answer"].lower()
    assert "nmap" in answer and "httpx" in answer
    assert "metasploit" not in answer
    assert "tshark" not in answer
    assert "withheld" not in answer


def test_failed_scan_state_is_not_treated_as_clean_or_as_prowler_context() -> None:
    assessment = create_assessment("Failed baseline", user_id=1001)
    add_assessment_target(assessment["id"], "btjoinery.ie")
    record_assessment_scan(assessment["id"], "nmap", "failed")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should we do next?",
        )

    model.assert_not_called()
    answer = result["answer"].lower()
    assert "nmap=FAILED".lower() in answer
    assert "clean" not in answer
    assert "prowler" in answer
    assert "not automatic recommendations" in answer


def test_summary_intent_does_not_accept_unselected_llm_tool_recommendation() -> None:
    assessment = create_assessment("Summary no extras", user_id=1001)
    add_assessment_target(assessment["id"], "btjoinery.ie")
    _add_nmap_scan(assessment["id"], user_id=1001, port=22, service="ssh")
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What have we learned about this target so far?",
    )

    assert context["question_intent"] == "assessment_summary"
    assert context["recommendation_context"]["preferred_next_tools"] == []
    assert violates_conversation_truthfulness(
        "Nmap recorded SSH. I recommend Prowler next.",
        context,
    ) is True


def test_empty_summary_distinguishes_no_evidence_from_remaining_gaps() -> None:
    assessment = create_assessment("Empty summary distinction", user_id=1001)
    add_assessment_target(assessment["id"], "btjoinery.ie")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What have we learned about this target so far?",
        )["answer"]

    model.assert_not_called()
    assert "has not stored any scans or findings" in answer
    assert "Relevant unperformed coverage remains" not in answer
    assert "Nmap" in answer and "httpx" in answer
    assert "Prowler" not in answer


def test_failed_scan_summary_reports_no_usable_observation_without_calling_it_clean() -> None:
    assessment = create_assessment("Failed summary distinction", user_id=1001)
    add_assessment_target(assessment["id"], "btjoinery.ie")
    record_assessment_scan(assessment["id"], "nmap", "failed")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What have we learned about this target so far?",
        )["answer"]

    model.assert_not_called()
    assert "No normalized observations are stored yet" in answer
    assert "safe or free of vulnerabilities" in answer
    assert "Relevant unperformed coverage remains" not in answer


def test_nmap_web_summary_with_next_step_adds_plain_httpx_guidance() -> None:
    assessment = create_assessment("Summary plus next", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="I'm a complete novice. What have we learned and what should I do next?",
        )["answer"]

    model.assert_not_called()
    assert "Nmap recorded exposed TCP services" in answer
    assert "httpx because" in answer
    assert "which HTTP(S) endpoints respond" in answer
    assert "does not run a tool" in answer


def test_two_port_nmap_web_summary_and_investigate_next_recommends_httpx() -> None:
    assessment = create_assessment("Two-port web next", user_id=1001)
    _add_two_port_web_nmap_scan(assessment["id"], user_id=1001)

    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What have we learned now, and what should we investigate next?",
    )
    assert context["recommendation_context"]["web_services_observed_by_nmap"] is True
    assert context["recommendation_context"]["preferred_next_tools"] == ["httpx"]

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What have we learned now, and what should we investigate next?",
        )["answer"]

    model.assert_not_called()
    assert "80/tcp (http)" in answer
    assert "443/tcp (https)" in answer
    assert "httpx because" in answer
    assert "which HTTP(S) endpoints respond" in answer
    assert "vulnerab" not in answer.lower().split("bounded stored observations")[0]
    assert "Prowler" not in answer
    assert "does not run a tool" in answer


def test_two_port_nmap_web_summary_only_does_not_force_httpx_recommendation() -> None:
    assessment = create_assessment("Two-port web summary only", user_id=1001)
    _add_two_port_web_nmap_scan(assessment["id"], user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What have we learned now?",
        )["answer"]

    model.assert_not_called()
    assert "80/tcp (http)" in answer
    assert "443/tcp (https)" in answer
    assert "httpx because" not in answer


def test_mixed_httpx_summary_and_next_step_recommends_katana_after_evidence_summary() -> None:
    assessment = create_assessment("Mixed httpx and next", user_id=1001)
    _add_two_port_web_nmap_scan(assessment["id"], user_id=1001)
    _add_realistic_httpx_scan(assessment["id"], user_id=1001)

    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What did httpx add to our understanding, and what should we investigate next?",
    )
    assert context["compound_requirements"]["tool_evidence_summary"] == ["httpx"]
    assert context["compound_requirements"]["needs_next_step"] is True
    assert context["recommendation_context"]["preferred_next_tools"] == ["katana"]

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What did httpx add to our understanding, and what should we investigate next?",
        )["answer"]

    model.assert_not_called()
    assert "httpx added HTTP(S) response-level evidence" in answer
    assert "status 301" in answer or "status 200" in answer
    assert "redirect" in answer
    assert "Squarespace" in answer
    assert "HSTS observed" in answer
    assert "TLS 1.3" in answer
    assert "issuer Example CA" in answer
    assert "fingerprint_sha256" not in answer
    assert "AA:BB:CC:DD" not in answer
    assert "{'version'" not in answer and '"version"' not in answer
    assert "I would use Mongrel's Katana next" in answer
    assert "URLs, paths, forms, and linked resources" in answer
    assert "would not by itself prove a vulnerability" in answer
    assert "httpx next" not in answer
    assert "Prowler" not in answer
    assert "does not run the tool" in answer


def test_explicit_httpx_certificate_fingerprint_detail_remains_available() -> None:
    assessment = create_assessment("httpx fingerprint detail", user_id=1001)
    _add_realistic_httpx_scan(assessment["id"], user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Show me the httpx certificate fingerprints.",
        )["answer"]

    model.assert_not_called()
    assert "fingerprint_sha256: AA:BB:CC:DD" in answer


def test_httpx_summary_collapses_semantic_duplicates_but_keeps_distinct_redirects() -> None:
    assessment = create_assessment("httpx duplicate summary", user_id=1001)
    _add_two_port_web_nmap_scan(assessment["id"], user_id=1001)
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "httpx",
            "target": "https://example.com",
            "status": "completed",
            "httpx_services": [
                {"url": "http://example.com", "status_code": 301, "redirect_location": "https://www.example.com/"},
                {"url": "http://example.com", "status_code": 301, "redirect_location": "https://www.example.com/"},
                {"url": "http://example.com", "status_code": 302, "redirect_location": "https://shop.example.com/"},
            ],
        },
    )
    record_assessment_scan(assessment["id"], tool="httpx", status="completed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What did httpx add and what should we investigate next?",
        )["answer"]

    model.assert_not_called()
    assert answer.count("http://example.com") == 2
    assert "https://www.example.com/" in answer
    assert "https://shop.example.com/" in answer
    assert "1 semantically duplicate stored observation(s) were collapsed" in answer
    assert "Katana next" in answer


def test_httpx_summary_merges_duplicate_metadata_without_raw_tls_dump() -> None:
    assessment = create_assessment("httpx duplicate metadata", user_id=1001)
    _add_two_port_web_nmap_scan(assessment["id"], user_id=1001)
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "httpx",
            "target": "https://example.com",
            "status": "completed",
            "httpx_services": [
                {"url": "https://example.com", "status_code": 200, "technologies": ["ExampleTech"]},
                {
                    "url": "https://example.com",
                    "status_code": 200,
                    "hsts": {"present": True, "max_age": 31536000},
                    "tls": {
                        "version": "1.3",
                        "issuer": "Example CA",
                        "fingerprint_sha256": "AA:BB:CC:DD",
                    },
                },
            ],
        },
    )
    record_assessment_scan(assessment["id"], tool="httpx", status="completed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What did httpx add and what should we investigate next?",
        )["answer"]

    model.assert_not_called()
    assert answer.count("https://example.com") == 1
    assert "1 semantically duplicate stored observation(s) were collapsed" in answer
    assert "ExampleTech" in answer
    assert "HSTS observed" in answer
    assert "TLS 1.3" in answer
    assert "issuer Example CA" in answer
    assert "fingerprint_sha256" not in answer
    assert "AA:BB:CC:DD" not in answer
    assert "{'version'" not in answer and '"version"' not in answer


def test_large_httpx_summary_is_bounded_and_acknowledges_omitted_observations() -> None:
    assessment = create_assessment("httpx large summary", user_id=1001)
    _add_two_port_web_nmap_scan(assessment["id"], user_id=1001)
    services = [
        {"url": f"https://example.com/page-{index}", "status_code": 200, "technologies": ["ExampleTech"]}
        for index in range(10)
    ]
    finding = add_finding(
        user_id=1001,
        finding={"source": "httpx", "target": "https://example.com", "status": "completed", "httpx_services": services},
    )
    record_assessment_scan(assessment["id"], tool="httpx", status="completed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What did httpx add and what should we investigate next?",
        )["answer"]

    model.assert_not_called()
    assert "4 additional distinct stored observation(s) are not shown here" in answer
    assert "page-0" in answer and "page-5" in answer
    assert "page-6" not in answer
    assert len(answer) < 2500


def test_mixed_nmap_summary_and_next_step_still_recommends_httpx() -> None:
    assessment = create_assessment("Mixed nmap and next", user_id=1001)
    _add_two_port_web_nmap_scan(assessment["id"], user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What did Nmap find and what should we do next?",
        )["answer"]

    model.assert_not_called()
    assert "Nmap added stored port/service observations" in answer
    assert "80/tcp (http)" in answer and "443/tcp (https)" in answer
    assert "httpx next" in answer
    assert "not evidence of a vulnerability" in answer


def test_mixed_failed_status_and_next_step_reports_state_before_recommendation() -> None:
    assessment = create_assessment("Mixed failure and next", user_id=1001)
    add_assessment_target(assessment["id"], "btjoinery.ie")
    record_assessment_scan(assessment["id"], "testssl", "failed")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What failed and what should we retry next?",
        )["answer"]

    model.assert_not_called()
    assert "testssl=FAILED" in answer
    assert "execution state" in answer
    assert "clean result" in answer
    assert "does not identify another automatically required tool" in answer


def test_summary_only_does_not_force_next_step_when_evidence_exists() -> None:
    assessment = create_assessment("Summary only", user_id=1001)
    _add_live_web_nmap_scan(assessment["id"], user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What have we learned about this target so far?",
        )["answer"]

    model.assert_not_called()
    assert "Nmap recorded exposed TCP services" in answer
    assert "httpx because" not in answer


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("is that a vulnerability?", "confirmed vulnerability"),
        ("is that a vulnerabilty?", "confirmed vulnerability"),
        ("is that a vunerability?", "confirmed vulnerability"),
        ("is that a vuln?", "confirmed vulnerability"),
        ("does that mean its vulnerable?", "confirmed vulnerability"),
        ("can that be exploited?", "successful exploitation path"),
        ("can that be exploitible?", "successful exploitation path"),
        ("could someone exploit that?", "successful exploitation path"),
        ("can an attacker actually use that?", "successful exploitation path"),
        ("are we safe?", "secure or vulnerable overall"),
        ("are we secure?", "secure or vulnerable overall"),
        ("is the site secure?", "secure or vulnerable overall"),
    ],
)
def test_casual_uncertainty_questions_recover_contextual_bounded_answer(question: str, expected: str) -> None:
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

    assert result["fallback_reason"] is None
    assert expected in result["answer"]
    assert "withheld" not in result["answer"].lower()


def test_uncertainty_reference_is_named_only_when_history_and_evidence_support_it() -> None:
    assessment = create_assessment("Supported reference", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=8080, service="http-proxy")
    conversation = create_conversation(assessment["id"], user_id=1001)
    append_message(
        conversation["id"], user_id=1001, role="assistant",
        content="The observed web-associated service surface is worth investigating.",
    )

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Yes, that is a vulnerability."):
        result = answer_assessment_conversation_question(
            user_id=1001, assessment_id=assessment["id"], conversation_id=conversation["id"],
            question="Is that a vulnerability?",
        )

    assert "the observed web-associated service surface as a confirmed vulnerability" in result["answer"]


def test_unresolved_uncertainty_reference_is_not_invented() -> None:
    assessment = create_assessment("Unresolved reference", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)
    append_message(conversation["id"], user_id=1001, role="assistant", content="That deserves another look.")

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="The target is exploitable."):
        result = answer_assessment_conversation_question(
            user_id=1001, assessment_id=assessment["id"], conversation_id=conversation["id"],
            question="Can that be exploited?",
        )

    assert "the referenced observation" in result["answer"]
    assert "web-associated" not in result["answer"]


def test_tool_state_contradictions_are_rejected_deterministically() -> None:
    assessment = create_assessment("State guard", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=443, service="https")
    record_assessment_scan(assessment["id"], tool="httpx", status="completed")
    context = build_assessment_conversation_context(
        user_id=1001, assessment_id=assessment["id"], question="What would you do next?",
    )

    assert violates_conversation_truthfulness("I recommend httpx next.", context) is True
    assert violates_conversation_truthfulness("Prowler has been initiated.", context) is True
    assert violates_conversation_truthfulness("There are no Gitleaks findings.", context) is True
    assert violates_conversation_truthfulness("No further evidence gaps have been identified.", context) is True
    assert violates_conversation_truthfulness("httpx is completed; I would use Katana next.", context) is False


def test_live_metasploit_detected_evidence_renders_without_upgrading_metadata() -> None:
    assessment = create_assessment("Live Metasploit", user_id=1001)
    finding = add_finding(user_id=1001, finding={
        "source": "metasploit",
        "target": "btjoinery.ie",
        "status": "completed",
        "metadata": {
            "module": "auxiliary/scanner/http/http_version",
            "port": 80,
        },
        "metasploit_evidence": {
            "source": "metasploit",
            "module": "auxiliary/scanner/http/http_version",
            "action_type": "auxiliary_validation",
            "target": "btjoinery.ie",
            "port": 80,
            "validation_state": "DETECTED",
            "subprocess_success": True,
            "module_executed": True,
            "session_established": False,
            "summary": "Metasploit reported service or version metadata. This is detection evidence, not proof of vulnerability, exploitation, or compromise.",
        },
    })
    record_assessment_scan(assessment["id"], tool="metasploit", status="completed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What did Metasploit find?",
        )

    ask_ai.assert_not_called()
    answer = result["answer"]
    assert "validation state: DETECTED" in answer
    assert "service/version metadata only" in answer
    assert "No specific HTTP version is stored" in answer
    assert "No vulnerability condition was validated" in answer
    assert "a session was not established" in answer
    assert "validation was successful" not in answer.lower()
    assert "supported HTTP version" not in answer.lower()


def test_metasploit_detected_guard_rejects_generated_upgrade_and_recovers() -> None:
    assessment = create_assessment("Metasploit guard", user_id=1001)
    finding = add_finding(user_id=1001, finding={
        "source": "metasploit",
        "target": "btjoinery.ie",
        "metasploit_evidence": {
            "module": "auxiliary/scanner/http/http_version",
            "target": "btjoinery.ie",
            "port": 80,
            "validation_state": "DETECTED",
            "subprocess_success": True,
            "session_established": False,
        },
    })
    record_assessment_scan(assessment["id"], tool="metasploit", status="completed", finding_id=finding["id"])
    context = build_assessment_conversation_context(
        user_id=1001, assessment_id=assessment["id"], question="What did Metasploit find?",
    )
    overclaim = "Metasploit validated that the target supports a supported HTTP version; validation was successful."

    assert violates_conversation_truthfulness(overclaim, context) is True
    recovered = _recover_rejected_assessment_answer(context)
    assert recovered is not None
    assert "validation state: DETECTED" in recovered
    assert "supported HTTP version" not in recovered.lower()


def test_metasploit_process_completion_wording_remains_allowed() -> None:
    assessment = create_assessment("Metasploit completion", user_id=1001)
    finding = add_finding(user_id=1001, finding={
        "source": "metasploit",
        "metasploit_evidence": {
            "validation_state": "DETECTED",
            "subprocess_success": True,
            "session_established": False,
        },
    })
    record_assessment_scan(assessment["id"], tool="metasploit", status="completed", finding_id=finding["id"])
    context = build_assessment_conversation_context(
        user_id=1001, assessment_id=assessment["id"], question="What did Metasploit find?",
    )

    assert violates_conversation_truthfulness(
        "msfconsole completed; service/version metadata was observed and no session was established.", context
    ) is False


def test_list_style_recommendations_for_completed_tools_are_rejected_but_reruns_are_allowed() -> None:
    assessment = create_assessment("Recommendation phrasing", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=80, service="http")
    httpx = add_finding(user_id=1001, finding={"source": "httpx", "target": "example.com", "httpx_services": []})
    record_assessment_scan(assessment["id"], tool="httpx", status="completed", finding_id=httpx["id"])
    context = build_assessment_conversation_context(
        user_id=1001, assessment_id=assessment["id"], question="What should we investigate next?",
    )

    assert violates_conversation_truthfulness(
        "Next steps should include a more comprehensive scan using tools like Nmap and httpx.", context
    ) is True
    assert violates_conversation_truthfulness(
        "Because evidence changed, rerun Nmap to confirm the host state.", context
    ) is False


@pytest.mark.parametrize(
    "claim",
    [
        "Nmap identified vulnerabilities.",
        "httpx identified the target's security posture.",
        "Nuclei identified vulnerabilities.",
        "testssl.sh identified insecure configurations.",
        "Metasploit identified vulnerabilities and weaknesses.",
        "TShark detected suspicious activity.",
    ],
)
def test_completed_tool_capabilities_cannot_be_rewritten_as_findings(claim: str) -> None:
    assessment = create_assessment("Semantic guard", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=443, service="https")
    for tool in ("nuclei", "httpx", "testssl", "metasploit", "tshark"):
        record_assessment_scan(assessment["id"], tool=tool, status="completed")
    context = build_assessment_conversation_context(
        user_id=1001, assessment_id=assessment["id"], question="Summarise what the tools established.",
    )

    assert violates_conversation_truthfulness(claim, context) is True


def test_live_messy_gitleaks_relevance_is_deterministic_and_state_first() -> None:
    assessment = create_assessment("Messy relevance", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=443, service="https")

    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001, assessment_id=assessment["id"], conversation_id=None,
            question="What wouldnt you use gitleaks",
        )

    ask_ai.assert_not_called()
    assert result["answer"].startswith("Gitleaks has not been run in this assessment.")
    assert "not an automatic next choice" in result["answer"]
    assert "no conclusion about the presence or absence of secrets" in result["answer"]
    assert "no findings or scans associated with the target" not in result["answer"].lower()


def test_assessment_wide_no_scan_claim_is_rejected_when_scans_exist() -> None:
    assessment = create_assessment("Existing scans", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001, port=443, service="https")
    context = build_assessment_conversation_context(
        user_id=1001, assessment_id=assessment["id"], question="What about Gitleaks?",
    )

    assert violates_conversation_truthfulness(
        "There are no findings or scans associated with the target.", context,
    ) is True


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

    if question != "And 8080?":
        ask_ai.assert_not_called()
        assert "httpx was suggested because" in result["answer"]
    else:
        ask_ai.assert_not_called()
        assert "8080/tcp classified as http-proxy" in result["answer"]
        assert "does not establish vulnerability" in result["answer"]
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

    ask_ai.assert_not_called()
    assert "httpx next" in result["answer"]
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


def test_unsupported_broad_security_conclusion_is_replaced_with_bounded_uncertainty() -> None:
    assessment = create_assessment("Guarded", user_id=1001)

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="The target is secure. No vulnerabilities were found."):
        result = answer_assessment_conversation_question(
            user_id=1001,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Is this secure?",
        )

    assert "not enough to conclude" in result["answer"]
    assert "secure or vulnerable overall" in result["answer"]
    assert result["fallback_reason"] is None


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

    ask_ai.assert_not_called()
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

    ask_ai.assert_not_called()
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

    ask_ai.assert_not_called()
    assert "httpx next because" in result["answer"]
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

    assert "httpx next because" in result["answer"]
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
            "output_token_budget", "inherited_evidence_scope", "prompt_budget_reduced",
            "prompt_budget_input_tokens", "evidence_items_before_budget", "evidence_items_after_budget",
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


def test_newest_tshark_artifact_survives_context_budget_and_drives_answer() -> None:
    user_id = 1090
    assessment = create_assessment("Latest capture wins", user_id=user_id)
    for index in range(8):
        scan = record_assessment_scan(assessment["id"], "tshark", "completed")
        add_assessment_artifact(
            assessment["id"], "tshark_normalized_evidence", f"Older capture {index}",
            content=json.dumps({"source": "tshark", "packet_count": 0, "byte_count": 0}), scan_id=scan["id"],
        )
    latest_scan = record_assessment_scan(assessment["id"], "tshark", "completed")
    add_assessment_artifact(
        assessment["id"], "tshark_normalized_evidence", "Latest capture",
        content=json.dumps({"source": "tshark", "packet_count": 37, "byte_count": 4096}), scan_id=latest_scan["id"],
    )

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None,
            question="What did TShark actually capture?",
        )

    assert "captured 37 packets (4096 bytes)" in result["answer"]
    model.assert_not_called()


def test_live_wording_variants_are_deterministic_and_evidence_scoped() -> None:
    user_id = 1091
    assessment = create_assessment("Live wording", user_id=user_id)
    evidence = {
        "nmap": {"open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}]},
        "httpx": {"httpx_services": [{"url": "https://example.test", "status_code": 403}]},
        "testssl": {"testssl_findings": [{"id": "cipher", "severity": "MEDIUM", "finding": "scanner observation"}]},
        "metasploit": {"metasploit_evidence": {"module_executed": True, "session_established": False}},
    }
    for tool, values in evidence.items():
        finding = add_finding(user_id=user_id, finding={"source": tool, "target": "example.test", **values})
        record_assessment_scan(
            assessment["id"], tool, "failed" if tool == "testssl" else "completed", finding_id=finding["id"]
        )
    tshark_scan = record_assessment_scan(assessment["id"], "tshark", "completed")
    add_assessment_artifact(assessment["id"], "tshark_normalized_evidence", "Capture", content=json.dumps({"packet_count": 12, "byte_count": 900}), scan_id=tshark_scan["id"])

    questions = (
        "What dont we know", "Is the TLS configuration safe?",
        "Did metasploit and tshark actually confirm exploitation", "Nothing else needs testing right?",
    )
    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answers = {question: answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question=question,
        )["answer"].lower() for question in questions}

    gaps_answer = answers[questions[0]]
    assert "completed core web coverage: nmap, httpx" in gaps_answer
    assert "testssl.sh is failed" in gaps_answer
    assert "completed structured tls configuration coverage remains missing" in gaps_answer
    assert "bbot is not_run" in gaps_answer
    assert "gitleaks and prowler are context-dependent, not required" in gaps_answer
    assert "does not establish that the target is secure or insecure" in gaps_answer
    assert "does not execute any tool" in gaps_answer
    assert "completed core web coverage: nmap, httpx, testssl" not in gaps_answer
    assert "testssl.sh" in answers[questions[1]] and "overall tls security" in answers[questions[1]]
    assert all(source in answers[questions[2]] for source in ("metasploit", "tshark"))
    assert "does not establish successful exploitation" in answers[questions[2]]
    assert "katana" in answers[questions[3]]
    model.assert_not_called()


def test_failed_testssl_without_structured_evidence_is_not_summarized_as_tls_observations() -> None:
    user_id = 1093
    assessment = create_assessment("Failed TLS scan", user_id=user_id)
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "testssl",
            "target": "example.test",
            "status": "failed",
            "summary": "No structured testssl.sh evidence was stored.",
            "error": "testssl.sh scan timed out.",
        },
    )
    record_assessment_scan(assessment["id"], "testssl", "failed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What have we actually established about this target?",
        )

    answer = result["answer"].lower()
    assert "stored scanner tls observations" not in answer
    assert "did not complete successfully" in answer
    assert "does not contain completed structured tls configuration evidence" in answer
    model.assert_not_called()


def test_partial_testssl_with_structured_evidence_preserves_tls_observations() -> None:
    user_id = 1094
    assessment = create_assessment("Partial TLS evidence", user_id=user_id)
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "testssl",
            "target": "example.test",
            "status": "partial",
            "testssl_evidence": {
                "target": "example.test",
                "protocols": [{"id": "TLS1_2", "finding": "offered"}],
            },
        },
    )
    record_assessment_scan(assessment["id"], "testssl", "partial", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What have we actually established about this target?",
        )

    assert "testssl.sh stored scanner TLS observations" in result["answer"]
    model.assert_not_called()


def test_after_that_one_continues_prior_katana_recommendation() -> None:
    user_id = 1092
    assessment = create_assessment("Continuation", user_id=user_id)
    conversation = create_conversation(assessment["id"], user_id)
    append_message(conversation["id"], user_id, "assistant", "I would use Mongrel's Katana next.")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=conversation["id"],
            question="And after that one",
        )

    assert "after katana" in result["answer"].lower()
    assert "conditional recommendation" in result["answer"].lower()
    model.assert_not_called()


def test_completed_katana_evidence_then_followup_advances_to_playwright() -> None:
    user_id = 1095
    assessment = create_assessment("Completed crawl continuation", user_id=user_id)
    conversation = create_conversation(assessment["id"], user_id)
    nmap = add_finding(
        user_id=user_id,
        finding={
            "source": "nmap",
            "target": "example.test",
            "open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
        },
    )
    record_assessment_scan(assessment["id"], "nmap", "completed", finding_id=nmap["id"])
    for tool in ("httpx", "nuclei"):
        record_assessment_scan(assessment["id"], tool, "completed")
    record_assessment_scan(assessment["id"], "testssl", "failed")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        recommendation_answer = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=conversation["id"],
            question="What should we do next",
        )["answer"]
        append_message(conversation["id"], user_id, "user", "What should we do next")
        append_message(conversation["id"], user_id, "assistant", recommendation_answer)
        katana = add_finding(
            user_id=user_id,
            finding={
                "source": "katana",
                "target": "https://example.test",
                "katana_observations": [
                    {
                        "url": "https://example.test/",
                        "host": "example.test",
                        "depth": 0,
                        "endpoint_type": "url",
                        "query_parameters": [],
                        "forms": [],
                    }
                ],
                "katana_summary": {
                    "url_count": 1,
                    "host_count": 1,
                    "javascript_count": 0,
                    "query_parameter_count": 0,
                    "form_count": 0,
                    "max_depth": 0,
                },
            },
        )
        record_assessment_scan(assessment["id"], "katana", "completed", finding_id=katana["id"])
        evidence_answer = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=conversation["id"],
            question="What did Katana add",
        )["answer"]
        append_message(conversation["id"], user_id, "user", "What did Katana add")
        append_message(conversation["id"], user_id, "assistant", evidence_answer)
        followup_answer = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=conversation["id"],
            question="And after that one?",
        )["answer"]

    assert "Katana next" in recommendation_answer
    assert "1 URL/endpoint" in evidence_answer
    assert "1 unique host" in evidence_answer
    assert "0 JavaScript files" in evidence_answer
    assert "0 query parameters" in evidence_answer
    assert "0 forms/actions" in evidence_answer
    assert "maximum observed crawl depth was 0" in evidence_answer
    assert "do not prove those features are absent" in evidence_answer
    assert "Playwright" in followup_answer
    assert "Katana next" not in followup_answer
    assert "testssl.sh" not in followup_answer
    assert "recommendation" in followup_answer.lower()
    assert "runs nothing" in followup_answer.lower()
    model.assert_not_called()


def test_confidence_summary_deduplicates_httpx_and_omits_unknown_status() -> None:
    user_id = 1093
    assessment = create_assessment("Summary rendering", user_id=user_id)
    finding = add_finding(user_id=user_id, finding={
        "source": "httpx", "target": "example.test",
        "httpx_services": [{"url": "https://example.test", "status_code": 200}, {"url": "https://example.test", "status_code": 200}],
        "httpx_results": [{"url": "https://other.example"}, {"url": "https://other.example"}],
    })
    record_assessment_scan(assessment["id"], "httpx", "completed", finding_id=finding["id"])

    result = answer_assessment_conversation_question(
        user_id=user_id, assessment_id=assessment["id"], conversation_id=None,
        question="What can you actually say with confidence?",
    )

    assert result["answer"].count("https://example.test (status 200)") == 1
    assert "https://other.example" not in result["answer"]
    assert "status None" not in result["answer"]


def test_completed_playwright_named_question_summarizes_normalized_browser_evidence() -> None:
    user_id = 1096
    assessment = create_assessment("Browser evidence", user_id=user_id)
    observation = {
        "requested_url": "https://btjoinery.ie/",
        "final_url": "https://www.btjoinery.ie/",
        "title": "BT Joinery Services Ireland",
        "load_status": "loaded",
        "status_code": 200,
        "forms_count": 0,
        "inputs_count": 12,
        "links_count": 56,
        "network_events": [{"url": f"https://www.btjoinery.ie/resource/{index}"} for index in range(25)],
        "console_issue_count": 8,
        "network_issue_count": 0,
        "page_error_count": 0,
        "screenshot": {"captured": True, "type": "png"},
        "redirected_out_of_scope": True,
    }
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "playwright",
            "target": observation["requested_url"],
            "playwright_observation": observation,
            "playwright_summary": {
                "final_url": observation["final_url"],
                "title": observation["title"],
                "load_status": "loaded",
                "status_code": 200,
                "forms_count": 0,
                "inputs_count": 12,
                "links_count": 56,
                "network_events_count": 25,
                "console_issue_count": 8,
                "network_issue_count": 0,
                "page_error_count": 0,
                "screenshot_present": True,
                "redirected_out_of_scope": True,
            },
        },
    )
    record_assessment_scan(assessment["id"], "playwright", "completed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="what did playwright add!",
        )["answer"]

    for expected in (
        "https://www.btjoinery.ie/",
        "BT Joinery Services Ireland",
        "loaded",
        "status 200",
        "0 forms",
        "12 inputs",
        "56 links",
        "25 network events",
        "8 console issues",
        "0 network issues",
        "0 page errors",
        "Screenshot/artifact: present",
        "Out-of-scope redirect: yes",
    ):
        assert expected in answer
    assert "passive browser observation" in answer
    model.assert_not_called()


def test_playright_typo_question_keeps_zero_counts_evidence_bounded() -> None:
    user_id = 1097
    assessment = create_assessment("Bounded browser evidence", user_id=user_id)
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "playwright",
            "target": "https://example.test",
            "playwright_observation": {
                "final_url": "https://example.test/",
                "load_status": "loaded",
                "forms_count": 0,
                "inputs_count": 0,
                "links_count": 0,
                "console_issue_count": 0,
                "network_issue_count": 0,
                "page_error_count": 0,
            },
        },
    )
    record_assessment_scan(assessment["id"], "playwright", "completed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="what did playright find?",
        )["answer"]

    assert "Playwright is recorded as completed" in answer
    assert "Zero counts do not prove absence" in answer
    assert "does not establish vulnerability, safety, exploitability" in answer
    assert "or complete coverage" in answer
    model.assert_not_called()


def test_completed_ffuf_zero_results_reports_stored_run_scope_without_absence_claim() -> None:
    user_id = 1098
    assessment = create_assessment("Zero-result ffuf", user_id=user_id)
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "ffuf",
            "target": "https://example.test/FUZZ",
            "status": "completed",
            "ffuf_results": [],
            "ffuf_summary": {"result_count": 0, "status_codes": {}, "limitations": ["Bounded selected wordlist."]},
            "metadata": {
                "ffuf_profile": "standard",
                "ffuf_profile_label": "Standard",
                "wordlist_path": "/opt/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                "wordlist_source": "Configured Standard SecLists wordlist",
                "wordlist_count": 30000,
                "timeout_seconds": 120,
            },
        },
    )
    record_assessment_scan(assessment["id"], "ffuf", "completed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question="What did ffuf add",
        )["answer"]

    for expected in ("Standard", "raft-medium-directories.txt", "Configured Standard SecLists wordlist", "30000", "120"):
        assert expected in answer
    assert "no structured ffuf response observations were stored" in answer.lower()
    assert "does not establish that hidden content is absent" in answer
    assert "/opt/seclists" not in answer
    model.assert_not_called()


def test_important_remaining_gaps_are_deterministic_and_state_aware() -> None:
    user_id = 1099
    assessment = create_assessment("State-aware gaps", user_id=user_id)
    for tool in ("nmap", "httpx", "nuclei", "katana", "playwright", "ffuf"):
        record_assessment_scan(assessment["id"], tool, "completed")
    record_assessment_scan(assessment["id"], "testssl", "failed")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What important gaps remain now",
        )["answer"]

    assert "Completed core web coverage: Nmap, httpx, Nuclei, Katana, Playwright, ffuf" in answer
    assert "testssl.sh is FAILED" in answer
    assert "completed structured TLS configuration coverage remains missing" in answer
    assert "BBOT is NOT_RUN" in answer and "if broader reconnaissance is relevant" in answer
    assert "Gitleaks and Prowler are context-dependent, not required" in answer
    assert "Metasploit and TShark are conditional, not mandatory" in answer
    assert "does not establish that the target is secure or insecure" in answer
    assert "run" not in answer.lower().split("metasploit and tshark")[1].split(".")[0]
    model.assert_not_called()


def test_named_ffuf_uses_newest_scan_linked_evidence_only() -> None:
    user_id = 1100
    assessment = create_assessment("Repeated ffuf", user_id=user_id)
    older = add_finding(user_id=user_id, finding={
        "source": "ffuf", "target": "https://example.test/FUZZ", "ffuf_results": [],
        "ffuf_summary": {"result_count": 0, "status_codes": {}},
        "metadata": {"ffuf_profile_label": "Custom", "wordlist_path": "ffuf_default.txt", "wordlist_count": 19},
    })
    record_assessment_scan(assessment["id"], "ffuf", "completed", finding_id=older["id"])
    newer = add_finding(user_id=user_id, finding={
        "source": "ffuf", "target": "https://example.test/FUZZ",
        "ffuf_results": [{"url": "https://example.test/admin", "status_code": 403}],
        "ffuf_summary": {"result_count": 1, "status_codes": {"403": 1}},
        "metadata": {
            "ffuf_profile_label": "Standard", "wordlist_path": "/opt/seclists/raft-medium.txt",
            "wordlist_source": "Configured Standard SecLists wordlist", "wordlist_count": 30000,
            "timeout_seconds": 120,
        },
    })
    record_assessment_scan(assessment["id"], "ffuf", "completed", finding_id=newer["id"])

    answer = answer_assessment_conversation_question(
        user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question="What did ffuf add?",
    )["answer"]

    assert all(value in answer for value in ("Standard", "raft-medium.txt", "30000", "timeout 120", "403=1"))
    assert all(value not in answer for value in ("Custom", "ffuf_default.txt", "19 wordlist entries"))


def test_named_ffuf_keeps_newest_failed_state_and_does_not_fall_back_to_older_completed_run() -> None:
    user_id = 1101
    assessment = create_assessment("Failed latest ffuf", user_id=user_id)
    older = add_finding(user_id=user_id, finding={
        "source": "ffuf", "target": "https://example.test/FUZZ", "ffuf_results": [{"status_code": 200}],
        "metadata": {"ffuf_profile_label": "Custom", "wordlist_path": "ffuf_default.txt", "wordlist_count": 19},
    })
    record_assessment_scan(assessment["id"], "ffuf", "completed", finding_id=older["id"])
    latest = add_finding(user_id=user_id, finding={
        "source": "ffuf", "target": "https://example.test/FUZZ", "status": "failed", "ffuf_results": [],
        "metadata": {"ffuf_profile_label": "Standard", "wordlist_count": 30000, "error": "timed out"},
    })
    record_assessment_scan(assessment["id"], "ffuf", "failed", finding_id=latest["id"])

    answer = answer_assessment_conversation_question(
        user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question="What did ffuf add?",
    )["answer"]

    assert "ffuf is failed" in answer
    assert "Standard" in answer and "30000" in answer
    assert all(value not in answer for value in ("Custom", "ffuf_default.txt", "19 wordlist entries"))


def test_named_ffuf_preserves_newest_partial_run_evidence() -> None:
    user_id = 1102
    assessment = create_assessment("Partial latest ffuf", user_id=user_id)
    older = add_finding(user_id=user_id, finding={
        "source": "ffuf", "ffuf_results": [{"status_code": 200}],
        "metadata": {"ffuf_profile_label": "Custom", "wordlist_count": 19},
    })
    record_assessment_scan(assessment["id"], "ffuf", "completed", finding_id=older["id"])
    latest = add_finding(user_id=user_id, finding={
        "source": "ffuf", "status": "partial", "ffuf_results": [{"status_code": 403}],
        "ffuf_summary": {"result_count": 1, "status_codes": {"403": 1}},
        "metadata": {"ffuf_profile_label": "Deep", "wordlist_count": 60000},
    })
    record_assessment_scan(assessment["id"], "ffuf", "partial", finding_id=latest["id"])

    answer = answer_assessment_conversation_question(
        user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question="What did ffuf add?",
    )["answer"]

    assert "ffuf is partial" in answer
    assert "interrupted" not in answer
    assert "Deep" in answer and "60000" in answer and "403=1" in answer
    assert "Custom" not in answer and "19 wordlist entries" not in answer


def test_mixed_ffuf_summary_keeps_remaining_web_security_tools_eligible() -> None:
    user_id = 1103
    assessment = create_assessment("Completed web discovery next", user_id=user_id)
    add_assessment_target(assessment["id"], "example.com")
    _add_two_port_web_nmap_scan(assessment["id"], user_id=user_id)
    _add_realistic_httpx_scan(assessment["id"], user_id=user_id)
    katana = add_finding(
        user_id=user_id,
        finding={
            "source": "katana",
            "target": "https://example.com",
            "katana_observations": [{"url": "https://example.com/", "depth": 0}],
        },
    )
    record_assessment_scan(assessment["id"], "katana", "completed", finding_id=katana["id"])
    playwright = add_finding(
        user_id=user_id,
        finding={
            "source": "playwright",
            "target": "https://example.com",
            "playwright_observation": {
                "final_url": "https://example.com/",
                "status_code": 200,
                "load_status": "loaded",
                "forms_count": 0,
                "inputs_count": 1,
                "links_count": 5,
                "network_events_count": 12,
            },
        },
    )
    record_assessment_scan(assessment["id"], "playwright", "completed", finding_id=playwright["id"])
    ffuf = add_finding(
        user_id=user_id,
        finding={
            "source": "ffuf",
            "target": "https://example.com/FUZZ",
            "status": "completed",
            "ffuf_results": [{"url": "https://example.com/admin", "status_code": 403, "content_length": 1234}],
            "ffuf_summary": {"result_count": 1, "status_codes": {"403": 1}},
            "metadata": {"ffuf_profile_label": "Standard", "wordlist_count": 30000, "timeout_seconds": 120},
        },
    )
    record_assessment_scan(assessment["id"], "ffuf", "completed", finding_id=ffuf["id"])

    question = "What did ffuf add to our understanding, and what should we investigate next?"
    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment["id"],
        question=question,
    )

    assert context["compound_requirements"]["tool_evidence_summary"] == ["ffuf"]
    assert context["compound_requirements"]["needs_next_step"] is True
    assert context["recommendation_context"]["preferred_next_tools"] == ["nuclei", "testssl", "bbot"]

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        answer = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question=question,
        )["answer"]

    model.assert_not_called()
    assert "ffuf is recorded as completed" in answer
    assert "Standard" in answer and "30000" in answer and "403=1" in answer
    assert "does not establish that hidden content is absent" in answer
    assert "Nuclei for approved template-based checks" in answer
    assert "testssl.sh for TLS protocol" in answer
    assert "BBOT for bounded broader reconnaissance" in answer
    assert "does not run a tool" in answer
    assert "Prowler" not in answer
    assert "Gitleaks" not in answer
    assert "Metasploit" not in answer
    assert "TShark" not in answer
    assert " is vulnerable" not in answer.lower()
    assert "found a vulnerability" not in answer.lower()


def test_followup_tool_explanation_preserves_state_after_bbot_recommendation() -> None:
    user_id = 1104
    assessment = create_assessment("BBOT follow-up state", user_id=user_id)
    add_assessment_target(assessment["id"], "example.com")
    _add_two_port_web_nmap_scan(assessment["id"], user_id=user_id)
    _add_realistic_httpx_scan(assessment["id"], user_id=user_id)
    for tool in ("nuclei", "katana", "playwright", "ffuf", "testssl"):
        finding = add_finding(
            user_id=user_id,
            finding={"source": tool, "target": "example.com", "status": "completed"},
        )
        record_assessment_scan(assessment["id"], tool, "completed", finding_id=finding["id"])

    first_question = "From the tests done so far, what do you recommend I do next?"
    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        first = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question=first_question,
        )["answer"]

    model.assert_not_called()
    assert "BBOT for bounded broader reconnaissance" in first
    assert "Nmap" not in first.split("Suitable remaining investigation options are", 1)[-1]
    assert "httpx" not in first.split("Suitable remaining investigation options are", 1)[-1]

    conversation = create_conversation(assessment["id"], user_id, "BBOT follow-up")
    append_message(conversation["id"], user_id, "user", first_question)
    append_message(conversation["id"], user_id, "assistant", first)

    valid_explanation = "BBOT performs bounded reconnaissance and asset discovery within authorized scope."
    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=valid_explanation) as model:
        accepted = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=conversation["id"],
            question="and what does bbot do?",
        )

    model.assert_called_once()
    assert accepted["answer"] == valid_explanation
    assert accepted["fallback_reason"] is None

    bad_explanation = (
        "BBOT performs bounded reconnaissance and asset discovery. "
        "For the next workflow, start with Nmap followed by httpx."
    )
    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=bad_explanation) as model:
        second = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=conversation["id"],
            question="and what does bbot do?",
        )

    model.assert_called_once()
    assert second["fallback_reason"] == "grounded_conversation_fallback"
    second = second["answer"]
    assert "BBOT is not run in this assessment" in second
    assert "Reconnaissance and asset discovery" in second
    assert "does not prove ownership" in second
    assert "prior recommendation context" in second
    assert "Nmap already completed" in second
    assert "httpx already completed" in second
    assert "This explanation does not run any tool" in second
    assert "Nmap" not in second.split("Current completed-tool state", 1)[0]
    assert "httpx" not in second.split("Current completed-tool state", 1)[0]


def test_completed_tool_followup_recommendation_phrases_are_rejected_without_rerun_reason() -> None:
    assessment = create_assessment("Completed tool contradiction", user_id=1105)
    add_assessment_target(assessment["id"], "example.com")
    _add_two_port_web_nmap_scan(assessment["id"], user_id=1105)
    _add_realistic_httpx_scan(assessment["id"], user_id=1105)
    context = build_assessment_conversation_context(
        user_id=1105,
        assessment_id=assessment["id"],
        question="and what does bbot do?",
    )

    assert violates_conversation_truthfulness("Use Nmap followed by httpx to begin.", context) is True
    assert violates_conversation_truthfulness("Because evidence changed, rerun Nmap to confirm the host state.", context) is False


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


def _add_two_port_web_nmap_scan(assessment_id: int, *, user_id: int) -> dict:
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "nmap",
            "target": "example.com",
            "status": "completed",
            "summary": "Host reachable; open ports observed.",
            "host_status": "up",
            "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http"},
                {"port": 443, "protocol": "tcp", "service": "https"},
            ],
        },
    )
    return record_assessment_scan(assessment_id, tool="nmap", status="completed", finding_id=finding["id"])


def _add_realistic_httpx_scan(assessment_id: int, *, user_id: int) -> dict:
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "httpx",
            "target": "https://example.com",
            "status": "completed",
            "httpx_services": [
                {
                    "url": "http://example.com",
                    "status_code": 301,
                    "redirect_location": "https://www.example.com/",
                    "title": "",
                    "technologies": ["Squarespace"],
                },
                {
                    "url": "https://www.example.com/",
                    "status_code": 200,
                    "title": "Example Joinery",
                    "technologies": ["Squarespace", "Squarespace Commerce"],
                    "hsts": {"present": True, "max_age": 31536000},
                    "tls": {
                        "version": "1.3",
                        "subject": "www.example.com",
                        "issuer": "Example CA",
                        "not_after": "2027-01-01T00:00:00Z",
                        "fingerprint_sha256": "AA:BB:CC:DD",
                    },
                },
            ],
        },
    )
    return record_assessment_scan(assessment_id, tool="httpx", status="completed", finding_id=finding["id"])


def _add_eight_tool_web_assessment(assessment_id: int, *, user_id: int) -> None:
    _add_two_port_web_nmap_scan(assessment_id, user_id=user_id)
    _add_realistic_httpx_scan(assessment_id, user_id=user_id)
    katana = add_finding(
        user_id=user_id,
        finding={
            "source": "katana",
            "target": "https://www.example.com/",
            "status": "completed",
            "katana_observations": [
                {
                    "url": "https://www.example.com/",
                    "host": "www.example.com",
                    "path": "/",
                    "status_code": 200,
                    "depth": 0,
                    "endpoint_type": "url",
                }
            ],
        },
    )
    record_assessment_scan(assessment_id, tool="katana", status="completed", finding_id=katana["id"])
    playwright = add_finding(
        user_id=user_id,
        finding={
            "source": "playwright",
            "target": "https://www.example.com/",
            "status": "completed",
            "playwright_observation": {
                "requested_url": "https://example.com/",
                "final_url": "https://www.example.com/",
                "status_code": 200,
                "load_status": "loaded",
                "forms_count": 0,
                "inputs_count": 12,
                "links_count": 56,
                "network_events": [{"url": "https://www.example.com/", "status": 200}],
                "console_issue_count": 8,
                "network_issue_count": 0,
                "page_error_count": 0,
                "screenshot": {"path": "screenshots/example.png"},
            },
        },
    )
    record_assessment_scan(assessment_id, tool="playwright", status="completed", finding_id=playwright["id"])
    ffuf = add_finding(
        user_id=user_id,
        finding={
            "source": "ffuf",
            "target": "https://www.example.com/",
            "status": "completed",
            "ffuf_results": [{"path": "/about", "status": 200, "size": 1234}],
            "ffuf_summary": {"result_count": 1, "status_codes": {"200": 1}},
            "metadata": {"ffuf_profile_label": "small web profile", "wordlist_count": 100},
        },
    )
    record_assessment_scan(assessment_id, tool="ffuf", status="completed", finding_id=ffuf["id"])
    nuclei = add_finding(
        user_id=user_id,
        finding={
            "source": "nuclei",
            "target": "https://www.example.com/",
            "status": "completed",
            "nuclei_findings": [
                {"template_id": "waf-detect", "name": "WAF Detection", "severity": "info"},
                {"template_id": "http-missing-security-headers", "name": "HTTP Missing Security Headers", "severity": "info"},
            ],
        },
    )
    record_assessment_scan(assessment_id, tool="nuclei", status="completed", finding_id=nuclei["id"])
    testssl = add_finding(
        user_id=user_id,
        finding={
            "source": "testssl",
            "target": "https://www.example.com/",
            "status": "completed",
            "testssl_findings": [
                {"id": "TLS1_3", "severity": "OK", "finding": "TLS 1.3 offered"},
                {"id": "cert_commonName", "severity": "INFO", "finding": "www.example.com"},
            ],
        },
    )
    record_assessment_scan(assessment_id, tool="testssl", status="completed", finding_id=testssl["id"])
    bbot = add_finding(
        user_id=user_id,
        finding={
            "source": "bbot",
            "target": "example.com",
            "status": "completed",
            "finding_count": 37,
            "bbot_observations": [
                {"observation_type": "subdomain", "value": "www.example.com"},
                {"observation_type": "ip_address", "value": "192.0.2.10"},
                {"observation_type": "dns_record", "value": "www.example.com A 192.0.2.10"},
            ],
        },
    )
    record_assessment_scan(assessment_id, tool="bbot", status="completed", finding_id=bbot["id"])


def test_referential_confidence_followup_inherits_nuclei_scope_and_stays_bounded() -> None:
    user_id = 1101
    assessment = create_assessment("Follow-up scope", user_id=user_id)
    add_assessment_target(assessment["id"], "example.com")
    tools = ["nmap", "httpx", "nuclei", "katana", "playwright", "ffuf", "testssl", "bbot", "gitleaks", "prowler", "metasploit", "tshark"]
    for index, tool in enumerate(tools):
        finding = add_finding(
            user_id=user_id,
            finding={
                "source": tool,
                "target": "example.com",
                "summary": f"UNRELATED-{tool}-EVIDENCE " + ("x" * 900),
                "nuclei_findings": [{"name": "Weak HSTS", "template_id": "weak-hsts", "severity": "info"}]
                if tool == "nuclei" else [],
            },
        )
        record_assessment_scan(assessment["id"], tool=tool, status="completed", finding_id=finding["id"])

    conversation = create_conversation(assessment["id"], user_id, "Scoped follow-up")
    for index in range(2):
        append_message(conversation["id"], user_id, "user", f"Older unrelated question {index}")
        append_message(conversation["id"], user_id, "assistant", f"Older unrelated answer {index}")
    first_question = "Explain why the Weak HSTS Nuclei match matters in this assessment."
    append_message(conversation["id"], user_id, "user", first_question)
    append_message(conversation["id"], user_id, "assistant", "It is an INFO template observation requiring validation.")
    follow_up = "How confident should I be in that conclusion, and why?"
    append_message(conversation["id"], user_id, "user", follow_up)

    context = build_assessment_conversation_context(
        user_id=user_id, assessment_id=assessment["id"], conversation_id=conversation["id"], question=follow_up,
    )
    prompt = build_assessment_conversation_prompt(context)

    assert context["selection"] == {
        "mode": "tool_relevant", "selected_tools": ["nuclei"], "inherited_evidence_scope": True,
    }
    assert context["provenance"]["evidence_counts"]["scans"] == 1
    assert context["provenance"]["evidence_counts"]["findings"] == 1
    assert "Weak HSTS" in prompt and first_question in prompt and follow_up in prompt
    assert "UNRELATED-nmap-EVIDENCE" not in prompt
    assert "UNRELATED-httpx-EVIDENCE" not in prompt
    assert len(prompt) <= ASSESSMENT_PROMPT_MAX_CHARS

    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=conversation["id"],
            question=follow_up,
        )

    ask_ai.assert_not_called()
    assert "moderate-to-high confidence" in result["answer"]
    assert "Interpretation confidence: lower" in result["answer"]
    assert "Exploitability confidence: not established" in result["answer"]
    assert "practical attack path" in result["answer"]
    assert result["instrumentation"]["inherited_evidence_scope"] is True
    assert result["instrumentation"]["prompt_budget_input_tokens"] == 2800
    assert result["instrumentation"]["prompt_chars"] == 0
    assert result["instrumentation"]["output_token_budget"] == 0


def test_broad_assessment_highlight_synthesizes_multiple_tools_risks_and_gaps() -> None:
    user_id = 1105
    assessment = create_assessment("Broad synthesis", user_id=user_id)
    fixtures = {
        "nmap": {"open_ports": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]},
        "httpx": {"httpx_services": [{"url": "https://example.com", "status_code": 200, "technologies": ["Example CMS"]}]},
        "nuclei": {"nuclei_findings": [{"name": "Weak HSTS", "template_id": "weak-hsts", "severity": "info"}]},
        "katana": {"katana_observations": [{"url": "https://example.com/", "depth": 0}]},
        "playwright": {"playwright_observation": {"final_url": "https://example.com/", "inputs_count": 12, "links_count": 56, "network_events_count": 25}},
        "ffuf": {"ffuf_results": [], "metadata": {"ffuf_profile_label": "Standard", "wordlist_count": 2570}},
    }
    for tool, evidence in fixtures.items():
        finding = add_finding(user_id=user_id, finding={"source": tool, "target": "example.com", **evidence})
        record_assessment_scan(assessment["id"], tool=tool, status="completed", finding_id=finding["id"])
    record_assessment_scan(assessment["id"], tool="testssl", status="failed")
    record_assessment_scan(assessment["id"], tool="tshark", status="partial")

    question = "Looking across the entire assessment, what stands out, what are the biggest risks, and what important gaps remain?"
    context = build_assessment_conversation_context(user_id=user_id, assessment_id=assessment["id"], question=question)
    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question=question,
        )

    answer = result["answer"]
    ask_ai.assert_not_called()
    assert context["selection"]["mode"] == "full_assessment"
    assert all(marker in answer for marker in ("What stands out", "Nmap", "httpx", "Nuclei", "Katana", "Playwright", "ffuf"))
    assert "Weak HSTS" in answer and "INFO" in answer
    assert "zero observations do not prove hidden content is absent" in answer
    assert "testssl=FAILED" in answer
    assert "tshark=PARTIAL" in answer
    assert "applicable NOT_RUN coverage bbot" in answer
    assert "none of these observations alone establishes a confirmed vulnerability" in answer
    assert "Important evidence/coverage gaps" in answer
    assert "Sensible next validation steps" in answer
    assert result["instrumentation"]["ai_ms"] == 0.0

    risk_question = "What are the biggest risks?"
    risk_context = build_assessment_conversation_context(
        user_id=user_id, assessment_id=assessment["id"], question=risk_question,
    )
    with patch("app.services.assessment_conversation_ai.ask_ai") as risk_ai:
        risk_result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question=risk_question,
        )
    risk_ai.assert_not_called()
    assert risk_context["question_intent"] == "assessment_highlight"
    assert all(tool in risk_result["answer"] for tool in ("Nmap", "Nuclei", "Katana", "Playwright", "ffuf"))


def test_live_secure_concern_and_next_step_sequence_stays_deterministic() -> None:
    user_id = 1110
    assessment = create_assessment("Concern routing sequence", user_id=user_id)
    conversation = create_conversation(assessment["id"], user_id)
    finding = add_finding(
        user_id=user_id,
        finding={"source": "nmap", "target": "example.com", "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}]},
    )
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id=finding["id"])
    questions = ("so are we secure?", "anything I should be worried about?", "what will i try next")
    answers = []

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        for question in questions:
            result = answer_assessment_conversation_question(
                user_id=user_id,
                assessment_id=assessment["id"],
                conversation_id=conversation["id"],
                question=question,
            )
            answers.append(result["answer"])
            append_message(conversation["id"], user_id, "user", question)
            append_message(conversation["id"], user_id, "assistant", result["answer"])

    model.assert_not_called()
    assert "not enough to conclude" in answers[0].lower()
    assert "what stands out" in answers[1].lower()
    assert "nmap" in answers[1].lower() and "vulnerability" in answers[1].lower()
    assert "httpx next" in answers[2].lower()
    assert "no tool has been run" in answers[2].lower()


@pytest.mark.parametrize(
    ("question", "expected_intent"),
    [
        ("anything I should be worried about?", "assessment_highlight"),
        ("should I be worried about anything?", "assessment_highlight"),
        ("what should concern me?", "assessment_highlight"),
        ("what are the main concerns?", "assessment_highlight"),
        ("what will I try next?", "next_step_recommendation"),
        ("what should I try next?", "next_step_recommendation"),
        ("what do I run next?", "next_step_recommendation"),
        ("wat should i try nxt?", "next_step_recommendation"),
    ],
)
def test_casual_concern_and_next_step_variants_use_deterministic_routes(question: str, expected_intent: str) -> None:
    user_id = 1111
    assessment = create_assessment("Standalone intent variants", user_id=user_id)
    finding = add_finding(
        user_id=user_id,
        finding={"source": "nmap", "target": "example.com", "open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}]},
    )
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id=finding["id"])
    context = build_assessment_conversation_context(user_id=user_id, assessment_id=assessment["id"], question=question)

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question=question,
        )

    assert context["question_intent"] == expected_intent
    assert result["answer"] != TRUTHFULNESS_FALLBACK_ANSWER
    assert "gitleaks" not in result["answer"].lower() or "not automatic" in result["answer"].lower()
    assert "prowler" not in result["answer"].lower() or "not automatic" in result["answer"].lower()
    model.assert_not_called()


@pytest.mark.parametrize(
    "question",
    [
        "Which tools completed, failed, timed out or were not run?",
        "Which tools completed?",
        "What failed?",
        "What timed out?",
        "Which tools were not run?",
        "What was or was not run?",
        "Show scan statuses",
        "What is the assessment coverage/status?",
    ],
)
def test_tool_status_inventory_questions_are_deterministic_and_precede_recommendations(question: str) -> None:
    user_id = 1114
    assessment = create_assessment("Mixed tool status inventory", user_id=user_id)
    for tool, status in (
        ("nmap", "completed"),
        ("httpx", "partial"),
        ("testssl", "timed_out"),
        ("bbot", "failed"),
        ("ffuf", "cancelled"),
        ("katana", "interrupted"),
    ):
        record_assessment_scan(assessment["id"], tool=tool, status=status)

    context = build_assessment_conversation_context(
        user_id=user_id, assessment_id=assessment["id"], question=question,
    )
    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question=question,
        )

    assert context["question_intent"] == "tool_state_overview"
    answer = result["answer"]
    assert "Completed: Nmap." in answer
    assert "Partial: httpx." in answer
    assert "Timed out: testssl.sh." in answer
    assert "Failed: BBOT." in answer
    assert "Cancelled: ffuf." in answer
    assert "Interrupted: Katana." in answer
    assert "Not run: Nuclei, Playwright, Gitleaks, Prowler, Metasploit, TShark." in answer
    assert "completion does not establish security" in answer.lower()
    assert "does not recommend or execute another tool" in answer.lower()
    model.assert_not_called()


@pytest.mark.parametrize(
    "question",
    [
        "What should I run next?",
        "Which missing tool should I use?",
    ],
)
def test_explicit_next_tool_questions_remain_recommendations(question: str) -> None:
    user_id = 1115
    assessment = create_assessment("Explicit next tool routing", user_id=user_id)
    finding = add_finding(
        user_id=user_id,
        finding={"source": "nmap", "target": "example.com", "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}]},
    )
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id=finding["id"])

    context = build_assessment_conversation_context(
        user_id=user_id, assessment_id=assessment["id"], question=question,
    )
    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question=question,
        )

    assert context["question_intent"] == "next_step_recommendation"
    assert "httpx next" in result["answer"].lower()
    assert "no tool has been run" in result["answer"].lower()
    model.assert_not_called()


@pytest.mark.parametrize(
    "question",
    ["Which concern should I prioritize?", "What risk needs attention first?"],
)
def test_rejected_prioritization_generation_recovers_with_bounded_assessment_synthesis(question: str) -> None:
    user_id = 1112
    assessment = create_assessment("Rejected prioritization recovery", user_id=user_id)
    finding = add_finding(
        user_id=user_id,
        finding={"source": "nmap", "target": "example.com", "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}]},
    )
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="The target is secure and has no vulnerabilities.") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question=question,
        )

    model.assert_not_called()
    assert "What stands out" in result["answer"]
    assert "22/tcp" in result["answer"]
    assert "establishes a confirmed vulnerability" in result["answer"]
    assert result["answer"] != TRUTHFULNESS_FALLBACK_ANSWER


def test_rejected_next_action_generation_recovers_without_second_model_call() -> None:
    user_id = 1113
    assessment = create_assessment("Rejected next action recovery", user_id=user_id)

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Run every scanner; this proves the target is secure.") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Where should we go from here?",
        )

    model.assert_not_called()
    assert "does not identify another automatically required tool" in result["answer"]
    assert "executes nothing" in result["answer"]
    assert result["answer"] != TRUTHFULNESS_FALLBACK_ANSWER


def test_rejected_security_and_confidence_intents_use_existing_deterministic_calibration() -> None:
    security = _recover_rejected_assessment_answer(
        {
            "question_intent": "uncertainty_safety",
            "uncertainty_subtype": "overall_security",
            "recommendation_context": {"tool_states": {}},
        }
    )
    confidence = _recover_rejected_assessment_answer(
        {
            "question_intent": "follow_up_reference",
            "current_question": "How strong is that evidence?",
            "selection": {"inherited_evidence_scope": True, "selected_tools": ["nuclei"]},
            "recommendation_context": {"tool_states": {"nuclei": "COMPLETED"}},
            "assessment_context": {
                "findings": [{"source": "nuclei", "nuclei_findings": [{"name": "Stored template", "severity": "info"}]}]
            },
        }
    )

    assert security is not None and "not enough to conclude" in security
    assert confidence is not None and "Evidence confidence" in confidence
    assert "Exploitability confidence: not established" in confidence


def test_rejected_live_evidence_review_question_recovers_with_grounded_next_step() -> None:
    user_id = 1114
    assessment = create_assessment("Rejected live evidence recovery", user_id=user_id)
    _add_nmap_scan(assessment["id"], user_id=user_id, port=80, service="http")

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="The target is vulnerable and compromised.") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Ok, looking at the evidence we have, is there anything worth investigating further?",
        )

    model.assert_called_once()
    assert result["fallback_reason"] == "grounded_conversation_fallback"
    assert "What stands out" in result["answer"]
    assert "80/tcp" in result["answer"]
    assert "httpx next" in result["answer"].lower()
    assert "not evidence of a vulnerability" in result["answer"].lower() or "not proof" in result["answer"].lower()
    assert "compromised" not in result["answer"].lower()


def test_rejected_assessment_wide_findings_summary_recovers_from_stored_evidence() -> None:
    user_id = 1115
    assessment = create_assessment("Rejected summary recovery", user_id=user_id)
    _add_nmap_scan(assessment["id"], user_id=user_id, port=443, service="https")

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Nmap proved the site is vulnerable.") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What did we find?",
        )

    model.assert_called_once()
    assert result["fallback_reason"] == "grounded_conversation_fallback"
    assert "Nmap recorded exposed TCP services" in result["answer"]
    assert "443/tcp" in result["answer"]
    assert "site is vulnerable" not in result["answer"].lower()


@pytest.mark.parametrize(
    "question",
    [
        "What have we actually found so far?",
        "What the fuck have we actually found so far?",
        "So what have we found?",
    ],
)
def test_rejected_summary_recovery_tolerates_casual_filler_and_profanity(question: str) -> None:
    user_id = 1122
    assessment = create_assessment("Rejected casual summary recovery", user_id=user_id)
    _add_nmap_scan(assessment["id"], user_id=user_id, port=443, service="https")
    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=None,
        question=question,
    )

    answer = _recover_rejected_assessment_answer(context)

    assert answer is not None
    assert "Nmap recorded exposed TCP services" in answer
    assert "443/tcp" in answer
    assert answer != TRUTHFULNESS_FALLBACK_ANSWER


@pytest.mark.parametrize(
    "question",
    [
        "What have we actually found so far?",
        "What the fuck have we actually found so far?",
        "So what have we found?",
        "ok please just what do we actually know?",
    ],
)
def test_shared_intent_normalization_routes_casual_summary_questions(question: str) -> None:
    assert classify_assessment_conversation_intent(question) == "assessment_summary"


def test_unrelated_profanity_does_not_become_primary_summary_intent() -> None:
    assert classify_assessment_conversation_intent("This is fucked.") == "current_assessment_evidence"


def test_live_shaped_eight_tool_summary_is_deterministic_and_cross_tool_grounded() -> None:
    user_id = 1124
    assessment = create_assessment("Live broad synthesis", user_id=user_id)
    add_assessment_target(assessment["id"], "example.com")
    _add_eight_tool_web_assessment(assessment["id"], user_id=user_id)

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What the fuck have we actually found so far?",
        )

    model.assert_not_called()
    answer = result["answer"]
    assert result["fallback_reason"] is None
    assert "Nmap recorded exposed TCP services" in answer
    assert "httpx recorded HTTP(S) response metadata" in answer
    assert "redirect https://www.example.com/" in answer
    assert "Katana stored" in answer
    assert "Playwright recorded passive browser state" in answer
    assert "ffuf stored" in answer
    assert "Nuclei stored" in answer
    assert "testssl.sh stored" in answer
    assert "BBOT stored" in answer
    assert "BBOT stored 37 reconnaissance observation item(s), including dns_record=1, ip_address=1, subdomain=1" in answer
    assert "unencrypted web service" not in answer.lower()
    assert "low-risk" not in answer.lower()
    assert "redirect traffic to https" not in answer.lower()
    assert "is vulnerable" not in answer.lower()
    assert "confirmed vulnerability" not in answer.lower()


def test_bbot_exact_ip_question_does_not_substitute_nearby_observation() -> None:
    user_id = 1125
    assessment = create_assessment("BBOT exact indicator", user_id=user_id)
    add_assessment_target(assessment["id"], "btjoinery.ie")
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "bbot",
            "target": "btjoinery.ie",
            "status": "completed",
            "observations": [{"observation_type": "ip_address", "value": "198.185.159.144"}],
        },
    )
    record_assessment_scan(assessment["id"], tool="bbot", status="completed", finding_id=finding["id"])

    absent = answer_assessment_conversation_question(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=None,
        question="Did BBOT observe 198.185.159.0?",
    )
    present = answer_assessment_conversation_question(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=None,
        question="Did BBOT observe 198.185.159.144?",
    )

    assert absent["answer"].startswith("No.")
    assert "198.185.159.0" in absent["answer"]
    assert "198.185.159.144" not in absent["answer"]
    assert present["answer"].startswith("Yes.")
    assert "198.185.159.144" in present["answer"]


def test_bbot_exact_ip_questions_retain_real_bounded_observation_shape() -> None:
    user_id = 1126
    assessment = create_assessment("BBOT bounded observations", user_id=user_id)
    add_assessment_target(assessment["id"], "btjoinery.ie")
    observations = [
        {"observation_type": "subdomain", "value": f"host-{index}.btjoinery.ie"}
        for index in range(11)
    ]
    observations.append({"observation_type": "ip_address", "value": "198.185.159.144"})
    observations.append({"observation_type": "dns_record", "value": "btjoinery.ie A 198.185.159.144"})
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "bbot",
            "target": "btjoinery.ie",
            "status": "completed",
            "finding_count": len(observations),
            "observations": observations,
            "observation_counts": {"subdomain": 11, "ip_address": 1, "dns_record": 1},
            "metadata": {"observation_count": len(observations)},
        },
    )
    record_assessment_scan(assessment["id"], tool="bbot", status="completed", finding_id=finding["id"])
    conversation = create_conversation(assessment["id"], user_id, "BBOT exact indicator")
    first_question = "Did BBOT observe 198.185.159.144?"
    append_message(conversation["id"], user_id, "user", first_question)

    present = answer_assessment_conversation_question(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=conversation["id"],
        question=first_question,
    )
    append_message(conversation["id"], user_id, "assistant", present["answer"])
    second_question = "Did BBOT observe 198.185.159.0?"
    append_message(conversation["id"], user_id, "user", second_question)
    absent = answer_assessment_conversation_question(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=conversation["id"],
        question=second_question,
    )

    assert present["answer"].startswith("Yes.")
    assert "198.185.159.144" in present["answer"]
    assert absent["answer"].startswith("No.")
    assert "198.185.159.0" in absent["answer"]
    assert "198.185.159.144" not in absent["answer"]


def test_nuclei_summary_uses_persisted_aggregate_counts_after_context_caps_list() -> None:
    user_id = 1128
    assessment = create_assessment("Nuclei aggregate budget", user_id=user_id)
    nuclei_findings = (
        [{"name": "HTTP Missing Security Headers", "severity": "info"}] * 10
        + [
            {"name": "WAF Detection", "severity": "info"},
            {"name": "Microsoft Azure Domain Tenant ID", "severity": "info"},
        ]
    )
    finding = add_finding(
        user_id=user_id,
        finding={
            "source": "nuclei",
            "target": "example.com",
            "status": "completed",
            "finding_count": 12,
            "severity_summary": {"critical": 0, "high": 0, "info": 12, "low": 0, "medium": 0},
            "nuclei_findings": nuclei_findings,
        },
    )
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=finding["id"])

    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=None,
        question="What have we actually found so far?",
    )
    stored = context["assessment_context"]["findings"][0]
    assert len(stored["nuclei_findings"]) == 10
    assert stored["nuclei_template_counts"] == {
        "HTTP Missing Security Headers": 10,
        "WAF Detection": 1,
        "Microsoft Azure Domain Tenant ID": 1,
    }

    result = answer_assessment_conversation_question(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=None,
        question="What have we actually found so far?",
    )
    answer = result["answer"]
    assert "Nuclei stored 12 template match(es)" in answer
    assert "aggregate severity INFO=12" in answer
    assert "HTTP Missing Security Headers=10" in answer
    assert "WAF Detection=1" in answer
    assert "Microsoft Azure Domain Tenant ID=1" in answer


def test_summary_plus_next_step_uses_synopsis_without_forcing_redirect_remediation() -> None:
    user_id = 1125
    assessment = create_assessment("Live broad synthesis next", user_id=user_id)
    add_assessment_target(assessment["id"], "example.com")
    _add_eight_tool_web_assessment(assessment["id"], user_id=user_id)

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What have we actually found so far, and what should we investigate next?",
        )

    model.assert_not_called()
    answer = result["answer"]
    assert "Nmap recorded exposed TCP services" in answer
    assert "httpx recorded HTTP(S) response metadata" in answer
    assert "redirect https://www.example.com/" in answer
    assert "redirect traffic to HTTPS" not in answer
    assert "Suitable remaining investigation options" not in answer


def test_bad_live_broad_summary_is_rejected_and_recovers_to_grounded_summary() -> None:
    user_id = 1126
    assessment = create_assessment("Bad live summary recovery", user_id=user_id)
    add_assessment_target(assessment["id"], "example.com")
    _add_eight_tool_web_assessment(assessment["id"], user_id=user_id)
    bad_answer = (
        "So far, we have found a low-risk open port on the target `example.com` (192.0.2.10), "
        "specifically port `80/tcp` for HTTP. This indicates that an unencrypted web service is exposed.\n\n"
        "The recommendation based on this finding is to redirect traffic to HTTPS and review the exposed web application functionality."
    )

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=bad_answer):
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Compare what we have found so far.",
        )

    assert result["fallback_reason"] == "grounded_conversation_fallback"
    answer = result["answer"]
    assert "Nmap recorded exposed TCP services" in answer
    assert "httpx recorded HTTP(S) response metadata" in answer
    assert "Katana stored" in answer
    assert "low-risk" not in answer.lower()
    assert "unencrypted web service" not in answer.lower()
    assert "redirect traffic to https" not in answer.lower()


def test_broad_prompt_budget_preserves_compact_synopsis() -> None:
    user_id = 1127
    assessment = create_assessment("Broad synopsis budget", user_id=user_id)
    add_assessment_target(assessment["id"], "example.com")
    _add_eight_tool_web_assessment(assessment["id"], user_id=user_id)
    for index in range(12):
        finding = add_finding(user_id=user_id, finding={
            "source": f"noise-{index}",
            "target": "example.com",
            "observations": ["bulk " + ("x" * 1600)] * 10,
        })
        record_assessment_scan(assessment["id"], tool=f"noise-{index}", status="completed", finding_id=finding["id"])

    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=None,
        question="Give me a broad assessment-wide review of the evidence and priorities.",
    )
    budgeted, _ = _apply_prompt_budget(context, _build_prompt_context(context))
    prompt = build_assessment_conversation_prompt(context, prompt_context=budgeted)

    assert len(prompt) <= ASSESSMENT_PROMPT_MAX_CHARS
    synopsis = json.dumps(budgeted.get("assessment_evidence_synopsis") or [], default=str)
    assert "Nmap recorded exposed TCP services" in synopsis
    assert "httpx recorded HTTP(S) response metadata" in synopsis


def test_unrelated_profanity_does_not_become_summary_recovery_intent() -> None:
    user_id = 1123
    assessment = create_assessment("Rejected unrelated profanity recovery", user_id=user_id)
    _add_nmap_scan(assessment["id"], user_id=user_id, port=443, service="https")
    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=None,
        question="This is fucked.",
    )

    answer = _recover_rejected_assessment_answer(context)

    assert answer is None


def test_rejected_coverage_and_gap_questions_recover_from_tool_state() -> None:
    user_id = 1116
    assessment = create_assessment("Rejected coverage recovery", user_id=user_id)
    _add_nmap_scan(assessment["id"], user_id=user_id, port=80, service="http")

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Everything has been tested and the target is secure."):
        tested = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question="What have we tested?",
        )
    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Nothing else needs testing."):
        gaps = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question="What haven't we tested?",
        )

    assert tested["fallback_reason"] == "grounded_conversation_fallback"
    assert "Completed: Nmap" in tested["answer"]
    assert "Not run:" in tested["answer"]
    assert gaps["fallback_reason"] == "grounded_conversation_fallback"
    assert "Relevant uncompleted" in gaps["answer"]
    assert "Gitleaks and Prowler are context-dependent" in gaps["answer"]


def test_rejected_next_step_recovery_preserves_tool_suitability_rules() -> None:
    user_id = 1117
    assessment = create_assessment("Rejected next suitability recovery", user_id=user_id)
    _add_nmap_scan(assessment["id"], user_id=user_id, port=80, service="http")

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Run Prowler next to find website services."):
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question="What would be worth doing from here?",
        )

    assert result["fallback_reason"] == "grounded_conversation_fallback"
    assert "httpx next" in result["answer"].lower()
    assert "Prowler" not in result["answer"]
    assert "no tool has been run" in result["answer"].lower()


def test_rejected_tool_specific_followup_recovers_with_named_tool_state() -> None:
    user_id = 1118
    assessment = create_assessment("Rejected tool followup recovery", user_id=user_id)
    _add_nmap_scan(assessment["id"], user_id=user_id, port=80, service="http")

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="Nmap proved the service is exploitable."):
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question="What did Nmap find?",
        )

    assert result["fallback_reason"] is None
    assert "80/tcp" in result["answer"]
    assert "did not establish vulnerability" in result["answer"]
    assert "exploitable" not in result["answer"].lower()


def test_rejected_unsupported_security_exploit_and_compromise_claims_are_corrected() -> None:
    user_id = 1119
    assessment = create_assessment("Rejected unsafe conclusion recovery", user_id=user_id)
    _add_nmap_scan(assessment["id"], user_id=user_id, port=22, service="ssh")

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="The host is exploitable and compromised."):
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=None, question="What did we find?",
        )

    assert result["fallback_reason"] == "grounded_conversation_fallback"
    assert "22/tcp" in result["answer"]
    assert "exploitable" not in result["answer"].lower()
    assert "compromised" not in result["answer"].lower()


def test_rejected_response_without_assessment_evidence_still_uses_generic_withheld_message() -> None:
    user_id = 1120
    assessment = create_assessment("Rejected insufficient recovery", user_id=user_id)

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="The target is vulnerable and compromised.") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Ok, looking at the evidence we have, is there anything worth investigating further?",
        )

    model.assert_called_once()
    assert result["fallback_reason"] == "truthfulness_guard"
    assert result["answer"] == TRUTHFULNESS_FALLBACK_ANSWER


def test_tls_referent_uses_authoritative_testssl_records_concisely() -> None:
    user_id = 1122
    assessment = create_assessment("TLS referent", user_id=user_id)
    finding = add_finding(user_id=user_id, finding={
        "source": "testssl", "target": "btjoinery.ie:443", "status": "completed", "finding_count": 9,
        "testssl_summary": {
            "notable_count": 9, "supported_protocols": ["TLS 1.2", "TLS 1.3"], "weak_protocol_count": 0,
        },
        "testssl_evidence": {
            "target": "btjoinery.ie:443", "host": "btjoinery.ie", "port": 443, "scan_status": "completed",
            "protocols": [
                {"id": "TLS1_2", "name": "TLS 1.2", "finding": "offered", "severity": "OK"},
                {"id": "TLS1_3", "name": "TLS 1.3", "finding": "offered with final", "severity": "OK"},
            ],
            "certificate": {"common_name": "btjoinery.ie", "not_after": "2026-11-27 14:05"},
            "vulnerabilities": [
                {"id": "LUCKY13", "severity": "LOW", "finding": "potentially vulnerable"},
                {"id": "wildcard-trust", "severity": "LOW", "finding": "wildcard trust"},
                {"id": "QUIC", "severity": "WARN", "finding": "not tested"},
            ],
            "cipher_findings": [
                {"id": "obsolete-cipher-list", "severity": "LOW", "finding": "obsolete cipher-list"},
            ] + [{"id": f"record-{index}", "severity": "INFO", "finding": "stored observation"} for index in range(5)],
            "security_headers": [{"id": f"header-{index}", "severity": "OK", "finding": "stored check"} for index in range(11)],
        },
    })
    record_assessment_scan(assessment["id"], tool="testssl", status="completed", finding_id=finding["id"])
    conversation = create_conversation(assessment["id"], user_id)
    append_message(conversation["id"], user_id, "user", "What did testssl report?")
    append_message(conversation["id"], user_id, "assistant", "The TLS observations need review.")

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=user_id, assessment_id=assessment["id"], conversation_id=conversation["id"],
            question="What about that TLS thing?",
        )

    model.assert_not_called()
    assert "9 authoritative normalized scanner record(s)" in result["answer"]
    assert "20 normalized scanner record(s)" not in result["answer"]
    assert "LUCKY13" in result["answer"]
    assert "overall TLS security" in result["answer"]
    assert len(result["answer"]) < 900


def test_testssl_authoritative_count_prefers_persisted_aggregate_over_display_lists() -> None:
    findings = [{
        "finding_count": 9,
        "testssl_summary": {"notable_count": 4, "weak_protocol_count": 1},
        "testssl_evidence": {"vulnerabilities": [{} for _ in range(20)]},
    }]
    assert _testssl_authoritative_count(findings) == 9
    assert _testssl_authoritative_count([{
        "testssl_summary": {"notable_count": 8, "weak_protocol_count": 1},
        "testssl_evidence": {"vulnerabilities": [{} for _ in range(20)]},
    }]) == 9
    assert _testssl_authoritative_count([{
        "testssl_evidence": {"vulnerabilities": [{} for _ in range(20)]},
    }]) is None


def test_cross_tool_tls_confirmation_uses_same_authoritative_testssl_count() -> None:
    user_id = 1126
    assessment = create_assessment("TLS cross count", user_id=user_id)
    testssl = add_finding(user_id=user_id, finding={
        "source": "testssl", "target": "example.test", "finding_count": 9,
        "testssl_summary": {"notable_count": 9, "weak_protocol_count": 0},
        "testssl_evidence": {"vulnerabilities": [{"id": f"record-{index}"} for index in range(20)]},
    })
    httpx = add_finding(user_id=user_id, finding={
        "source": "httpx", "target": "example.test", "httpx_services": [{"url": "https://example.test", "tls": {"version": "TLS1.3"}}],
    })
    record_assessment_scan(assessment["id"], tool="testssl", status="completed", finding_id=testssl["id"])
    record_assessment_scan(assessment["id"], tool="httpx", status="completed", finding_id=httpx["id"])
    conversation = create_conversation(assessment["id"], user_id)
    append_message(conversation["id"], user_id, "user", "What did testssl report?")
    append_message(conversation["id"], user_id, "assistant", "The TLS observations need review.")

    result = answer_assessment_conversation_question(
        user_id=user_id, assessment_id=assessment["id"], conversation_id=conversation["id"],
        question="Did anything else confirm that?",
    )

    assert "9 normalized TLS scanner record(s)" in result["answer"]
    assert "20 normalized TLS scanner record(s)" not in result["answer"]


@pytest.mark.parametrize("claim", [
    "testssl found no notable findings.",
    "TLS 1.2 is supported and is not weak.",
    "The certificate is valid and trusted.",
    "I recommend httpx for more investigation.",
])
def test_testssl_followup_truthfulness_rejects_unsupported_claims(claim: str) -> None:
    user_id = 1123
    assessment = create_assessment("TLS truth guard", user_id=user_id)
    finding = add_finding(user_id=user_id, finding={
        "source": "testssl", "target": "example.test", "testssl_findings": [
            {"id": "LUCKY13", "severity": "LOW", "finding": "potentially vulnerable"},
        ],
    })
    record_assessment_scan(assessment["id"], tool="testssl", status="completed", finding_id=finding["id"])
    httpx = add_finding(user_id=user_id, finding={"source": "httpx", "target": "example.test", "httpx_services": []})
    record_assessment_scan(assessment["id"], tool="httpx", status="completed", finding_id=httpx["id"])
    context = build_assessment_conversation_context(
        user_id=user_id, assessment_id=assessment["id"], question="What about that TLS thing?",
    )
    assert violates_conversation_truthfulness(claim, context) is True


def test_cross_tool_tls_referent_distinguishes_related_evidence_from_confirmation() -> None:
    user_id = 1124
    assessment = create_assessment("TLS cross tool", user_id=user_id)
    testssl = add_finding(user_id=user_id, finding={
        "source": "testssl", "target": "example.test", "testssl_findings": [{"id": "cipher", "severity": "LOW"}],
    })
    httpx = add_finding(user_id=user_id, finding={
        "source": "httpx", "target": "example.test", "httpx_services": [{"url": "https://example.test", "tls": {"version": "TLS1.3"}}],
    })
    record_assessment_scan(assessment["id"], tool="testssl", status="completed", finding_id=testssl["id"])
    record_assessment_scan(assessment["id"], tool="httpx", status="completed", finding_id=httpx["id"])
    conversation = create_conversation(assessment["id"], user_id)
    append_message(conversation["id"], user_id, "user", "What did testssl report?")
    append_message(conversation["id"], user_id, "assistant", "The TLS observation needs review.")

    result = answer_assessment_conversation_question(
        user_id=user_id, assessment_id=assessment["id"], conversation_id=conversation["id"],
        question="Did anything else confirm that?",
    )

    assert "No automatic confirmation" in result["answer"]
    assert "related evidence" in result["answer"]
    assert "confirmed" not in result["answer"].lower()


def test_coverage_followup_surfaces_completed_tool_limits() -> None:
    user_id = 1125
    assessment = create_assessment("Coverage limits", user_id=user_id)
    fixtures = {
        "katana": {"katana_observations": [{"url": "https://example.test/", "depth": 0}]},
        "playwright": {"playwright_observation": {"final_url": "https://example.test/", "inputs_count": 1, "links_count": 2, "network_events_count": 3}},
        "ffuf": {"ffuf_results": [], "metadata": {"ffuf_profile_label": "Standard", "wordlist_count": 2570}},
    }
    for tool, evidence in fixtures.items():
        finding = add_finding(user_id=user_id, finding={"source": tool, "target": "example.test", **evidence})
        record_assessment_scan(assessment["id"], tool=tool, status="completed", finding_id=finding["id"])

    result = answer_assessment_conversation_question(
        user_id=user_id, assessment_id=assessment["id"], conversation_id=None,
        question="What haven't we tested properly yet?",
    )

    assert "maximum observed depth was 0" in result["answer"]
    assert "Standard with 2570 entries" in result["answer"]
    assert "passive browser observation" in result["answer"]


def test_valid_generated_answer_is_not_replaced_by_recovery() -> None:
    user_id = 1121
    assessment = create_assessment("Valid qwen retained", user_id=user_id)
    _add_nmap_scan(assessment["id"], user_id=user_id, port=80, service="http")
    valid_answer = "Stored Nmap evidence records 80/tcp classified as http. That observation does not establish a vulnerability."

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value=valid_answer) as model:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Give me a concise note about the current evidence.",
        )

    model.assert_called_once()
    assert result["fallback_reason"] is None
    assert result["answer"] == valid_answer


def test_nuclei_template_match_cannot_be_rendered_as_causal_mitm_path() -> None:
    assessment = create_assessment("Nuclei causal guard", user_id=1106)
    finding = add_finding(user_id=1106, finding={
        "source": "nuclei", "target": "example.com",
        "nuclei_findings": [{"name": "Weak HSTS", "severity": "info"}],
    })
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=finding["id"])
    context = build_assessment_conversation_context(
        user_id=1106, assessment_id=assessment["id"], question="What does the Nuclei match mean?",
    )
    answer = "Nuclei stored a Weak HSTS match. It can lead to MITM attacks and enable a downgrade attack."

    assert violates_conversation_truthfulness(answer, context) is True


def test_genuinely_broad_remaining_gaps_question_keeps_assessment_wide_state() -> None:
    user_id = 1102
    assessment = create_assessment("Broad gaps", user_id=user_id)
    for tool in ("nmap", "httpx", "nuclei"):
        finding = add_finding(user_id=user_id, finding={"source": tool, "target": "example.com", "summary": tool})
        record_assessment_scan(assessment["id"], tool=tool, status="completed", finding_id=finding["id"])

    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment["id"],
        question="What are the biggest remaining gaps in this assessment?",
    )

    assert context["question_intent"] == "remaining_coverage_gaps"
    assert context["selection"]["mode"] == "full_assessment"
    assert context["selection"]["inherited_evidence_scope"] is False
    assert context["provenance"]["evidence_counts"]["scans"] == 3


def test_broad_prompt_budget_prioritizes_severity_and_preserves_tool_coverage() -> None:
    user_id = 1103
    assessment = create_assessment("Importance-aware budget", user_id=user_id)
    info = add_finding(user_id=user_id, finding={
        "source": "nuclei", "target": "example.com",
        "nuclei_findings": [{"name": "Technology fingerprint", "severity": "info"}],
        "observations": ["low-value " + ("i" * 1100)] * 10,
    })
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=info["id"])
    high = add_finding(user_id=user_id, finding={
        "source": "nuclei", "target": "example.com",
        "nuclei_findings": [{"name": "Stored high-severity template", "severity": "high"}],
        "observations": ["direct evidence " + ("h" * 1100)] * 10,
    })
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=high["id"])
    for tool in ("nmap", "httpx", "katana", "playwright", "ffuf", "bbot"):
        finding = add_finding(user_id=user_id, finding={
            "source": tool, "target": "example.com", "observations": [f"{tool}-noise " + ("x" * 1100)] * 10,
        })
        record_assessment_scan(assessment["id"], tool=tool, status="completed", finding_id=finding["id"])
    record_assessment_scan(assessment["id"], tool="testssl", status="failed")

    context = build_assessment_conversation_context(
        user_id=user_id, assessment_id=assessment["id"],
        question="Give me a broad assessment-wide review of the evidence and priorities.",
    )
    budgeted, reduced = _apply_prompt_budget(context, _build_prompt_context(context))
    prompt = build_assessment_conversation_prompt(context, prompt_context=budgeted)
    findings = budgeted["stored_evidence"]["findings"]

    assert reduced is True
    rendered_findings = json.dumps(findings, default=str)
    assert "Stored high-severity template" in rendered_findings
    assert "Technology fingerprint" not in rendered_findings
    assert budgeted["tool_state"]["testssl"] == "FAILED"
    assert set((budgeted.get("tool_state") or {})) == {
        "nmap", "bbot", "nuclei", "httpx", "playwright", "katana", "ffuf", "testssl",
        "gitleaks", "prowler", "metasploit", "tshark",
    }
    decision_contract = budgeted.get("tool_decision_contract") or {}
    assert set(decision_contract).issubset({"preferred", "allowed", "blocked", "rules"})
    assert "prowler" in (decision_contract.get("blocked") or {})
    assert "prerequisites" not in json.dumps(decision_contract, default=str).lower()
    assert "limitations" not in json.dumps(decision_contract, default=str).lower()
    assert any(scan["tool"] == "testssl" and scan["status"] == "failed" for scan in budgeted["stored_evidence"]["scans"])
    assert len(prompt) <= ASSESSMENT_PROMPT_MAX_CHARS


def test_recommendation_prompt_budget_preserves_suitability_without_verbose_contract() -> None:
    user_id = 1103
    assessment = create_assessment("Recommendation budget", user_id=user_id)
    add_assessment_target(assessment["id"], "example.com")
    for tool in ("nmap", "nuclei", "bbot"):
        finding = add_finding(user_id=user_id, finding={
            "source": tool, "target": "example.com", "observations": [f"{tool}-noise " + ("x" * 1400)] * 12,
        })
        record_assessment_scan(assessment["id"], tool=tool, status="completed", finding_id=finding["id"])

    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment["id"],
        question="What should we investigate next?",
    )
    budgeted, _ = _apply_prompt_budget(context, _build_prompt_context(context))
    prompt = build_assessment_conversation_prompt(context, prompt_context=budgeted)
    contract = budgeted.get("tool_decision_contract") or {}

    assert len(prompt) <= ASSESSMENT_PROMPT_MAX_CHARS
    assert set((budgeted.get("tool_state") or {})) == {
        "nmap", "bbot", "nuclei", "httpx", "playwright", "katana", "ffuf", "testssl",
        "gitleaks", "prowler", "metasploit", "tshark",
    }
    assert set(contract).issubset({"preferred", "allowed", "blocked", "rules"})
    assert "prowler" in (contract.get("blocked") or {})


def test_prompt_budget_ultra_compact_fallback_still_preserves_state_and_failed_scan() -> None:
    user_id = 1103
    assessment = create_assessment("Ultra compact budget", user_id=user_id)
    high = add_finding(user_id=user_id, finding={
        "source": "nuclei", "target": "example.com",
        "nuclei_findings": [{"name": "Critical template", "severity": "critical", "description": "d" * 2000}],
        "observations": ["critical evidence " + ("z" * 2500)] * 25,
    })
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=high["id"])
    for tool in ("nmap", "httpx", "katana", "playwright", "ffuf", "bbot", "gitleaks", "prowler", "metasploit", "tshark"):
        finding = add_finding(user_id=user_id, finding={
            "source": tool, "target": "example.com", "observations": [f"{tool}-bulk " + ("y" * 2500)] * 25,
        })
        record_assessment_scan(assessment["id"], tool=tool, status="completed", finding_id=finding["id"])
    record_assessment_scan(assessment["id"], tool="testssl", status="failed")

    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment["id"],
        question="Give me a broad assessment-wide review of the evidence and priorities.",
    )
    budgeted, reduced = _apply_prompt_budget(context, _build_prompt_context(context))
    prompt = build_assessment_conversation_prompt(context, prompt_context=budgeted)

    assert reduced is True
    assert len(prompt) <= ASSESSMENT_PROMPT_MAX_CHARS
    assert set((budgeted.get("tool_state") or {})) == {
        "nmap", "bbot", "nuclei", "httpx", "playwright", "katana", "ffuf", "testssl",
        "gitleaks", "prowler", "metasploit", "tshark",
    }
    assert any(scan["tool"] == "testssl" and scan["status"] == "failed" for scan in budgeted["stored_evidence"]["scans"])
    assert "Critical template" in json.dumps(budgeted["stored_evidence"]["findings"], default=str)


def test_narrow_prompt_budget_uses_latest_authoritative_same_tool_run() -> None:
    user_id = 1104
    assessment = create_assessment("Reference-first budget", user_id=user_id)
    referenced = add_finding(user_id=user_id, finding={
        "source": "nuclei", "target": "example.com",
        "nuclei_findings": [{"name": "Weak HSTS", "template_id": "weak-hsts", "severity": "info"}],
        "observations": ["referenced " + ("r" * 1100)] * 10,
    })
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=referenced["id"])
    unrelated = add_finding(user_id=user_id, finding={
        "source": "nuclei", "target": "example.com",
        "nuclei_findings": [{"name": "Unrelated high item", "template_id": "other", "severity": "high"}],
        "observations": ["unrelated " + ("u" * 1100)] * 10,
    })
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=unrelated["id"])
    conversation = create_conversation(assessment["id"], user_id, "Reference priority")
    append_message(
        conversation["id"], user_id, "user",
        "Explain why the Weak HSTS Nuclei match matters in this assessment.",
    )
    append_message(
        conversation["id"], user_id, "assistant",
        "The stored Weak HSTS INFO match is an observation, not proof of exploitability.",
    )

    context = build_assessment_conversation_context(
        user_id=user_id, assessment_id=assessment["id"], conversation_id=conversation["id"],
        question="How confident should I be in that conclusion, and why?",
    )
    budgeted, reduced = _apply_prompt_budget(context, _build_prompt_context(context))
    rendered = json.dumps(budgeted["stored_evidence"]["findings"], default=str)
    prompt = build_assessment_conversation_prompt(context, prompt_context=budgeted)

    assert reduced is True
    assert "Weak HSTS" not in rendered
    assert "Unrelated high item" in rendered
    assert len(prompt) <= ASSESSMENT_PROMPT_MAX_CHARS


def _competition_final_conversation_fixture(user_id: int = 1200) -> dict:
    assessment = create_assessment("Collective answer projection", user_id=user_id)
    fixtures = {
        "nmap": {"open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}, {"port": 443, "protocol": "tcp", "service": "https"}]},
        "httpx": {"httpx_services": [{"url": "https://example.test", "status_code": 301}, {"url": "https://attempted.example"}]},
        "nuclei": {"nuclei_findings": [
            {"name": "Technology observation", "severity": "info"},
            {"name": "WAF detection", "severity": "info"},
            {"name": "Weak HSTS", "severity": "info"},
        ]},
        "katana": {"katana_observations": [{"url": "https://example.test/", "depth": 0}]},
        "playwright": {"playwright_observation": {"final_url": "https://example.test/", "status_code": 200, "forms_count": 0, "inputs_count": 12, "links_count": 4, "network_events_count": 8}},
        "ffuf": {"ffuf_results": [], "metadata": {"ffuf_profile_label": "Standard", "wordlist_count": 2570}},
        "testssl": {"testssl_evidence": {"target": "example.test", "protocols": [{"id": "TLS1_2", "finding": "offered"}]}},
        "metasploit": {"metasploit_evidence": {"module_executed": True, "validation_outcome": "DETECTED", "session_established": False}},
        "tshark": {"tshark_evidence": {"packet_count": 59, "byte_count": 6758, "observed_endpoints": [{"address": "203.0.113.10"}], "observed_protocols": [{"protocol": "TCP"}, {"protocol": "DNS"}, {"protocol": "HTTP"}], "http_observations": [{"method": "GET"}, {"status_code": 301}]}},
    }
    scans = {}
    for tool, evidence in fixtures.items():
        finding = add_finding(user_id=user_id, finding={"source": tool, "target": "example.test", **evidence})
        scans[tool] = record_assessment_scan(assessment["id"], tool=tool, status="completed", finding_id=finding["id"])
    record_assessment_scan(assessment["id"], tool="bbot", status="failed")
    return {"assessment": assessment, "scans": scans}


@pytest.mark.parametrize(
    "question, expected",
    [
        ("so are we secure?", "not enough to conclude"),
        ("anything I should be worried about?", "What stands out"),
        ("what should I try next?", "executes nothing"),
        ("what important gaps remain?", "coverage"),
        ("How strong is the evidence across this assessment?", "Evidence confidence"),
        ("What did Nuclei find?", "template matches"),
        ("Which concern should I prioritize?", "Priority interpretation"),
        ("What did the tools find?", "Nmap recorded"),
        ("What remains unknown?", "coverage"),
    ],
)
def test_core_assessment_intent_matrix_is_deterministic_and_useful(question: str, expected: str) -> None:
    fixture = _competition_final_conversation_fixture()
    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=1200, assessment_id=fixture["assessment"]["id"], conversation_id=None, question=question,
        )

    model.assert_not_called()
    assert result["answer"] != TRUTHFULNESS_FALLBACK_ANSWER
    assert expected.lower() in result["answer"].lower()
    assert "secure target" not in result["answer"].lower()


def test_canonical_projection_uses_latest_capture_not_later_related_artifact() -> None:
    fixture = _competition_final_conversation_fixture(user_id=1201)
    assessment_id = fixture["assessment"]["id"]
    old = add_finding(user_id=1201, finding={"source": "tshark", "target": "example.test", "tshark_evidence": {"packet_count": 7}})
    record_assessment_scan(assessment_id, tool="tshark", status="completed", finding_id=old["id"])
    latest = add_finding(user_id=1201, finding={"source": "tshark", "target": "example.test", "tshark_evidence": {"observed_protocols": [{"protocol": "TCP"}]}})
    latest_scan = record_assessment_scan(assessment_id, tool="tshark", status="partial", finding_id=latest["id"])
    add_assessment_artifact(
        assessment_id, scan_id=latest_scan["id"], artifact_type="tshark_normalized_evidence",
        title="Authoritative capture", content=json.dumps({"packet_count": 59, "observed_protocols": [{"protocol": "TCP"}]}),
    )
    add_assessment_artifact(
        assessment_id, scan_id=latest_scan["id"], artifact_type="tshark_metasploit_correlation_record",
        title="Later related record", content=json.dumps({"correlation_confidence": "high"}),
    )

    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=1201, assessment_id=assessment_id, conversation_id=None, question="What did TShark actually observe?",
        )

    model.assert_not_called()
    assert "captured 59 packets" in result["answer"]
    assert "7 packet" not in result["answer"]
    assert "captured 0" not in result["answer"]


def test_large_tshark_artifact_preserves_authoritative_capture_summary() -> None:
    user_id = 1204
    assessment = create_assessment("Large TShark capture", user_id=user_id)
    scan = record_assessment_scan(assessment["id"], "tshark", "completed")
    content = {
        "source": "tshark",
        "execution_status": "completed",
        "success": True,
        "packet_count": 2055,
        "byte_count": 7067089,
        "duration_seconds": 19.9,
        "capture_start": "1710000000.1",
        "capture_end": "1710000020.0",
        "observed_protocols": [
            {"protocol": f"protocol-{index}", "packet_count": index + 1}
            for index in range(30)
        ],
        "http_observations": [],
        "tls_observations": [{"sni": "example.test", "version": "TLS 1.3"}],
        "evidence_limitations": ["Capture scope limits conclusions."] * 30,
    }
    add_assessment_artifact(
        assessment["id"],
        scan_id=scan["id"],
        artifact_type="tshark_normalized_evidence",
        title="Large authoritative capture",
        content=json.dumps(content),
    )

    context = build_assessment_conversation_context(
        user_id=user_id,
        assessment_id=assessment["id"],
        question="What did TShark actually observe?",
    )
    stored = context["assessment_context"]["artifacts"][0]["content"]
    assert stored["packet_count"] == 2055
    assert stored["byte_count"] == 7067089
    assert stored["duration_seconds"] == 19.9

    result = answer_assessment_conversation_question(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=None,
        question="What did TShark actually observe?",
    )
    assert "captured 2055 packets (7067089 bytes)" in result["answer"]
    assert "capture duration 19.9s" in result["answer"]
    assert "packet count is unknown" not in result["answer"]


def test_tshark_ask_presentation_deduplicates_dns_and_formats_tls_versions() -> None:
    user_id = 1205
    assessment = create_assessment("TShark presentation", user_id=user_id)
    scan = record_assessment_scan(assessment["id"], "tshark", "completed")
    content = {
        "source": "tshark",
        "packet_count": 4,
        "byte_count": 400,
        "dns_observations": [
            {"query_name": "www.example.test"},
            {"query_name": "www.example.test"},
            {"query_name": "google.com"},
            {"query_name": "www.example.test"},
        ],
        "tls_observations": [
            {"sni": "example.test", "version": "0x0303"},
            {"sni": "unknown.test", "version": "0x9999"},
        ],
    }
    add_assessment_artifact(
        assessment["id"],
        scan_id=scan["id"],
        artifact_type="tshark_normalized_evidence",
        title="Presentation capture",
        content=json.dumps(content),
    )

    result = answer_assessment_conversation_question(
        user_id=user_id,
        assessment_id=assessment["id"],
        conversation_id=None,
        question="What did TShark actually observe?",
    )
    answer = result["answer"]
    assert "DNS names www.example.test, google.com" in answer
    assert answer.count("www.example.test") == 1
    assert "version TLS 1.2" in answer
    assert "version 0x9999" in answer
    assert "version TLS 1.2 handshake" not in answer
    assert "does not establish a completed TLS handshake" in answer
    assert "vulnerability, exploitation, or compromise" in answer


def test_missing_tshark_packet_count_remains_unknown_not_zero() -> None:
    assessment = create_assessment("Unknown capture count", user_id=1203)
    finding = add_finding(user_id=1203, finding={
        "source": "tshark", "target": "example.test",
        "tshark_evidence": {"observed_protocols": [{"protocol": "TCP"}]},
    })
    record_assessment_scan(assessment["id"], tool="tshark", status="partial", finding_id=finding["id"])

    result = answer_assessment_conversation_question(
        user_id=1203, assessment_id=assessment["id"], conversation_id=None,
        question="What did TShark actually observe?",
    )

    assert "packet count is unknown" in result["answer"]
    assert "captured 0" not in result["answer"]


def test_canonical_httpx_projection_does_not_promote_attempts_to_responses() -> None:
    fixture = _competition_final_conversation_fixture(user_id=1202)
    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=1202, assessment_id=fixture["assessment"]["id"], conversation_id=None,
            question="What did httpx actually observe?",
        )

    model.assert_not_called()
    assert "https://example.test; status 301" in result["answer"]
    assert "attempted.example" not in result["answer"]
