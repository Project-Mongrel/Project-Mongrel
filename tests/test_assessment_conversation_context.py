import json

import pytest

from app.services.assessment_context import build_assessment_context
from app.services.assessment_conversation_context import (
    build_assessment_conversation_context,
    classify_assessment_conversation_intent,
    classify_uncertainty_subtype,
    detect_question_tools,
)
from app.services.assessment_conversation_store import append_message, create_conversation, update_summary_status
from app.services.assessment_store import add_assessment_artifact, add_assessment_target, create_assessment, record_assessment_scan
from app.services.findings_store import add_finding, close_findings_database, configure_findings_database


@pytest.fixture(autouse=True)
def sqlite_assessment_conversation_context(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_owner_can_build_context() -> None:
    assessment = create_assessment("Ask Context", user_id=1001)
    add_assessment_target(assessment["id"], "example.com")

    context = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="What is known?")

    assert context["schema_version"] == "assessment_conversation_context.v1"
    assert context["assessment_context"]["assessment"]["id"] == assessment["id"]
    assert context["assessment_context"]["assessment"]["user_id"] == 1001
    assert context["provenance"]["user_id"] == 1001
    assert context["evidence_context_digest"].startswith("sha256:")


def test_different_user_cannot_build_context() -> None:
    assessment = create_assessment("Private Context", user_id=1001)

    with pytest.raises(ValueError, match="Assessment not found"):
        build_assessment_conversation_context(user_id=2002, assessment_id=assessment["id"], question="Show evidence")


def test_recent_messages_are_bounded_and_ordered() -> None:
    assessment = create_assessment("History Bound", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)
    for index in range(6):
        append_message(conversation["id"], user_id=1001, role="user", content=f"Turn {index}")

    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="Continue",
        conversation_id=conversation["id"],
        recent_message_limit=3,
    )

    messages = context["conversation"]["recent_messages"]
    assert [message["content"] for message in messages] == ["Turn 3", "Turn 4", "Turn 5"]
    assert context["conversation"]["recent_message_limit"] == 3


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("What is next", "next_step_recommendation"),
        ("What should we investigate next?", "next_step_recommendation"),
        ("Which one first?", "prioritization"),
        ("What haven't we checked?", "remaining_coverage_gaps"),
        ("Anything worrying so far?", "significance_interpretation"),
        ("Do we know it's vulnerable?", "uncertainty_safety"),
        ("Tell me like I'm new to this.", "simplify_explanation"),
        ("Why?", "follow_up_reference"),
        ("Why that one?", "follow_up_reference"),
        ("After that?", "follow_up_reference"),
        ("What will that tell me?", "follow_up_reference"),
        ("And 8080?", "follow_up_reference"),
        ("Explain that.", "explanation"),
        ("What does that mean?", "explanation"),
        ("Explain the TLS stuff simply.", "simplify_explanation"),
        ("How could an attacker look at this?", "attacker_informed_defensive_reasoning"),
    ],
)
def test_natural_conversation_intents(question: str, expected: str) -> None:
    assert classify_assessment_conversation_intent(question) == expected


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
def test_casual_security_uncertainty_variants_share_safe_intent(question: str) -> None:
    assert classify_assessment_conversation_intent(question) == "uncertainty_safety"


@pytest.mark.parametrize(
    ("question", "subtype"),
    [
        ("is that a vunerability?", "vulnerability"),
        ("is that a vuln?", "vulnerability"),
        ("does that mean its vulnerable?", "vulnerability"),
        ("is it exploitable?", "exploitability"),
        ("could someone exploit that?", "exploitability"),
        ("can an attacker actually use that?", "exploitability"),
        ("are we secure?", "overall_security"),
        ("is the site secure?", "overall_security"),
        ("so everything is safe?", "overall_security"),
    ],
)
def test_uncertainty_subtypes_are_compact_and_semantic(question: str, subtype: str) -> None:
    assert classify_assessment_conversation_intent(question) == "uncertainty_safety"
    assert classify_uncertainty_subtype(question) == subtype


@pytest.mark.parametrize(
    ("question", "intent"),
    [
        ("what next?", "next_step_recommendation"),
        ("what would you do next?", "next_step_recommendation"),
        ("what should we do?", "next_step_recommendation"),
        ("where do we go from here?", "next_step_recommendation"),
        ("which tool next?", "next_step_recommendation"),
        ("what haven't we done?", "remaining_coverage_gaps"),
        ("anything else?", "remaining_coverage_gaps"),
        ("what remains?", "remaining_coverage_gaps"),
        ("What exactly will this tell us?", "follow_up_reference"),
        ("And after that?", "follow_up_reference"),
        ("Why wouldn't you use Gitleaks here?", "individual_tool_explanation"),
        ("What about Prowler?", "individual_tool_explanation"),
    ],
)
def test_state_aware_conversation_phrase_variants(question: str, intent: str) -> None:
    assert classify_assessment_conversation_intent(question) == intent


@pytest.mark.parametrize(
    "question",
    [
        "why wouldn't you use gitleaks",
        "why wouldnt you use gitleaks",
        "what wouldn't you use gitleaks",
        "what wouldnt you use gitleaks",
        "why not gitleaks",
        "should we use gitleaks",
        "should we run gitleaks",
        "do we need gitleaks",
        "is gitleaks useful here",
        "what about gitleaks",
    ],
)
def test_messy_named_tool_relevance_variants(question: str) -> None:
    assert classify_assessment_conversation_intent(question) == "individual_tool_explanation"


@pytest.mark.parametrize(
    "tool",
    ["Nmap", "BBOT", "Nuclei", "httpx", "Playwright", "Katana", "ffuf", "testssl.sh", "Gitleaks", "Prowler", "Metasploit", "TShark"],
)
def test_relevance_shape_applies_to_every_locked_tool(tool: str) -> None:
    assert classify_assessment_conversation_intent(f"Should we use {tool}?") == "individual_tool_explanation"


def test_context_carries_explicit_authoritative_state_for_all_tools() -> None:
    assessment = create_assessment("Tool states", user_id=1001)
    record_assessment_scan(assessment["id"], tool="nmap", status="completed")
    record_assessment_scan(assessment["id"], tool="bbot", status="partial")
    record_assessment_scan(assessment["id"], tool="nuclei", status="failed")
    record_assessment_scan(assessment["id"], tool="prowler", status="skipped")

    context = build_assessment_conversation_context(
        user_id=1001, assessment_id=assessment["id"], question="What remains?",
    )

    states = context["recommendation_context"]["tool_states"]
    assert len(states) == 12
    assert states["nmap"] == "COMPLETED"
    assert states["bbot"] == "PARTIAL"
    assert states["nuclei"] == "FAILED"
    assert states["prowler"] == "SKIPPED"
    assert states["httpx"] == "NOT_RUN"
    assert states["testssl"] == "NOT_RUN"


def test_stored_summary_represents_older_conversation() -> None:
    assessment = create_assessment("Summary Context", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)
    update_summary_status(1001, conversation["id"], summary="Earlier discussion: Nmap observed SSH.")

    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What changed?",
        conversation_id=conversation["id"],
    )

    assert context["conversation"]["summary"] == "Earlier discussion: Nmap observed SSH."
    assert context["provenance"]["conversation_summary_present"] is True


def test_assessment_evidence_remains_present_when_history_is_large() -> None:
    assessment = create_assessment("Large History", user_id=1001)
    finding = _add_nmap_finding(1001, "example.com", [{"port": 22, "protocol": "tcp", "service": "ssh"}])
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id=finding["id"])
    conversation = create_conversation(assessment["id"], user_id=1001)
    for index in range(20):
        append_message(conversation["id"], user_id=1001, role="assistant", content=("old interpretation " * 100) + str(index))

    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="What ports were observed?",
        conversation_id=conversation["id"],
        recent_message_limit=4,
    )

    assert len(context["conversation"]["recent_messages"]) == 4
    assert context["assessment_context"]["findings"][0]["open_ports"][0]["port"] == 22
    assert context["assessment_context"]["budget"]["evidence_prioritized_over_history"] is True


def test_evidence_outranks_stale_assistant_statement() -> None:
    assessment = create_assessment("Precedence", user_id=1001)
    conversation = create_conversation(assessment["id"], user_id=1001)
    append_message(conversation["id"], user_id=1001, role="assistant", content="No open ports were observed earlier.")
    finding = _add_nmap_finding(1001, "example.com", [{"port": 443, "protocol": "tcp", "service": "https"}])
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id=finding["id"])

    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="Is the old answer still correct?",
        conversation_id=conversation["id"],
    )

    assert "Stored normalized assessment evidence is authoritative" in context["evidence_precedence"]
    assert context["assessment_context"]["findings"][0]["open_ports"][0]["port"] == 443
    assert "No open ports were observed earlier." in str(context["conversation"]["recent_messages"])


def test_tool_specific_question_selects_relevant_evidence() -> None:
    assessment = create_assessment("Tool Select", user_id=1001)
    nmap = _add_nmap_finding(1001, "example.com", [{"port": 80, "protocol": "tcp", "service": "http"}])
    bbot = add_finding(
        user_id=1001,
        finding={
            "source": "bbot",
            "target": "example.com",
            "status": "completed",
            "summary": "BBOT discovered subdomains.",
            "bbot_observations": [{"type": "DNS_NAME", "data": "www.example.com"}],
        },
    )
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id=nmap["id"])
    record_assessment_scan(assessment["id"], tool="bbot", status="completed", finding_id=bbot["id"])

    context = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="What did Nmap find?")

    assert detect_question_tools("What did Nmap find?") == ["nmap"]
    assert context["selection"] == {"mode": "tool_relevant", "selected_tools": ["nmap"]}
    assert [finding["source"] for finding in context["assessment_context"]["findings"]] == ["nmap"]


def test_full_assessment_question_retains_cross_tool_evidence() -> None:
    assessment = create_assessment("Full Assessment", user_id=1001)
    nmap = _add_nmap_finding(1001, "example.com", [{"port": 80, "protocol": "tcp", "service": "http"}])
    nuclei = add_finding(
        user_id=1001,
        finding={
            "source": "nuclei",
            "target": "https://example.com",
            "status": "completed",
            "nuclei_findings": [{"template_id": "tech-detect", "severity": "info"}],
        },
    )
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id=nmap["id"])
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=nuclei["id"])

    context = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="Summarize the assessment.")

    assert context["selection"]["mode"] == "full_assessment"
    assert {finding["source"] for finding in context["assessment_context"]["findings"]} == {"nmap", "nuclei"}


def test_gitleaks_raw_secrets_are_excluded() -> None:
    assessment = create_assessment("Secrets Context", user_id=1001)
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "gitleaks",
            "target": "repo",
            "status": "completed",
            "raw_output": "ghp_raw_secret_value",
            "gitleaks_evidence": {
                "finding_count": 1,
                "findings": [
                    {
                        "rule_id": "github-pat",
                        "file_path": "src/config.py",
                        "raw_secret": "ghp_raw_secret_value",
                        "redacted_secret_preview": "<REDACTED> len=36",
                        "secret_hash": "abc123",
                    }
                ],
            },
        },
    )
    record_assessment_scan(assessment["id"], tool="gitleaks", status="completed", finding_id=finding["id"])

    context = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="Review Gitleaks.")

    rendered = str(context)
    assert "ghp_raw_secret_value" not in rendered
    assert "<REDACTED> len=36" in rendered
    assert "abc123" in rendered


def test_tshark_correlation_confidence_keeps_existing_meaning() -> None:
    assessment = create_assessment("Correlation Context", user_id=1001)
    artifact = add_assessment_artifact(
        assessment["id"],
        artifact_type="tshark_metasploit_correlation",
        title="TShark + Metasploit Correlation",
        content=json.dumps(
            {
                "correlation_confidence": "high",
                "correlation_confidence_meaning": "attribution confidence only; not exploitability confidence",
                "correlation_outcome": "corroborated",
            }
        ),
    )

    context = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="Explain correlation.")

    assert context["provenance"]["included_artifact_ids"] == [artifact["id"]]
    assert "not exploitability confidence" in str(context)
    assert "TShark correlation confidence describes attribution confidence" in str(context["truthfulness"]["tool_boundaries"])


def test_metasploit_session_semantics_remain_intact() -> None:
    assessment = create_assessment("Metasploit Context", user_id=1001)
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "metasploit",
            "target": "example.com",
            "status": "completed",
            "metasploit_evidence": {
                "module": "auxiliary/scanner/http/http_version",
                "subprocess_success": True,
                "module_executed": True,
                "session_established": False,
                "validation_state": "NO_SESSION",
            },
        },
    )
    record_assessment_scan(assessment["id"], tool="metasploit", status="completed", finding_id=finding["id"])

    context = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="What did Metasploit prove?")

    evidence = context["assessment_context"]["findings"][0]["metasploit_evidence"]
    assert evidence["subprocess_success"] is True
    assert evidence["module_executed"] is True
    assert evidence["session_established"] is False
    assert "sessions, exploitation, and compromise are distinct states" in str(context["truthfulness"]["tool_boundaries"])


def test_prowler_pass_remains_check_specific() -> None:
    assessment = create_assessment("Prowler Context", user_id=1001)
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "prowler",
            "target": "aws",
            "status": "completed",
            "prowler_evidence": {
                "provider": "aws",
                "findings": [
                    {
                        "check_id": "s3_bucket_public_access",
                        "status": "PASS",
                        "severity": "low",
                        "status_interpretation": "scanner_reported_passed_check",
                    }
                ],
            },
        },
    )
    record_assessment_scan(assessment["id"], tool="prowler", status="completed", finding_id=finding["id"])

    context = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="Is AWS secure?")

    check = context["assessment_context"]["findings"][0]["prowler_evidence"]["findings"][0]
    assert check["status"] == "PASS"
    assert check["status_interpretation"] == "scanner_reported_passed_check"
    assert "Prowler PASS/FAIL applies to the specific scanner check" in str(context["truthfulness"]["tool_boundaries"])


def test_digest_is_stable_for_identical_context() -> None:
    assessment = create_assessment("Digest Stable", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001)

    first = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="Summarize.")
    second = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="Summarize.")

    assert first["evidence_context_digest"] == second["evidence_context_digest"]


def test_new_evidence_changes_digest_and_context() -> None:
    assessment = create_assessment("Digest Changes", user_id=1001)
    first = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="Summarize.")

    _add_nmap_scan(assessment["id"], user_id=1001)
    second = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question="Summarize.")

    assert first["evidence_context_digest"] != second["evidence_context_digest"]
    assert second["provenance"]["evidence_counts"]["scans"] == 1


def test_unowned_legacy_assessment_cannot_gain_conversation_context() -> None:
    legacy = create_assessment("Legacy")

    with pytest.raises(ValueError, match="Assessment not found"):
        build_assessment_conversation_context(user_id=1001, assessment_id=legacy["id"], question="Can I ask?")


def test_context_service_reuses_current_assessment_context_builder() -> None:
    assessment = create_assessment("Reuse Context", user_id=1001)
    _add_nmap_scan(assessment["id"], user_id=1001)

    base = build_assessment_context(assessment["id"], user_id=1001)
    conversation_context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="Summarize.",
    )

    assert conversation_context["assessment_context"]["scans"][0]["id"] == base["scans"][0]["id"]


def _add_nmap_scan(assessment_id: int, *, user_id: int) -> dict:
    finding = _add_nmap_finding(user_id, "example.com", [{"port": 22, "protocol": "tcp", "service": "ssh"}])
    return record_assessment_scan(assessment_id, tool="nmap", status="completed", finding_id=finding["id"])


def _add_nmap_finding(user_id: int, target: str, open_ports: list[dict]) -> dict:
    return add_finding(
        user_id=user_id,
        finding={
            "source": "nmap",
            "target": target,
            "status": "completed",
            "risk_level": "medium",
            "summary": "Nmap observed open ports.",
            "open_ports": open_ports,
        },
    )
