from unittest.mock import patch

import pytest

from app.services.assessment_conversation_ai import (
    TRUTHFULNESS_FALLBACK_ANSWER,
    answer_assessment_conversation_question,
    violates_conversation_truthfulness,
)
from app.services.assessment_conversation_context import classify_assessment_conversation_intent
from app.services.assessment_conversation_store import append_message, create_conversation
from app.services.assessment_store import create_assessment, record_assessment_scan
from app.services.findings_store import add_finding, close_findings_database, configure_findings_database
from app.services.mongrel_self_knowledge import get_mongrel_tool_names


USER_ID = 6401
TOOLS = [name.lower() for name in get_mongrel_tool_names()]


@pytest.fixture(autouse=True)
def database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _answer(assessment_id, question, conversation_id=None):
    with patch("app.services.assessment_conversation_ai.ask_ai") as model:
        result = answer_assessment_conversation_question(
            user_id=USER_ID,
            assessment_id=assessment_id,
            conversation_id=conversation_id,
            question=question,
        )
    return result, model


def _record(assessment_id, tool, status="completed", **evidence):
    tool = tool.removesuffix(".sh")
    finding = add_finding(
        user_id=USER_ID,
        finding={"source": tool, "target": "example.test", "status": status, **evidence},
    )
    record_assessment_scan(assessment_id, tool=tool, status=status, finding_id=finding["id"])


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    "template",
    (
        "what about {tool}?",
        "did we run {tool}?",
        "what did {tool} find?",
        "did {tool} find anything?",
        "why not {tool}?",
        "should we use {tool}?",
        "do we need {tool}?",
    ),
)
def test_every_named_tool_question_preserves_not_run_state(tool, template):
    assessment = create_assessment("not-run matrix", user_id=USER_ID)
    result, model = _answer(assessment["id"], template.format(tool=tool))

    assert "not been run" in result["answer"].lower() or "is not run" in result["answer"].lower()
    assert not any(
        phrase in result["answer"].lower()
        for phrase in ("is clean", "has passed", "was initiated", "was scanned", "no vulnerabilities were found")
    )
    model.assert_not_called()


@pytest.mark.parametrize("tool", TOOLS)
def test_every_completed_tool_reports_state_without_turning_completion_into_success(tool):
    assessment = create_assessment("completed matrix", user_id=USER_ID)
    _record(assessment["id"], tool)

    result, model = _answer(assessment["id"], f"did we run {tool}?")

    assert "recorded as completed" in result["answer"].lower()
    assert "does not imply" in result["answer"].lower()
    model.assert_not_called()


COMPLETED_EVIDENCE_CASES = (
    ("nmap", {"open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}]}, "did not establish vulnerability"),
    ("bbot", {"bbot_observations": [{"type": "DNS_NAME", "value": "www.example.test"}]}, "discovery observations"),
    ("nuclei", {"nuclei_findings": [{"template_id": "tech-detect", "severity": "info"}]}, "INFO"),
    ("httpx", {"httpx_services": [{"url": "https://example.test", "status_code": 403}]}, "status 403"),
    ("playwright", {"playwright_observation": {"final_url": "https://example.test", "forms": [{}]}}, "does not establish XSS"),
    ("katana", {"katana_observations": [{"url": "https://example.test/login"}]}, "discovery observations"),
    ("ffuf", {"ffuf_results": [{"path": "/admin", "status": 200, "size": 123}]}, "sensitive exposure"),
    (
        "testssl",
        {"testssl_evidence": {"target": "example.test", "vulnerabilities": [{"id": "early_data", "severity": "HIGH", "finding": "potentially VULNERABLE"}]}},
        "potentially VULNERABLE",
    ),
    ("gitleaks", {"gitleaks_evidence": {"finding_count": 1, "redacted": True}}, "active or usable credential"),
    ("prowler", {"prowler_evidence": {"findings": [{"check_id": "check-1", "status": "FAIL"}]}}, "check-scoped"),
    ("metasploit", {"metasploit_evidence": {"module_executed": True, "session_established": False}}, "does not establish successful exploitation"),
    ("tshark", {"tshark_evidence": {"packet_count": 3, "byte_count": 250}}, "does not establish a completed TLS handshake"),
)


@pytest.mark.parametrize("tool,evidence,marker", COMPLETED_EVIDENCE_CASES)
def test_every_completed_tool_direct_evidence_answer_stays_within_semantics(tool, evidence, marker):
    assessment = create_assessment("completed evidence matrix", user_id=USER_ID)
    _record(assessment["id"], tool, **evidence)

    result, model = _answer(assessment["id"], f"what did {tool} find?")

    assert marker.lower() in result["answer"].lower()
    assert result["answer"] != TRUTHFULNESS_FALLBACK_ANSWER
    model.assert_not_called()


@pytest.mark.parametrize("status,expected", (("partial", "partial"), ("failed", "failed"), ("skipped", "skipped")))
def test_noncompleted_tool_states_are_not_presented_as_results(status, expected):
    assessment = create_assessment(status, user_id=USER_ID)
    _record(assessment["id"], "nuclei", status=status)

    result, model = _answer(assessment["id"], "what did nuclei find?")

    assert expected in result["answer"].lower()
    assert "not evidence of a clean result" in result["answer"].lower()
    model.assert_not_called()


@pytest.mark.parametrize(
    "question,intent",
    (
        ("what did httpx add?", "current_assessment_evidence"),
        ("what did Metasploit prove?", "current_assessment_evidence"),
        ("how do you know?", "follow_up_reference"),
        ("what evidence supports that?", "follow_up_reference"),
        ("are we insecure?", "uncertainty_safety"),
        ("have we compromised it?", "uncertainty_safety"),
        ("Nuclei proved XSS", "unsupported_premise_check"),
    ),
)
def test_sweep_wording_routes_to_grounded_intent(question, intent):
    assert classify_assessment_conversation_intent(question) == intent


@pytest.mark.parametrize(
    "question,marker",
    (
        ("we confirmed the site is vulnerable right?", "does not establish"),
        ("port 443 is definitely exploitable", "does not establish"),
        ("metasploit exploited it right?", "does not establish successful exploitation"),
        ("tshark confirmed the exploit", "does not establish exploitation"),
        ("nuclei proved XSS", "does not by itself prove xss"),
        ("testssl proved TLS is insecure", "do not by themselves prove insecure tls"),
        ("gitleaks proved no secrets", "cannot prove that no secrets exist"),
        ("prowler proved the cloud is compliant", "cannot prove organization-wide cloud compliance"),
        ("scans found everything so we're secure", "does not establish"),
    ),
)
def test_false_premises_are_corrected_without_model_generation(question, marker):
    assessment = create_assessment("false premises", user_id=USER_ID)
    result, model = _answer(assessment["id"], question)

    assert marker in result["answer"].lower()
    assert result["answer"] != TRUTHFULNESS_FALLBACK_ANSWER
    model.assert_not_called()


@pytest.mark.parametrize(
    "tool,unsafe",
    (
        ("nmap", "Nmap identified vulnerabilities on the host."),
        ("bbot", "BBOT confirmed ownership and a breach."),
        ("nuclei", "Nuclei proved XSS on the target."),
        ("httpx", "httpx identified the target's security posture."),
        ("playwright", "Playwright found SQL injection in the form."),
        ("katana", "Katana found all hidden endpoints and complete coverage."),
        ("ffuf", "ffuf identified sensitive exposure and a vulnerability."),
        ("testssl", "testssl.sh confirmed insecure exploitable TLS."),
        ("metasploit", "Metasploit confirmed an exploitable weakness."),
        ("tshark", "TShark detected suspicious activity and an attack."),
    ),
)
def test_semantic_guard_rejects_capability_language_rewritten_as_findings(tool, unsafe):
    context = {
        "current_question": f"what did {tool} find?",
        "assessment_context": {"findings": []},
        "recommendation_context": {"tool_states": {tool: "COMPLETED"}},
    }
    assert violates_conversation_truthfulness(unsafe, context)


def test_short_followups_use_persisted_recommendation_and_evidence_not_history_as_fact():
    assessment = create_assessment("followups", user_id=USER_ID)
    _record(
        assessment["id"],
        "nmap",
        open_ports=[{"port": 443, "protocol": "tcp", "service": "https"}],
    )
    _record(assessment["id"], "httpx", httpx_services=[{"url": "https://example.test", "status_code": 403}])
    conversation = create_conversation(assessment["id"], USER_ID)
    append_message(conversation["id"], USER_ID, role="assistant", content="I would use Mongrel's Katana next.")

    for question in ("why?", "why that onw?", "what will that tell us?", "what did you mean?", "what about that?"):
        result, model = _answer(assessment["id"], question, conversation["id"])
        assert "katana" in result["answer"].lower()
        assert "not" in result["answer"].lower() and "vulnerability" in result["answer"].lower()
        model.assert_not_called()

    result, model = _answer(assessment["id"], "after that?", conversation["id"])
    assert "playwright" in result["answer"].lower()
    assert "conditional" in result["answer"].lower()
    model.assert_not_called()


def test_evidence_support_followup_returns_grounded_stored_summary():
    assessment = create_assessment("evidence followup", user_id=USER_ID)
    _record(assessment["id"], "nmap", open_ports=[{"port": 443, "protocol": "tcp", "service": "https"}])
    conversation = create_conversation(assessment["id"], USER_ID)
    append_message(conversation["id"], USER_ID, role="assistant", content="This surface is worth attention.")

    result, model = _answer(assessment["id"], "how do you know?", conversation["id"])

    assert "443/tcp (https)" in result["answer"]
    assert "not an overall secure" in result["answer"].lower()
    model.assert_not_called()


def test_compromise_and_insecurity_questions_receive_distinct_bounded_answers():
    assessment = create_assessment("uncertainty", user_id=USER_ID)

    compromised, compromised_model = _answer(assessment["id"], "have we compromised it?")
    insecure, insecure_model = _answer(assessment["id"], "are we insecure?")

    assert "does not establish that the target was compromised" in compromised["answer"].lower()
    assert "not enough to conclude" in insecure["answer"].lower()
    compromised_model.assert_not_called()
    insecure_model.assert_not_called()
