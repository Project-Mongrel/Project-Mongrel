from unittest.mock import patch

import pytest

from app.services.assessment_conversation_ai import answer_assessment_conversation_question
from app.services.assessment_conversation_context import build_assessment_conversation_context
from app.services.assessment_conversation_store import append_message, create_conversation
from app.services.assessment_map_identity import (
    canonical_endpoint,
    canonical_finding,
    canonical_hostname,
    canonical_service,
)
from app.services.assessment_map_retrieval import build_assessment_map_context
from app.services.assessment_map_store import (
    AssessmentMapScopeError,
    attach_evidence,
    get_or_create_assertion,
    get_or_create_entity,
)
from app.services.assessment_store import create_assessment, record_assessment_scan
from app.services.findings_store import add_finding, close_findings_database, configure_findings_database


@pytest.fixture(autouse=True)
def isolated_database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _mapped_endpoint_with_finding(*, user_id: int = 7001, assessment_name: str = "Mapped") -> dict:
    assessment = create_assessment(assessment_name, user_id=user_id)
    scan = record_assessment_scan(assessment["id"], "nuclei", "completed")
    endpoint_identity = canonical_endpoint("https://example.com/admin?token=secret&debug=1#frag")
    endpoint = get_or_create_entity(
        user_id=user_id,
        assessment_id=assessment["id"],
        identity=endpoint_identity,
        display_value="https://example.com/admin",
    )
    finding = get_or_create_entity(
        user_id=user_id,
        assessment_id=assessment["id"],
        identity=canonical_finding("nuclei", "weak-hsts", endpoint_identity, matcher="header"),
        display_value="Weak HSTS template match",
    )
    relationship = get_or_create_assertion(
        user_id=user_id,
        assessment_id=assessment["id"],
        subject_entity_id=finding["id"],
        predicate="finding_affects",
        object_entity_id=endpoint["id"],
    )
    attach_evidence(
        user_id=user_id,
        assessment_id=assessment["id"],
        source_tool="nuclei",
        evidence_kind="template_match",
        evidence_fingerprint=f"scan:{scan['id']}:weak-hsts",
        assertion_id=relationship["id"],
        scan_id=scan["id"],
        evidence_path="$.matches[0].template_id",
        confidence="scanner-observed",
    )
    return {"assessment": assessment, "scan": scan, "endpoint": endpoint, "finding": finding}


def test_map_retrieval_preserves_ownership_and_provenance() -> None:
    owned = _mapped_endpoint_with_finding(user_id=7001, assessment_name="Owned map")
    other = _mapped_endpoint_with_finding(user_id=7002, assessment_name="Other map")
    get_or_create_entity(
        user_id=7002,
        assessment_id=other["assessment"]["id"],
        identity=canonical_hostname("other.example"),
        display_value="other.example",
    )

    context = build_assessment_map_context(
        user_id=7001,
        assessment_id=owned["assessment"]["id"],
        question="What evidence supports this finding?",
    )

    rendered = str(context)
    assert context["available"] is True
    assert "Weak HSTS template match" in rendered
    assert "https://example.com/admin" in rendered
    assert "other.example" not in rendered
    assert "nuclei" in rendered
    assert str(owned["scan"]["id"]) in rendered

    with pytest.raises(AssessmentMapScopeError):
        build_assessment_map_context(
            user_id=7002,
            assessment_id=owned["assessment"]["id"],
            question="What evidence supports this finding?",
        )


def test_map_retrieval_connects_cross_tool_evidence_with_attributed_provenance() -> None:
    assessment = create_assessment("Cross-tool map", user_id=7010)
    nmap_scan = record_assessment_scan(assessment["id"], "nmap", "completed")
    httpx_scan = record_assessment_scan(assessment["id"], "httpx", "completed")
    hostname = get_or_create_entity(
        user_id=7010,
        assessment_id=assessment["id"],
        identity=canonical_hostname("example.com"),
        display_value="example.com",
    )
    service = get_or_create_entity(
        user_id=7010,
        assessment_id=assessment["id"],
        identity=canonical_service("example.com", "tcp", 443),
        display_value="example.com:443/tcp",
    )
    endpoint = get_or_create_entity(
        user_id=7010,
        assessment_id=assessment["id"],
        identity=canonical_endpoint("https://example.com/login"),
        display_value="https://example.com/login",
    )
    exposes = get_or_create_assertion(
        user_id=7010,
        assessment_id=assessment["id"],
        subject_entity_id=hostname["id"],
        predicate="host_exposes_service",
        object_entity_id=service["id"],
    )
    serves = get_or_create_assertion(
        user_id=7010,
        assessment_id=assessment["id"],
        subject_entity_id=service["id"],
        predicate="service_serves_endpoint",
        object_entity_id=endpoint["id"],
    )
    attach_evidence(
        user_id=7010, assessment_id=assessment["id"], source_tool="nmap",
        evidence_kind="open_port", evidence_fingerprint="nmap-443", assertion_id=exposes["id"],
        scan_id=nmap_scan["id"], evidence_path="$.open_ports[0]",
    )
    attach_evidence(
        user_id=7010, assessment_id=assessment["id"], source_tool="httpx",
        evidence_kind="response", evidence_fingerprint="httpx-login", assertion_id=serves["id"],
        scan_id=httpx_scan["id"], evidence_path="$.responses[0].url",
    )

    context = build_assessment_map_context(
        user_id=7010,
        assessment_id=assessment["id"],
        question="How do Nmap and httpx connect on the same service and endpoint?",
    )

    rendered = str(context)
    assert "host_exposes_service" in rendered
    assert "service_serves_endpoint" in rendered
    assert "nmap" in rendered
    assert "httpx" in rendered
    assert context["coverage"]["represented_tools"] == ["httpx", "nmap"]


def test_map_retrieval_bounds_context_and_does_not_leak_url_secrets() -> None:
    assessment = create_assessment("Bounded map", user_id=7003)
    scan = record_assessment_scan(assessment["id"], "httpx", "completed")
    for index in range(25):
        endpoint = get_or_create_entity(
            user_id=7003,
            assessment_id=assessment["id"],
            identity=canonical_endpoint(f"https://example.com/path{index}?api_key=secret-{index}&page={index}"),
            display_value=f"https://example.com/path{index}",
        )
        attach_evidence(
            user_id=7003,
            assessment_id=assessment["id"],
            source_tool="httpx",
            evidence_kind="response",
            evidence_fingerprint=f"scan:{scan['id']}:endpoint:{index}",
            entity_id=endpoint["id"],
            scan_id=scan["id"],
            evidence_path=f"$.responses[{index}].url",
        )

    context = build_assessment_map_context(
        user_id=7003,
        assessment_id=assessment["id"],
        question="Which endpoints are associated with this server?",
        entity_limit=5,
        relationship_limit=3,
        max_chars=1800,
    )

    rendered = str(context).lower()
    assert len(context["entities"]) <= 5
    assert context["truncated"] is True
    assert "secret-" not in rendered
    assert "api_key=secret" not in rendered
    assert len(str(context)) <= 2200


def test_assessment_ask_answers_map_question_deterministically_without_model_call() -> None:
    mapped = _mapped_endpoint_with_finding(user_id=7004, assessment_name="Ask map")

    with patch("app.services.assessment_conversation_ai.ask_ai", return_value="unsupported") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=7004,
            assessment_id=mapped["assessment"]["id"],
            conversation_id=None,
            question="Which services and endpoints are associated with this server?",
        )

    ask_ai.assert_not_called()
    assert "Assessment map evidence" in result["answer"]
    assert "https://example.com/admin" in result["answer"]
    assert "nuclei scan" in result["answer"]
    assert "does not run or approve any tool" in result["answer"]


def test_map_retrieval_failure_falls_back_to_existing_deterministic_status(monkeypatch) -> None:
    assessment = create_assessment("Fallback", user_id=7005)
    record_assessment_scan(assessment["id"], "nmap", "completed")

    def fail_map(**_kwargs):
        raise RuntimeError("synthetic map failure")

    monkeypatch.setattr("app.services.assessment_conversation_context.build_assessment_map_context", fail_map)
    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=7005,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Which tools completed, failed, timed out or were not run?",
        )

    ask_ai.assert_not_called()
    assert "Assessment tool status" in result["answer"]
    assert "Completed: Nmap" in result["answer"]


def test_unavailable_map_falls_through_to_existing_assessment_conversation(monkeypatch) -> None:
    assessment = create_assessment("Map unavailable", user_id=7011)

    monkeypatch.setattr(
        "app.services.assessment_conversation_context.build_assessment_map_context",
        lambda **_kwargs: {
            "version": "assessment-map.retrieval.v1", "available": False,
            "reason": "no_mapped_evidence", "entities": [], "relationships": [], "truncated": False,
        },
    )
    with patch(
        "app.services.assessment_conversation_ai.ask_ai",
        return_value="The stored assessment evidence does not contain a mapped relationship for that question.",
    ) as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=7011,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="Which endpoints are associated with this service?",
        )

    ask_ai.assert_called_once()
    assert "does not contain a mapped relationship" in result["answer"]
    assert "relationship map does not contain" not in result["answer"]


def test_referential_map_retrieval_uses_persisted_user_topic_only_as_ranking_hint(monkeypatch) -> None:
    assessment = create_assessment("Map follow-up", user_id=7012)
    conversation = create_conversation(assessment["id"], user_id=7012)
    append_message(
        conversation["id"], user_id=7012, role="user",
        content="How is the login endpoint connected to port 443?",
    )
    append_message(
        conversation["id"], user_id=7012, role="assistant",
        content="Untrusted conversational interpretation that must not become evidence.",
    )
    captured = {}

    def capture_query(**kwargs):
        captured.update(kwargs)
        return {
            "version": "assessment-map.retrieval.v1", "available": False,
            "reason": "no_mapped_evidence", "entities": [], "relationships": [], "truncated": False,
        }

    monkeypatch.setattr(
        "app.services.assessment_conversation_context.build_assessment_map_context", capture_query,
    )
    context = build_assessment_conversation_context(
        user_id=7012,
        assessment_id=assessment["id"],
        conversation_id=conversation["id"],
        question="What evidence supports that?",
    )

    assert "login endpoint" in captured["question"]
    assert "Untrusted conversational interpretation" not in captured["question"]
    assert context["conversation"]["id"] == conversation["id"]


def test_explicit_next_tool_question_keeps_existing_recommendation_route() -> None:
    assessment = create_assessment("Next route", user_id=7006)
    finding = add_finding(
        7006,
        {
            "source": "nmap",
            "target": "example.com",
            "summary": "Nmap observed web service",
            "open_ports": [{"port": 80, "protocol": "tcp", "service": "http", "state": "open"}],
        },
    )
    record_assessment_scan(assessment["id"], "nmap", "completed", finding_id=finding["id"])

    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=7006,
            assessment_id=assessment["id"],
            conversation_id=None,
            question="What should I run next?",
        )

    ask_ai.assert_not_called()
    assert "httpx" in result["answer"].lower()
    assert "Assessment map evidence" not in result["answer"]
