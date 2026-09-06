import json

import pytest

from app.services.assessment_conversation_ai import build_assessment_conversation_prompt
from app.services.assessment_conversation_context import build_assessment_conversation_context
from app.services.assessment_evidence_semantics import get_evidence_semantics
from app.services.assessment_store import add_assessment_artifact, add_assessment_note, create_assessment, record_assessment_scan
from app.services.findings_store import add_finding, close_findings_database, configure_findings_database


@pytest.fixture(autouse=True)
def database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


TOOL_CASES = [
    ("nmap", "What did Nmap actually find?", "Do those service labels prove a vulnerability?", "service labels", "not vulnerability"),
    ("bbot", "What assets did BBOT actually discover?", "Does that prove ownership or a breach?", "reconnaissance observations", "do not establish ownership"),
    ("nuclei", "What did Nuclei actually match?", "Does that INFO match prove exploitability or safety?", "INFO and LOW remain INFO and LOW", "not confirmed exploitability"),
    ("httpx", "What responses did httpx actually observe?", "Does 403 prove a WAF or 404 prove the host is absent?", "401 or 403", "does not prove the host"),
    ("playwright", "What browser state did Playwright observe?", "Do those forms prove XSS, SQLi, or CSRF?", "requested and rendered browser state", "not complete application coverage"),
    ("katana", "What URLs did Katana actually discover?", "Does an empty crawl prove there are no hidden endpoints?", "crawl observations", "does not prove that hidden endpoints"),
    ("ffuf", "What paths and statuses did ffuf observe?", "Does a 200 admin path prove sensitive exposure?", "fuzzing observations", "Zero results do not prove safety"),
    ("testssl", "What did testssl.sh actually report?", "Does potentially VULNERABLE prove exploitability?", "potentially VULNERABLE", "overall TLS safety"),
    ("gitleaks", "What did Gitleaks actually match?", "Does that prove an active credential or compromise?", "secret-pattern match", "Zero findings do not prove"),
    ("prowler", "Which Prowler checks passed or failed?", "Does a failed check prove compromise or passes prove compliance?", "individual stored check", "organization-wide compliance"),
    ("metasploit", "What Metasploit execution state was stored?", "Does module execution prove exploit success or a session?", "subprocess completion", "does not establish exploit success"),
    ("tshark", "What did TShark actually observe?", "Does TCP prove application success or TLS packets prove a handshake?", "TCP traffic", "do not establish a completed TLS handshake"),
]

REQUIRED_BOUNDARIES = {
    "bbot": ("do not establish ownership", "reachability", "vulnerability, breach, or exploitability", "no assets exist"),
    "nuclei": ("INFO and LOW remain INFO and LOW", "not confirmed exploitability", "template intent", "not that the target is safe"),
    "httpx": ("does not prove a vulnerability or WAF", "does not prove the host or site is absent", "does not prove its cause", "does not prove the host is down", "vulnerable technology"),
    "playwright": ("requested and rendered browser state", "XSS, SQL injection, CSRF", "does not prove that an issue is absent", "not complete application coverage"),
    "katana": ("do not establish a vulnerability", "hidden endpoints do not exist", "target is safe", "complete coverage"),
    "ffuf": ("does not automatically establish sensitive exposure", "does not establish authorized access", "redirect does not establish vulnerability", "Zero results do not prove safety", "wordlist, filters, scope, runtime"),
    "testssl": ("potentially VULNERABLE", "confirmed exploitable vulnerability", "overall TLS safety", "early_data severity", "complete TLS assurance"),
    "gitleaks": ("active, valid, or usable credential", "authorization, or compromise", "never expose a raw secret", "Zero findings do not prove"),
    "prowler": ("individual stored check and resource", "does not establish compromise", "organization-wide compliance", "overall cloud security", "not proof of realized impact"),
    "metasploit": ("does not establish execution", "subprocess completion", "does not establish exploit success", "stored session evidence", "explicit user review and approval"),
    "tshark": ("do not establish exploitation or compromise", "does not establish a successful application transaction", "do not establish a completed TLS handshake", "not exploit confidence"),
}


@pytest.mark.parametrize("tool,markers", REQUIRED_BOUNDARIES.items())
def test_compact_semantics_encode_each_required_truthfulness_boundary(tool, markers):
    semantics = " ".join(get_evidence_semantics(tool))
    assert all(marker in semantics for marker in markers)


def _add_tool_finding(assessment_id: int, tool: str) -> None:
    finding = add_finding(
        user_id=1001,
        finding={
            "source": tool,
            "target": "example.com",
            "status": "completed",
            "summary": "Unsupported generic top-risk prose",
            "risk_level": "high",
            "observations": [{"value": "stored observation"}],
        },
    )
    record_assessment_scan(assessment_id, tool=tool, status="completed", finding_id=finding["id"])


@pytest.mark.parametrize("tool,direct_question,reasoning_question,direct_marker,reasoning_marker", TOOL_CASES)
def test_direct_evidence_prompt_has_only_represented_tool_semantics(
    tool, direct_question, reasoning_question, direct_marker, reasoning_marker
):
    assessment = create_assessment(f"{tool} semantics", user_id=1001)
    _add_tool_finding(assessment["id"], tool)
    context = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question=direct_question)
    prompt = build_assessment_conversation_prompt(context)

    assert direct_marker.lower() in prompt.lower()
    assert reasoning_marker.lower() in prompt.lower()
    assert f'"{tool}"' in prompt
    other_tools = {case[0] for case in TOOL_CASES} - {tool}
    assert all(f'"{other}": [' not in prompt for other in other_tools)


@pytest.mark.parametrize("tool,direct_question,reasoning_question,direct_marker,reasoning_marker", TOOL_CASES)
def test_reasoning_prompt_preserves_tool_specific_boundary(
    tool, direct_question, reasoning_question, direct_marker, reasoning_marker
):
    assessment = create_assessment(f"{tool} reasoning", user_id=1001)
    _add_tool_finding(assessment["id"], tool)
    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question=f"Think like an attacker. {reasoning_question}",
    )
    prompt = build_assessment_conversation_prompt(context)

    assert direct_marker.lower() in prompt.lower()
    assert reasoning_marker.lower() in prompt.lower()
    assert "bounded hypotheses, not confirmed findings" in prompt


def test_tshark_selected_semantics_complete_existing_packet_guards():
    assessment = create_assessment("TShark semantics", user_id=1001)
    _add_tool_finding(assessment["id"], "tshark")
    context = build_assessment_conversation_context(
        user_id=1001, assessment_id=assessment["id"], question="What did TShark observe?"
    )
    prompt = build_assessment_conversation_prompt(context)

    assert get_evidence_semantics("tshark")
    assert '"tshark": [' in prompt
    assert "TCP traffic does not establish a successful application transaction" in prompt
    assert "do not establish a completed TLS handshake" in prompt
    assert "attribution confidence, not exploit confidence" in prompt


def test_generation_context_filters_enrichment_but_preserves_primary_evidence():
    assessment = create_assessment("Clean evidence", user_id=1001)
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "nuclei",
            "target": "https://example.com",
            "status": "completed",
            "risk_level": "critical",
            "risk_notes": "assumed compromise",
            "summary": "prior generic risk summary",
            "command": "nuclei -u example.com",
            "working_directory": "/tmp/tool-run",
            "output_path": "/tmp/output.json",
            "parser_errors": ["debug details"],
            "raw_json": {"unsafe": "duplicate"},
            "raw_event": "untrusted original event",
            "raw_evidence_excerpt": "raw subprocess text",
            "nuclei_findings": [{
                "template_id": "tech-detect",
                "name": "Technology detection",
                "severity": "info",
                "matched_at": "https://example.com/",
                "description": "template context",
                "remediation": "generic remediation",
                "classification": {"cve_id": ["CVE-0000-0000"]},
            }],
        },
    )
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=finding["id"])
    add_assessment_artifact(
        assessment["id"], artifact_type="ai_assessment", title="Prior AI report", content="invented compromise"
    )
    add_assessment_note(assessment["id"], "Unsupported analyst note says the target is breached.")

    context = build_assessment_conversation_context(
        user_id=1001, assessment_id=assessment["id"], question="What did Nuclei actually find?"
    )
    prompt = build_assessment_conversation_prompt(context)
    model_data = prompt.split("Private reference data (use its facts; never quote its labels or format):\n", 1)[1].rsplit("\n\nAnswer:", 1)[0]
    model_context = json.loads(model_data)
    rendered = json.dumps(model_context)

    for excluded in (
        "critical", "assumed compromise", "prior generic risk summary", "nuclei -u", "/tmp/tool-run",
        "/tmp/output.json", "debug details", "untrusted original event", "raw subprocess text",
        "generic remediation", "CVE-0000-0000", "invented compromise", "target is breached",
    ):
        assert excluded not in rendered
    for preserved in ("tech-detect", "Technology detection", "info", "https://example.com/", "template context"):
        assert preserved in rendered


def test_cross_tool_attacker_prompt_includes_only_two_represented_semantics_and_no_notes_or_artifacts():
    assessment = create_assessment("Two-tool reasoning", user_id=1001)
    _add_tool_finding(assessment["id"], "httpx")
    _add_tool_finding(assessment["id"], "prowler")
    add_assessment_artifact(assessment["id"], artifact_type="report", title="AI report", content="prior AI conclusion")

    context = build_assessment_conversation_context(
        user_id=1001,
        assessment_id=assessment["id"],
        question="Think like an attacker: what do the httpx and Prowler observations mean?",
    )
    prompt = build_assessment_conversation_prompt(context)

    assert '"httpx": [' in prompt
    assert '"prowler": [' in prompt
    assert '"nuclei": [' not in prompt
    assert "prior AI conclusion" not in prompt
