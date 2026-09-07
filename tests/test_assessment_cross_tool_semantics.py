import json
from unittest.mock import patch

import pytest

from app.services.assessment_conversation_ai import answer_assessment_conversation_question, build_assessment_conversation_prompt
from app.services.assessment_conversation_context import build_assessment_conversation_context, detect_question_tools
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


def _add_httpx_evidence(assessment_id: int, status: int = 403) -> None:
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "httpx",
            "target": "https://example.com",
            "status": "completed",
            "httpx_services": [{
                "url": "https://example.com",
                "status_code": status,
                "title": "Restricted",
                "redirect_location": "https://www.example.com",
                "web_server": "nginx",
                "technologies": ["nginx"],
                "content_type": "text/html",
                "ip": "23.227.38.65",
                "cdn": True,
                "cname": ["edge.example.net"],
                "tls": {"subject_cn": "example.com"},
            }],
        },
    )
    record_assessment_scan(assessment_id, tool="httpx", status="completed", finding_id=finding["id"])


def _add_tshark_artifact(assessment_id: int) -> None:
    scan = record_assessment_scan(assessment_id, tool="tshark", status="completed")
    add_assessment_artifact(
        assessment_id,
        scan_id=scan["id"],
        artifact_type="tshark_normalized_evidence",
        title="TShark normalized PCAP evidence",
        content=json.dumps({
            "execution_status": "completed",
            "success": True,
            "packet_count": 76,
            "byte_count": 265200,
            "observed_protocols": [
                {"protocol": "dns", "packet_count": 4},
                {"protocol": "tls", "packet_count": 40},
            ],
            "observed_endpoints": [{"address": "23.227.38.65", "packet_count": 40}],
            "observed_conversations": [{
                "src": "192.0.2.10", "dst": "23.227.38.65", "src_port": "51000",
                "dst_port": "443", "transport": "tcp", "packet_count": 40,
            }],
            "dns_observations": [{"query_name": "hellosundaykids.com", "response_address": "23.227.38.65"}],
            "http_observations": [],
            "tls_observations": [{"sni": "hellosundaykids.com", "version": "TLS 1.2"}],
            "evidence_limitations": ["TLS SNI/version metadata does not prove a successful TLS handshake by itself."],
        }),
    )


def _add_testssl_evidence(assessment_id: int) -> None:
    finding = add_finding(
        user_id=1001,
        finding={
            "source": "testssl",
            "target": "hellosundaykids.com:443",
            "status": "completed",
            "testssl_evidence": {
                "target": "hellosundaykids.com:443",
                "host": "hellosundaykids.com",
                "port": 443,
                "protocols": [{"id": "TLS1_2", "name": "TLS 1.2", "finding": "offered", "severity": "OK"}],
                "certificate": {"issuer": "Example CA", "not_after": "2030-01-01"},
                "vulnerabilities": [{"id": "heartbleed", "finding": "not vulnerable", "severity": "OK"}],
                "notable_findings": [{"id": "early_data", "finding": "potentially VULNERABLE", "severity": "HIGH"}],
                "limitations": ["Scanner labels are not automatic exploit confirmation."],
            },
        },
    )
    record_assessment_scan(assessment_id, tool="testssl", status="completed", finding_id=finding["id"])


def test_live_httpx_direct_question_is_deterministic_and_not_withheld():
    assessment = create_assessment("httpx direct", user_id=1001)
    _add_httpx_evidence(assessment["id"])
    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001, assessment_id=assessment["id"], conversation_id=None,
            question="What did httpx actually observe?",
        )
    ask_ai.assert_not_called()
    answer = result["answer"]
    assert "status 403" in answer
    assert "technology hints nginx" in answer
    assert "stored TLS metadata subject_cn=example.com" in answer
    assert "withheld" not in answer.lower()
    assert "WAF" in answer and "do not by themselves establish" in answer
    assert "recommend" not in answer.lower()
    assert result["instrumentation"]["prompt_chars"] == 0
    assert result["instrumentation"]["context_chars"] == 0


def test_live_httpx_403_question_answers_no_and_separates_nuclei_waf_evidence():
    assessment = create_assessment("httpx WAF boundary", user_id=1001)
    _add_httpx_evidence(assessment["id"])
    nuclei = add_finding(
        user_id=1001,
        finding={
            "source": "nuclei", "target": "https://example.com", "status": "completed",
            "nuclei_findings": [{
                "template_id": "waf-detect", "name": "WAF Detection", "severity": "info",
                "matched_at": "https://example.com",
            }],
        },
    )
    record_assessment_scan(assessment["id"], tool="nuclei", status="completed", finding_id=nuclei["id"])
    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001, assessment_id=assessment["id"], conversation_id=None,
            question="Do the 403 responses prove there is a WAF?",
        )
    ask_ai.assert_not_called()
    assert result["answer"].startswith("No. A 403 response")
    assert "does not by itself prove a WAF" in result["answer"]
    assert "Nuclei separately reported an informational WAF Detection template match" in result["answer"]
    assert "separate scanner evidence" in result["answer"]


def test_live_testssl_direct_question_preserves_scanner_wording_without_withholding():
    assessment = create_assessment("testssl direct", user_id=1001)
    _add_testssl_evidence(assessment["id"])
    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001, assessment_id=assessment["id"], conversation_id=None,
            question="What did testssl.sh actually establish about TLS?",
        )
    ask_ai.assert_not_called()
    assert "potentially VULNERABLE" in result["answer"]
    assert "severity HIGH" in result["answer"]
    assert "does not establish exploitability" in result["answer"]
    assert "withheld" not in result["answer"].lower()
    assert result["instrumentation"]["prompt_chars"] == 0


def test_live_tshark_direct_question_reports_packet_metadata_without_inventing_service_absence():
    assessment = create_assessment("TShark direct", user_id=1001)
    _add_tshark_artifact(assessment["id"])
    metasploit = add_finding(
        user_id=1001,
        finding={"source": "metasploit", "target": "hellosundaykids.com", "status": "completed"},
    )
    record_assessment_scan(assessment["id"], tool="metasploit", status="completed", finding_id=metasploit["id"])
    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001, assessment_id=assessment["id"], conversation_id=None,
            question="What did TShark actually observe during the Metasploit validation?",
        )
    ask_ai.assert_not_called()
    answer = result["answer"]
    for expected in ("76 packets", "265200 bytes", "23.227.38.65", "DNS", "TLS", "SNI hellosundaykids.com", "version TLS 1.2"):
        assert expected in answer
    assert "no HTTP metadata was observed" in answer
    assert "does not establish a completed TLS handshake" in answer
    assert "no HTTP service" not in answer
    assert "no HTTPS traffic" not in answer
    assert result["instrumentation"]["prompt_chars"] == 0


def test_tls_packet_question_uses_tshark_provenance_and_ignores_testssl_early_data_and_heartbeat():
    assessment = create_assessment("TLS provenance", user_id=1001)
    _add_tshark_artifact(assessment["id"])
    _add_testssl_evidence(assessment["id"])
    question = "Did the TLS packets prove that a TLS handshake completed?"
    context = build_assessment_conversation_context(user_id=1001, assessment_id=assessment["id"], question=question)
    assert detect_question_tools(question) == ["tshark"]
    assert context["selection"]["selected_tools"] == ["tshark"]
    assert all(finding.get("source") != "testssl" for finding in context["assessment_context"]["findings"])
    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001, assessment_id=assessment["id"], conversation_id=None, question=question,
        )
    ask_ai.assert_not_called()
    assert result["answer"].startswith("No—not from the stored evidence")
    assert "did not establish whether a TLS handshake completed" in result["answer"]
    assert "cannot determine completion of this captured handshake" in result["answer"]
    assert "prevents" not in result["answer"]
    assert result["instrumentation"]["prompt_chars"] == 0


def test_cross_tool_port_443_synthesis_attributes_each_source_and_stays_bounded():
    assessment = create_assessment("Port 443 synthesis", user_id=1001)
    nmap = add_finding(
        user_id=1001,
        finding={"source": "nmap", "target": "hellosundaykids.com", "status": "completed", "open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}]},
    )
    record_assessment_scan(assessment["id"], tool="nmap", status="completed", finding_id=nmap["id"])
    _add_httpx_evidence(assessment["id"], status=200)
    metasploit = add_finding(
        user_id=1001,
        finding={
            "source": "metasploit", "target": "hellosundaykids.com", "status": "completed",
            "metasploit_evidence": {
                "validation_state": "DETECTED", "subprocess_success": True,
                "module_executed": True, "session_established": False,
            },
        },
    )
    record_assessment_scan(assessment["id"], tool="metasploit", status="completed", finding_id=metasploit["id"])
    _add_tshark_artifact(assessment["id"])
    question = "Combine the Nmap, httpx, Metasploit and TShark evidence. What can we actually conclude about port 443?"
    with patch("app.services.assessment_conversation_ai.ask_ai") as ask_ai:
        result = answer_assessment_conversation_question(
            user_id=1001, assessment_id=assessment["id"], conversation_id=None, question=question,
        )
    ask_ai.assert_not_called()
    answer = result["answer"]
    assert "Nmap classified 443/tcp as https" in answer
    assert "httpx recorded HTTP(S)-related response metadata" in answer
    assert "Metasploit recorded validation state DETECTED" in answer
    assert "session established was False" in answer
    assert "TShark observed target-related TLS packet metadata including SNI hellosundaykids.com" in answer
    assert "did not establish a completed TLS handshake" in answer
    assert "support an exposed web/TLS-associated service surface on port 443" in answer
    assert "do not by themselves establish vulnerability, exploitability, compromise, or overall TLS security" in answer
    assert result["instrumentation"]["prompt_chars"] == 0
