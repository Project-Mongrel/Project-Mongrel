from unittest.mock import patch
from datetime import UTC, datetime

from app.services.assessment_ai import (
    ASSESSMENT_AI_REPORT_NUM_PREDICT,
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


def test_assessment_ai_prompt_scopes_playwright_counts_to_returned_browser_state() -> None:
    prompt = build_assessment_ai_prompt(
        "What did Playwright observe?",
        {
            "assessment": {"name": "Playwright Assessment", "status": "active"},
            "targets": [{"address": "example.com"}],
            "scans": [{"tool": "playwright", "status": "completed"}],
            "findings": [
                {
                    "source": "playwright",
                    "target": "https://example.com",
                    "playwright_observation": {
                        "requested_url": "https://example.com",
                        "final_url": "https://example.com",
                        "load_status": "domcontentloaded",
                        "status_code": 429,
                        "forms_count": 0,
                        "inputs_count": 0,
                        "links_count": 0,
                    },
                }
            ],
            "artifacts": [],
            "notes": [],
        },
    )

    assert "forms_observed_in_returned_state=0" in prompt
    assert "links_observed_in_returned_state=0" in prompt
    assert "does not test XSS, SQL injection, CSRF" in prompt
    assert "too many requests were sent" not in prompt.lower()


def test_assessment_ai_prompt_scopes_katana_evidence_to_crawl_observations() -> None:
    prompt = build_assessment_ai_prompt(
        "What did Katana observe?",
        {
            "assessment": {"name": "Katana Assessment", "status": "active"},
            "targets": [{"address": "example.com"}],
            "scans": [{"tool": "katana", "status": "completed"}],
            "findings": [
                {
                    "source": "katana",
                    "target": "https://example.com",
                    "katana_observations": [
                        {
                            "url": "https://example.com/search?id=1",
                            "endpoint_type": "parameterized_url",
                            "query_parameters": ["id"],
                            "forms": [{"action": "/login"}],
                        }
                    ],
                }
            ],
            "artifacts": [],
            "notes": [],
        },
    )

    assert "params_observed_during_crawl=id" in prompt
    assert "forms_observed_during_crawl=1" in prompt
    assert "Katana crawl observations only; does not prove vulnerability" in prompt
    assert "parameter is vulnerable" not in prompt.lower()


def test_assessment_ai_prompt_scopes_ffuf_evidence_to_fuzzing_observations() -> None:
    prompt = build_assessment_ai_prompt(
        "What did ffuf observe?",
        {
            "assessment": {"name": "ffuf Assessment", "status": "active"},
            "targets": [{"address": "example.com"}],
            "scans": [{"tool": "ffuf", "status": "completed"}],
            "findings": [
                {
                    "source": "ffuf",
                    "target": "https://example.com",
                    "ffuf_results": [
                        {
                            "url": "https://example.com/admin",
                            "path": "/admin",
                            "status_code": 403,
                            "classification": "forbidden",
                            "input_word": "admin",
                        }
                    ],
                }
            ],
            "artifacts": [],
            "notes": [],
        },
    )

    assert "ffuf response observations:" in prompt
    assert "classification=forbidden" in prompt
    assert "ffuf fuzzing response metadata only; does not prove vulnerability" in prompt
    assert "admin directory is vulnerable" not in prompt.lower()


def test_assessment_ai_prompt_preserves_metasploit_validation_boundaries() -> None:
    prompt = build_assessment_ai_prompt(
        "What did Metasploit validate?",
        {
            "assessment": {"name": "Metasploit Assessment", "status": "active"},
            "targets": [{"address": "example.com"}],
            "scans": [{"tool": "metasploit", "status": "completed"}],
            "findings": [
                {
                    "source": "metasploit",
                    "target": "example.com",
                    "risk_level": "info",
                    "summary": "Metasploit output did not provide a conclusive validation result.",
                    "metasploit_evidence": {
                        "module": "exploit/multi/http/struts2_content_type_ognl",
                        "action_type": "exploit_validation",
                        "target": "example.com",
                        "port": 443,
                        "validation_state": "INCONCLUSIVE",
                        "subprocess_success": True,
                        "module_executed": True,
                        "session_established": False,
                        "summary": "Metasploit output did not provide a conclusive validation result.",
                    },
                    "metadata": {"proposal_id": "proposal-1", "artifact_ref": "assessment_artifact:7"},
                }
            ],
            "artifacts": [],
            "notes": [],
        },
    )

    assert "Treat Metasploit execution status, validation state, and session evidence as separate facts." in prompt
    assert "Metasploit normalized validation evidence:" in prompt
    assert "module=exploit/multi/http/struts2_content_type_ognl" in prompt
    assert "action=exploit_validation" in prompt
    assert "validation_state=INCONCLUSIVE" in prompt
    assert "subprocess_success=True" in prompt
    assert "session_established=False" in prompt
    assert "proposal_ref=proposal-1 artifact_ref=assessment_artifact:7" in prompt
    assert "not exploit proof or target safety proof" in prompt
    assert "exploit succeeded" not in prompt.lower()


def test_assessment_ai_prompt_preserves_tshark_packet_boundaries() -> None:
    prompt = build_assessment_ai_prompt(
        "What did TShark observe?",
        {
            "assessment": {"name": "TShark Assessment", "status": "active"},
            "targets": [{"address": "example.com"}],
            "scans": [{"tool": "tshark", "status": "completed"}],
            "findings": [
                {
                    "source": "tshark",
                    "target": "capture.pcap",
                    "risk_level": "info",
                    "tshark_evidence": {
                        "packet_count": 2,
                        "byte_count": 160,
                        "capture_start": "1710000000.1",
                        "capture_end": "1710000001.2",
                        "observed_protocols": [{"protocol": "tls", "packet_count": 1}],
                        "observed_conversations": [{"src": "192.0.2.10", "dst": "198.51.100.20", "src_port": "53000", "dst_port": "443", "transport": "tcp", "packet_count": 1}],
                        "dns_observations": [{"query_name": "example.com", "response_address": "198.51.100.20"}],
                        "http_observations": [{"method": "GET", "host": "example.com", "uri": "/", "response_code": ""}],
                        "tls_observations": [{"sni": "example.com", "version": "0x0303"}],
                    },
                }
            ],
            "artifacts": [],
            "notes": [],
        },
    )

    assert "Treat TShark evidence as packet metadata only" in prompt
    assert "TShark normalized packet metadata evidence:" in prompt
    assert "packet_count=2 byte_count=160" in prompt
    assert "dns_query=example.com capture_response=198.51.100.20" in prompt
    assert "http_request=GET host=example.com uri=/ response_status=not observed" in prompt
    assert "tls_sni=example.com version=0x0303 handshake_success=not established by stored metadata" in prompt
    assert "do not prove exploitation, compromise, ownership, authentication success, vulnerability, successful TLS handshake, or completed HTTP transaction" in prompt
    assert "tls handshake succeeded" not in prompt.lower()


def test_assessment_ai_prompt_preserves_gitleaks_secret_boundaries() -> None:
    prompt = build_assessment_ai_prompt(
        "What did Gitleaks find?",
        {
            "assessment": {"name": "Gitleaks Assessment", "status": "active"},
            "targets": [{"address": "/tmp/artifact"}],
            "scans": [{"tool": "gitleaks", "status": "completed"}],
            "findings": [
                {
                    "source": "gitleaks",
                    "target": "/tmp/artifact",
                    "risk_level": "high",
                    "gitleaks_evidence": {
                        "scan_root": "/tmp/artifact",
                        "finding_count": 1,
                        "affected_files_count": 1,
                        "findings": [
                            {
                                "rule_id": "github-pat",
                                "file_path": "src/config.py",
                                "line_number": 12,
                                "provider": "github",
                                "severity": "high",
                                "fingerprint": "abc123",
                                "redacted_secret_preview": "<REDACTED> len=36",
                                "commit": "deadbeef",
                            }
                        ],
                    },
                }
            ],
            "artifacts": [],
            "notes": [],
        },
    )

    assert "Treat Gitleaks detections as redacted secret-exposure evidence only." in prompt
    assert "Do not infer Gitleaks-detected values are valid, active, usable" in prompt
    assert "rule=github-pat file=src/config.py line=12 provider=github severity=high fingerprint=abc123 commit=deadbeef secret=<REDACTED> len=36" in prompt
    assert "validity, current usability, ownership, access, compromise, exfiltration, repository security, and absence of secrets are not established" in prompt
    assert "ghp_1234567890abcdefghijklmnopqrstuv" not in prompt


def test_assessment_ai_prompt_preserves_prowler_cloud_check_boundaries() -> None:
    prompt = build_assessment_ai_prompt(
        "What did Prowler find?",
        {
            "assessment": {"name": "Prowler Assessment", "status": "active"},
            "targets": [{"address": "aws", "target_type": "cloud_provider"}],
            "scans": [{"tool": "prowler", "status": "completed"}],
            "findings": [
                {
                    "source": "prowler",
                    "target": "standalone-aws",
                    "provider": "aws",
                    "cloud_context": "standalone-aws",
                    "risk_level": "info",
                    "summary": "Prowler recorded scanner-reported checks.",
                    "prowler_summary": {
                        "finding_count": 2,
                        "failed_count": 1,
                        "passed_count": 1,
                        "highest_severity": "HIGH",
                    },
                    "prowler_evidence": {
                        "provider": "aws",
                        "cloud_context": "standalone-aws",
                        "finding_count": 2,
                        "findings": [
                            {
                                "status": "FAIL",
                                "severity": "HIGH",
                                "check_id": "s3_check",
                                "service": "s3",
                                "region": "eu-west-1",
                                "resource_identifier": "bucket-1",
                                "check_title": "S3 check",
                            },
                            {"status": "PASS", "severity": "informational", "check_id": "iam_check", "service": "iam"},
                        ],
                    },
                }
            ],
            "artifacts": [],
            "notes": [],
        },
    )

    assert "Treat Prowler evidence as scanner-reported cloud check results only" in prompt
    assert "Prowler scanner-reported cloud check evidence:" in prompt
    assert "status=FAIL severity=HIGH check_id=s3_check service=s3 region=eu-west-1 resource=bucket-1" in prompt
    assert "PASS is not account/resource security proof" in prompt
    assert "FAIL is not exploitability, compromise, attacker access, data exposure, or organization-wide compliance proof" in prompt
    assert "severity/compliance mappings remain scanner metadata" in prompt
    assert "AWS account is secure" not in prompt


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

    with patch("app.services.assessment_ai.ask_ai", return_value=response) as ask:
        assert generate_assessment_ai_report({"assessment": {"name": "A"}}) == response
    assert ask.call_args.kwargs["num_predict"] == ASSESSMENT_AI_REPORT_NUM_PREDICT


def test_generate_assessment_ai_report_unavailable_returns_fallback() -> None:
    with patch("app.services.assessment_ai.ask_ai", return_value="AI request timed out."):
        assert generate_assessment_ai_report({"assessment": {"name": "A"}}) == FALLBACK_REPORT


def test_assessment_ai_report_rejects_global_absence_and_safety_conclusions() -> None:
    context = {"assessment": {"name": "Boundary", "status": "active"}, "scans": [], "findings": []}
    rejected = (
        "No vulnerabilities were detected within the scope of the current tools used.",
        "No security issues have been identified at this time.",
        "There are no specific risks identified based on the current evidence.",
        "The target appears secure and has a clean bill of health.",
    )

    for response in rejected:
        with patch("app.services.assessment_ai.ask_ai", return_value=response):
            report = generate_assessment_ai_report(context)
        assert report != response
        assert "does not establish" in report.lower()


def test_assessment_ai_report_allows_evidence_scoped_negation() -> None:
    allowed = (
        "The evidence does not establish that a vulnerability is present.",
        "Absence of findings does not establish that the target is secure.",
    )
    context = {"assessment": {"name": "Bounded wording", "status": "active"}, "scans": [], "findings": []}

    for response in allowed:
        with patch("app.services.assessment_ai.ask_ai", return_value=response):
            assert generate_assessment_ai_report(context) == response


def test_rejected_assessment_ai_report_uses_live_shaped_bbot_nmap_fallback() -> None:
    context = {
        "assessment": {"name": "Competition Demo", "status": "completed"},
        "targets": [{"address": "btjoinery.ie"}],
        "scans": [
            {
                "id": 1,
                "tool": "nmap",
                "status": "completed",
                "finding": {
                    "source": "nmap",
                    "target": "btjoinery.ie",
                    "host_status": "Up",
                    "open_ports": [
                        {"port": 80, "protocol": "tcp", "service": "http"},
                        {"port": 443, "protocol": "tcp", "service": "https"},
                    ],
                },
            },
            {
                "id": 2,
                "tool": "bbot",
                "status": "completed",
                "finding": {
                    "source": "bbot",
                    "target": "btjoinery.ie",
                    "finding_count": 36,
                    "observation_counts": {"dns_record": 5, "raw_event": 2, "subdomain": 3},
                    "observations": [{"observation_type": "raw_event", "value": f"event-{index}"} for index in range(10)],
                },
            },
        ],
        "findings": [],
        "artifacts": [],
        "notes": [],
    }
    response = "No vulnerabilities were detected within the scope of the current tools used."

    with patch("app.services.assessment_ai.ask_ai", return_value=response):
        report = generate_assessment_ai_report(context)

    assert "BBOT completed and recorded 36 reconnaissance observation(s)" in report
    assert "dns_record=5" in report and "raw_event=2" in report and "subdomain=3" in report
    assert "Nmap completed and recorded host status Up, 80/tcp http, 443/tcp https" in report
    assert "reconnaissance and network-exposure observations only" in report
    assert "do not establish that a vulnerability is present or absent" in report
    assert "Executive Summary" in report
    assert "Evidence Limitations" in report
    assert "no vulnerabilities were detected" not in report.lower()


def test_ai_report_uses_latest_tool_evidence_and_corrects_scanner_semantics() -> None:
    older = {
        "id": 10, "tool": "ffuf", "status": "completed", "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "finding": {"source": "ffuf", "metadata": {"ffuf_profile_label": "Custom", "wordlist_path": "ffuf_default.txt", "wordlist_count": 19}},
    }
    newer = {
        "id": 20, "tool": "ffuf", "status": "completed", "created_at": datetime(2026, 1, 2, tzinfo=UTC),
        "finding": {"source": "ffuf", "metadata": {"ffuf_profile_label": "Standard", "wordlist_path": "/opt/ffuf-standard.txt", "wordlist_count": 2570}},
    }
    context = {
        "assessment": {"name": "Final", "status": "active"}, "targets": [],
        "scans": [newer, older, {
            "id": 30, "tool": "nuclei", "status": "completed", "created_at": datetime(2026, 1, 3, tzinfo=UTC),
            "finding": {"source": "nuclei", "nuclei_findings": [
                {"name": "Weak HSTS", "severity": "info"},
                {"name": "Technology Detection", "severity": "info"},
                {"name": "HTTP Metadata", "severity": "info"},
            ]},
        }, {
            "id": 40, "tool": "testssl", "status": "failed", "created_at": datetime(2026, 1, 4, tzinfo=UTC),
            "finding": {"source": "testssl", "summary": "scan timed out"},
        }, {
            "id": 50, "tool": "playwright", "status": "completed", "created_at": datetime(2026, 1, 5, tzinfo=UTC),
            "finding": {"source": "playwright", "playwright_observation": {"forms_count": 0, "inputs_count": 12, "links_count": 56}},
        }], "artifacts": [], "notes": [],
    }
    response = "\n".join([
        "Playwright Scan: Passive browser observation completed, no hidden content found.",
        "Playwright observed links and forms.",
        "Nuclei found 3 issues.",
        "FFUW: Observed no hidden content paths.",
        "HSTS presence is generally considered secure.",
        "No findings indicate any vulnerabilities or potential exploits.",
        "No immediate remediation actions are recommended.",
        "testssl.sh completed with no findings.",
    ])

    prompt = build_assessment_ai_report_prompt(context)
    with patch("app.services.assessment_ai.ask_ai", return_value=response):
        report = generate_assessment_ai_report(context)

    assert "profile=Standard" in prompt and "wordlist_entries=2570" in prompt
    assert "profile=Custom" not in prompt and "wordlist_entries=19" not in prompt
    assert "no hidden content found" not in report.lower()
    assert "ffuw" not in report.lower()
    assert "zero observations do not establish that hidden content or paths are absent" in report
    assert "generally considered secure" not in report.lower()
    assert "HSTS presence is a stored observation only" in report
    assert "1 HSTS-related Nuclei template match(es) (INFO)" in report
    assert "no findings indicate" not in report.lower()
    assert "No confirmed vulnerability or exploitability conclusion" in report
    assert "No immediate remediation" not in report
    assert "failed or unperformed coverage" in report
    assert "0 forms, 12 inputs, and 56 links" in report
    assert "3 template match(es)" in report and "INFO" in report
    assert "testssl.sh: FAILED" in report and "no completed structured TLS" in report
