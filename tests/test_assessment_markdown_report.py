from datetime import UTC, datetime
import json

from app.services.assessment_markdown_report import generate_assessment_markdown_report


def test_assessment_markdown_report_handles_empty_assessment() -> None:
    report = generate_assessment_markdown_report(
        {
            "assessment": {
                "name": "Empty Assessment",
                "status": "active",
                "created_at": datetime(2026, 1, 1, tzinfo=UTC),
                "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
            },
            "targets": [],
            "scans": [],
            "findings": [],
            "artifacts": [],
            "notes": [],
        }
    )

    assert report.startswith("# Assessment Report")
    assert "Assessment Name: Empty Assessment" in report
    assert "Primary Target(s):\n- Not set" in report
    assert "No completed or partial assessment scans are recorded" in report
    assert "## Evidence Limitations" in report
    assert "- Absence of findings is not evidence of security." in report


def test_report_uses_latest_runs_and_preserves_playwright_nuclei_testssl_boundaries() -> None:
    def scan(scan_id: int, tool: str, status: str, day: int, finding: dict) -> dict:
        return {"id": scan_id, "tool": tool, "status": status, "created_at": datetime(2026, 1, day, tzinfo=UTC), "finding": finding}

    report = generate_assessment_markdown_report({
        "assessment": {"name": "Competition Final", "status": "active"}, "targets": [{"address": "example.com"}],
        "scans": [
            scan(9, "ffuf", "completed", 1, {"source": "ffuf", "metadata": {"ffuf_profile_label": "Custom", "wordlist_path": "ffuf_default.txt", "wordlist_count": 19}}),
            scan(2, "playwright", "completed", 2, {"source": "playwright", "summary": "Passive browser observation completed, no hidden content found.", "playwright_observation": {"final_url": "https://example.com", "load_status": "loaded", "forms_count": 0}}),
            scan(3, "nuclei", "completed", 3, {"source": "nuclei", "summary": "No matching Nuclei findings were observed", "nuclei_findings": [{"name": f"info-{i}", "severity": "info"} for i in range(3)]}),
            scan(4, "ffuf", "completed", 4, {"source": "ffuf", "metadata": {"ffuf_profile_label": "Standard", "wordlist_path": "/opt/seclists/ffuf-standard.txt", "wordlist_source": "SecLists", "wordlist_count": 2570, "timeout_seconds": 120}, "ffuf_results": []}),
            scan(5, "testssl", "failed", 5, {"source": "testssl", "summary": "testssl.sh scan timed out."}),
        ], "findings": [], "artifacts": [], "notes": [],
    })

    assert "no hidden content found" not in report.lower()
    assert "does not establish that hidden content is absent" in report
    assert "3 Nuclei template match(es) stored (INFO)" in report
    assert "No matching Nuclei findings were observed" not in report
    assert "Scan status\nFailed" in report
    assert "testssl.sh did not complete successfully; no completed structured evidence was stored" in report
    assert "Selected profile: Standard" in report and "Wordlist: ffuf-standard.txt" in report
    assert "Wordlist entries: 2570" in report
    assert "Selected profile: Custom" not in report and "ffuf_default.txt" not in report


def test_nuclei_scan_summary_prefers_normalized_info_matches_over_legacy_no_findings_summary() -> None:
    report = generate_assessment_markdown_report({
        "assessment": {"name": "Nuclei summary precedence", "status": "active"},
        "targets": [{"address": "example.com"}],
        "scans": [{
            "id": 101,
            "tool": "nuclei",
            "status": "completed",
            "created_at": datetime(2026, 1, 1, tzinfo=UTC),
            "risk": "info",
            "finding": {
                "source": "nuclei",
                "summary": "No matching Nuclei findings were observed with the selected template/profile.",
                "nuclei_findings": [
                    {"name": "Microsoft Azure Domain Tenant ID - Detect", "severity": "info"},
                    {"name": "WAF Detection", "severity": "info"},
                    {"name": "Weak HTTP Strict-Transport-Security - Detect", "severity": "info"},
                ],
            },
        }],
        "findings": [], "artifacts": [], "notes": [],
    })

    assert "No matching Nuclei findings" not in report
    assert "Summary\n3 Nuclei template match(es) stored (INFO)" in report
    assert "do not automatically establish a confirmed vulnerability or exploitability" in report


def test_assessment_markdown_report_renders_multi_tool_evidence() -> None:
    context = {
        "assessment": {
            "name": "External Assessment",
            "status": "active",
            "created_at": datetime(2026, 1, 1, tzinfo=UTC),
            "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
        },
        "targets": [{"address": "scanme.nmap.org"}],
        "scans": [
            {
                "tool": "nmap",
                "status": "completed",
                "risk": "medium",
                "completed_at": datetime(2026, 1, 1, 10, tzinfo=UTC),
                "finding": {
                    "summary": "SSH and HTTP observed.",
                    "target": "scanme.nmap.org",
                    "risk_level": "medium",
                    "open_ports": [
                        {"port": "22", "protocol": "tcp", "service": "ssh"},
                        {"port": "80", "protocol": "tcp", "service": "http"},
                    ],
                },
            },
            {
                "tool": "bbot",
                "status": "completed",
                "risk": "info",
                "completed_at": datetime(2026, 1, 1, 11, tzinfo=UTC),
                "finding": {
                    "summary": "Reconnaissance observations collected.",
                    "target": "scanme.nmap.org",
                    "observation_counts": {"subdomain": 2, "url": 3, "technology": 1},
                },
            },
            {
                "tool": "nuclei",
                "status": "completed",
                "risk": "high",
                "completed_at": datetime(2026, 1, 1, 12, tzinfo=UTC),
                "finding": {
                    "summary": "One matched finding observed.",
                    "target": "https://scanme.nmap.org",
                    "risk_level": "high",
                    "nuclei_findings": [
                        {
                            "name": "Example finding",
                            "template_id": "example-template",
                            "severity": "high",
                            "matched_at": "https://scanme.nmap.org/login",
                            "technology": "Apache",
                        }
                    ],
                },
            },
        ],
        "findings": [
            {
                "target": "scanme.nmap.org",
                "open_ports": [
                    {"port": "22", "protocol": "tcp", "service": "ssh"},
                    {"port": "80", "protocol": "tcp", "service": "http"},
                ],
            },
            {"target": "scanme.nmap.org", "observation_counts": {"subdomain": 2, "url": 3, "technology": 1}},
            {
                "target": "https://scanme.nmap.org",
                "nuclei_findings": [
                    {
                        "name": "Example finding",
                        "severity": "high",
                        "matched_at": "https://scanme.nmap.org/login",
                        "technology": "Apache",
                    }
                ],
            },
        ],
        "artifacts": [],
        "notes": [],
    }

    report = generate_assessment_markdown_report(context)

    assert "### Nmap" in report
    assert "### BBOT" in report
    assert "### Nuclei" in report
    assert "SSH and HTTP observed." in report
    assert "- 22/tcp ssh" in report
    assert "- Example finding (HIGH)" in report
    assert "Services\n- 22/tcp ssh\n- 80/tcp http" in report
    assert "Technologies\n- Apache" in report
    assert "## Assessment History" in report
    assert "Nmap Completed - Risk: MEDIUM" in report
    assert "- Review SSH exposure, authentication policy, and network access restrictions." in report
    assert "latest recorded state, including completed, partial, and failed runs" in report


def test_bbot_markdown_total_uses_authoritative_count_over_bounded_category_breakdown() -> None:
    finding = {
        "source": "bbot",
        "target": "btjoinery.ie",
        "finding_count": 36,
        "metadata": {"observation_count": 36},
        "observation_counts": {
            "dns_record": 19,
            "ip_address": 2,
            "raw_event": 4,
            "subdomain": 9,
            "open_port": 2,
        },
    }
    report = generate_assessment_markdown_report({
        "assessment": {"name": "BBOT authoritative total", "status": "active"},
        "targets": [{"address": "btjoinery.ie"}],
        "scans": [{"id": 1, "tool": "bbot", "status": "completed", "finding": finding}],
        "findings": [], "artifacts": [], "notes": [],
    })

    assert "Summary\n36 reconnaissance observation(s) recorded." in report
    assert "- BBOT: 36 reconnaissance observation(s) recorded." in report
    assert "- DNS records: 19" in report
    assert "- IP addresses: 2" in report
    assert "- Raw events: 4" in report
    assert "- Subdomains: 9" in report


def test_bbot_markdown_total_falls_back_to_observation_categories_without_authoritative_count() -> None:
    report = generate_assessment_markdown_report({
        "assessment": {"name": "BBOT category fallback", "status": "active"},
        "targets": [{"address": "example.com"}],
        "scans": [{
            "id": 2,
            "tool": "bbot",
            "status": "completed",
            "finding": {
                "source": "bbot",
                "target": "example.com",
                "observation_counts": {"subdomain": 2, "url": 3, "technology": 1},
            },
        }],
        "findings": [], "artifacts": [], "notes": [],
    })

    assert "Summary\n6 reconnaissance observation(s) recorded." in report
    assert "- BBOT: 6 reconnaissance observation(s) recorded." in report


def test_assessment_markdown_report_includes_partial_bbot_evidence() -> None:
    report = generate_assessment_markdown_report(
        {
            "assessment": {
                "name": "Partial Assessment",
                "status": "active",
                "created_at": datetime(2026, 1, 1, tzinfo=UTC),
                "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
            },
            "targets": [{"address": "example.com"}],
            "scans": [
                {
                    "tool": "bbot",
                    "status": "partial",
                    "risk": "info",
                    "completed_at": datetime(2026, 1, 1, 11, tzinfo=UTC),
                    "finding": {
                        "summary": "Partial reconnaissance observations collected.",
                        "target": "example.com",
                        "observation_counts": {"subdomain": 1, "url": 1},
                    },
                }
            ],
            "findings": [{"target": "example.com", "observation_counts": {"subdomain": 1, "url": 1}}],
            "artifacts": [],
            "notes": [],
        }
    )

    assert "completed or partial assessment scan(s)" in report
    assert "### BBOT" in report
    assert "Partial reconnaissance observations collected." in report
    assert "BBOT Partial - Risk: INFO" in report
    assert "- BBOT: 2 reconnaissance observation(s) recorded." in report


def test_assessment_markdown_report_includes_httpx_section() -> None:
    report = generate_assessment_markdown_report(
        {
            "assessment": {
                "name": "httpx Assessment",
                "status": "active",
                "created_at": datetime(2026, 1, 1, tzinfo=UTC),
                "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
            },
            "targets": [{"address": "example.com"}],
            "scans": [
                {
                    "tool": "httpx",
                    "status": "completed",
                    "risk": "info",
                    "completed_at": datetime(2026, 1, 1, 12, tzinfo=UTC),
                    "finding": {
                        "summary": "httpx observed two HTTP services.",
                        "target": "https://example.com",
                        "risk_level": "info",
                        "httpx_services": [
                            {
                                "url": "https://example.com",
                                "status_code": 301,
                                "title": "Example",
                                "web_server": "nginx",
                                "technologies": ["nginx"],
                                "redirect_location": "https://www.example.com",
                            },
                            {
                                "url": "https://www.example.com",
                                "status_code": 200,
                                "title": "Home",
                                "technologies": ["React"],
                                "tls": {"probe": True},
                            },
                        ],
                    },
                }
            ],
            "findings": [
                {
                    "target": "https://example.com",
                    "httpx_services": [
                        {"url": "https://example.com", "status_code": 301, "title": "Example", "technologies": ["nginx"]},
                        {"url": "https://www.example.com", "status_code": 200, "title": "Home", "technologies": ["React"]},
                    ],
                }
            ],
            "artifacts": [],
            "notes": [],
        }
    )

    assert "### httpx" in report
    assert "Scan status\nCompleted" in report
    assert "https://example.com status=301 title=Example server=nginx technologies=nginx redirect=https://www.example.com" in report
    assert "Technologies\n- nginx\n- React" in report
    assert "- httpx: 2 HTTP response/URL observation(s) recorded." in report
    assert "- Limitation: httpx response metadata is not proof of vulnerability, compromise, application health, or full service availability." in report
    assert "- Validate observed HTTP responses, redirects, page titles, headers, and technology fingerprints against intended exposure." in report


def test_assessment_markdown_report_includes_katana_section() -> None:
    report = generate_assessment_markdown_report(
        {
            "assessment": {
                "name": "Katana Assessment",
                "status": "active",
                "created_at": datetime(2026, 1, 1, tzinfo=UTC),
                "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
            },
            "targets": [{"address": "example.com"}],
            "scans": [
                {
                    "tool": "katana",
                    "status": "completed",
                    "risk": "info",
                    "completed_at": datetime(2026, 1, 1, 12, tzinfo=UTC),
                    "finding": {
                        "summary": "Katana observed three endpoints.",
                        "target": "https://example.com",
                        "risk_level": "info",
                        "katana_summary": {
                            "host_count": 1,
                            "javascript_count": 1,
                            "query_parameter_count": 1,
                            "form_count": 1,
                            "max_depth": 2,
                        },
                        "katana_observations": [
                            {
                                "url": "https://example.com/",
                                "host": "example.com",
                                "endpoint_type": "url",
                                "depth": 0,
                            },
                            {
                                "url": "https://example.com/app.js",
                                "host": "example.com",
                                "endpoint_type": "javascript",
                                "depth": 1,
                            },
                            {
                                "url": "https://example.com/search?q=test",
                                "host": "example.com",
                                "endpoint_type": "parameterized_url",
                                "query_parameters": ["q"],
                                "forms": [{"action": "/login", "method": "POST"}],
                                "depth": 2,
                            },
                        ],
                    },
                }
            ],
            "findings": [
                {
                    "target": "https://example.com",
                    "katana_observations": [
                        {"url": "https://example.com/app.js", "host": "example.com", "endpoint_type": "javascript", "depth": 1},
                        {
                            "url": "https://example.com/search?q=test",
                            "host": "example.com",
                            "endpoint_type": "parameterized_url",
                            "query_parameters": ["q"],
                            "forms": [{"action": "/login"}],
                            "depth": 2,
                        },
                    ],
                }
            ],
            "artifacts": [],
            "notes": [],
        }
    )

    assert "### Katana" in report
    assert "Scan status\nCompleted" in report
    assert "- URLs/endpoints observed during crawl: 3" in report
    assert "- Unique hosts: 1" in report
    assert "- JavaScript files observed during crawl: 1" in report
    assert "- Query parameters observed during crawl: 1" in report
    assert "- Forms/actions observed during crawl: 1" in report
    assert "- Max observed crawl depth: 2" in report
    assert "- Limitation: Katana crawl observations do not prove vulnerability, exploitability, sensitive exposure" in report
    assert "https://example.com/search?q=test type=parameterized_url depth=2 params=q forms=1" in report
    assert "- Katana: 3 crawled URL/endpoint observation(s) recorded." in report
    assert "- Review Katana-observed URLs, JavaScript files, forms, and query parameters to prioritize manual validation." in report


def test_assessment_markdown_report_includes_playwright_section() -> None:
    report = generate_assessment_markdown_report(
        {
            "assessment": {
                "name": "Playwright Assessment",
                "status": "active",
                "created_at": datetime(2026, 1, 1, tzinfo=UTC),
                "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
            },
            "targets": [{"address": "example.com"}],
            "scans": [
                {
                    "tool": "playwright",
                    "status": "completed",
                    "risk": "info",
                    "completed_at": datetime(2026, 1, 1, 12, tzinfo=UTC),
                    "finding": {
                        "summary": "Playwright passive browser observation completed.",
                        "target": "https://example.com",
                        "risk_level": "info",
                        "playwright_observation": {
                            "requested_url": "https://example.com",
                            "final_url": "https://www.example.com",
                            "title": "Example",
                            "load_status": "loaded",
                            "status_code": 200,
                            "forms_count": 1,
                            "inputs_count": 4,
                            "links_count": 12,
                            "console_issue_count": 2,
                            "network_issue_count": 1,
                            "page_error_count": 0,
                            "link_samples": ["https://www.example.com/about"],
                            "limitations": ["Passive browser observation only."],
                        },
                    },
                }
            ],
            "findings": [
                {
                    "target": "https://example.com",
                    "playwright_observation": {
                        "requested_url": "https://example.com",
                        "final_url": "https://www.example.com",
                        "title": "Example",
                        "load_status": "loaded",
                        "forms_count": 1,
                        "inputs_count": 4,
                        "links_count": 12,
                    },
                }
            ],
            "artifacts": [],
            "notes": [],
        }
    )

    assert "### Playwright" in report
    assert "Scan status\nCompleted" in report
    assert "- Requested URL: https://example.com" in report
    assert "- Final URL: https://www.example.com" in report
    assert "- Title: Example" in report
    assert "- Load status: loaded" in report
    assert "- Forms/inputs observed in returned state: 1 forms / 4 inputs" in report
    assert "- Links observed in returned state: 12" in report
    assert "- Console/network summary: 2 console / 1 network / 0 page errors" in report
    assert "- Screenshot/artifact metadata: not captured" in report
    assert "- Limitation: Passive Playwright observation does not test XSS, SQL injection, CSRF" in report
    assert "- Playwright: passive browser observation recorded for https://www.example.com." in report
    assert "- Review returned browser-state forms, links, console issues, and network failures before deeper manual testing." in report


def test_assessment_markdown_report_includes_ffuf_section() -> None:
    report = generate_assessment_markdown_report(
        {
            "assessment": {
                "name": "ffuf Assessment",
                "status": "active",
                "created_at": datetime(2026, 1, 1, tzinfo=UTC),
                "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
            },
            "targets": [{"address": "example.com"}],
            "scans": [
                {
                    "tool": "ffuf",
                    "status": "completed",
                    "risk": "info",
                    "completed_at": datetime(2026, 1, 1, 12, tzinfo=UTC),
                    "finding": {
                        "summary": "ffuf observed hidden-content paths.",
                        "target": "https://example.com",
                        "risk_level": "info",
                        "ffuf_summary": {
                            "status_codes": {"200": 1, "302": 1, "403": 1},
                            "redirect_count": 1,
                            "forbidden_count": 1,
                            "server_error_count": 0,
                        },
                        "ffuf_results": [
                            {
                                "url": "https://example.com/admin",
                                "path": "/admin",
                                "status_code": 200,
                                "content_length": 120,
                                "words": 10,
                                "lines": 3,
                                "classification": "public",
                            },
                            {
                                "url": "https://example.com/login",
                                "path": "/login",
                                "status_code": 302,
                                "redirect_location": "https://example.com/sso",
                                "classification": "redirect",
                            },
                            {
                                "url": "https://example.com/config",
                                "path": "/config",
                                "status_code": 403,
                                "classification": "forbidden",
                            },
                        ],
                    },
                }
            ],
            "findings": [
                {
                    "target": "https://example.com",
                    "ffuf_results": [
                        {"url": "https://example.com/admin", "path": "/admin", "status_code": 200, "classification": "public"},
                        {"url": "https://example.com/config", "path": "/config", "status_code": 403, "classification": "forbidden"},
                    ],
                }
            ],
            "artifacts": [],
            "notes": [],
        }
    )

    assert "### ffuf" in report
    assert "Scan status\nCompleted" in report
    assert "- Target/base URL: https://example.com" in report
    assert "- ffuf response observations: 3" in report
    assert "- Status codes: 200=1, 302=1, 403=1" in report
    assert "- Redirects: 1" in report
    assert "https://example.com/login status=302 classification=redirect redirect=https://example.com/sso" in report
    assert "- Limitation: Conservative bounded wordlist discovery only. ffuf response observations are not confirmed vulnerabilities" in report
    assert "- ffuf: 3 hidden-content path observation(s) recorded." in report
    assert "- Review ffuf-observed response paths and status codes as follow-up candidates before manual validation." in report


def test_assessment_markdown_report_includes_metasploit_validation() -> None:
    report = generate_assessment_markdown_report(
        {
            "assessment": {
                "name": "Metasploit Assessment",
                "status": "active",
                "created_at": datetime(2026, 1, 1, tzinfo=UTC),
                "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
            },
            "targets": [{"address": "example.com"}],
            "scans": [
                {
                    "tool": "metasploit",
                    "status": "completed",
                    "risk": "high",
                    "completed_at": datetime(2026, 1, 1, 12, tzinfo=UTC),
                    "finding": {
                        "summary": "Metasploit reported validation evidence. This is not proof of full compromise.",
                        "target": "example.com",
                        "risk_level": "high",
                        "raw_output": "RAW " * 500,
                        "metasploit_evidence": {
                            "module": "auxiliary/scanner/http/http_version",
                            "action_type": "auxiliary_validation",
                            "target": "example.com",
                            "port": 80,
                            "validation_state": "VALIDATED",
                            "subprocess_success": True,
                            "module_executed": True,
                            "session_established": False,
                            "summary": "Metasploit reported validation evidence. This is not proof of full compromise.",
                            "raw_evidence_excerpt": "The target appears vulnerable",
                        },
                        "metadata": {
                            "proposal_id": "proposal-abc",
                            "artifact_ref": "assessment_artifact:10",
                        },
                    },
                }
            ],
            "findings": [
                {
                    "target": "example.com",
                    "metasploit_evidence": {
                        "module": "auxiliary/scanner/http/http_version",
                        "validation_state": "VALIDATED",
                    },
                    "metadata": {"proposal_id": "proposal-abc"},
                }
            ],
            "artifacts": [],
            "notes": [],
        }
    )

    assert "### Metasploit" in report
    assert "- Metasploit: validation state VALIDATED recorded; execution status is not treated as exploit success." in report
    assert "Module: auxiliary/scanner/http/http_version" in report
    assert "Action: auxiliary_validation" in report
    assert "Validation State: VALIDATED" in report
    assert "Subprocess Success: True" in report
    assert "Module Executed: True" in report
    assert "Session Established: False" in report
    assert "Proposal Reference: proposal-abc" in report
    assert "Artifact Reference: assessment_artifact:10" in report
    assert "Subprocess success, target response, network evidence, or module compatibility alone is not exploit success." in report
    assert "Failed, blocked, or not reproduced validation does not mean the target is secure." in report
    assert "execution status is not treated as exploit success" in report
    assert ("RAW " * 20) not in report


def test_assessment_markdown_report_includes_tshark_normalized_evidence_only() -> None:
    evidence = {
        "source": "tshark",
        "execution_status": "completed",
        "source_file": {"name": "capture.pcap"},
        "packet_count": 3,
        "byte_count": 354,
        "capture_start": "1710000000.1",
        "capture_end": "1710000002.3",
        "observed_protocols": [{"protocol": "dns", "packet_count": 1}, {"protocol": "tls", "packet_count": 1}],
        "observed_endpoints": [{"address": "192.0.2.10", "packet_count": 2}],
        "observed_conversations": [{"src": "192.0.2.10", "dst": "198.51.100.20", "src_port": "53000", "dst_port": "53", "transport": "udp", "packet_count": 1}],
        "dns_observations": [{"query_name": "example.com", "response_address": "93.184.216.34"}],
        "http_observations": [{"method": "GET", "host": "example.com", "uri": "/?token=<REDACTED>", "response_code": "200"}],
        "tls_observations": [{"sni": "tls.example.com", "version": "0x0303"}],
        "parser_warnings": ["one malformed row skipped"],
        "truncation": {"output_truncated": True},
        "evidence_limitations": [
            "A packet observation is not malicious by itself.",
            "A connection is not evidence of compromise by itself.",
            "A DNS query is not evidence of exfiltration by itself.",
            "Encrypted traffic limits application visibility.",
            "Absence from the capture does not prove absence from the network.",
        ],
        "output": "raw tshark stdout should not appear",
    }
    report = generate_assessment_markdown_report(
        {
            "assessment": {
                "name": "TShark Assessment",
                "status": "active",
                "created_at": datetime(2026, 1, 1, tzinfo=UTC),
                "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
            },
            "targets": [{"address": "example.com"}],
            "scans": [
                {
                    "id": 42,
                    "tool": "tshark",
                    "status": "completed",
                    "risk": "info",
                    "completed_at": datetime(2026, 1, 1, 12, tzinfo=UTC),
                }
            ],
            "findings": [],
            "artifacts": [
                {
                    "id": 7,
                    "scan_id": 42,
                    "artifact_type": "tshark_normalized_evidence",
                    "title": "TShark normalized evidence",
                    "content": json.dumps(evidence),
                }
            ],
            "notes": [],
        }
    )

    assert "### TShark" in report
    assert "TShark normalized 3 packet metadata observation(s)." in report
    assert "- TShark: 3 packet metadata observation(s) recorded." in report
    assert "- Source file: capture.pcap" in report
    assert "- Packet count: 3" in report
    assert "- Protocols: dns=1, tls=1" in report
    assert "query=example.com capture_response=93.184.216.34" in report
    assert "request=GET host=example.com uri=/?token=<REDACTED> response_status=200" in report
    assert "sni=tls.example.com version=0x0303 handshake_success=not established by stored metadata" in report
    assert "packet activity is not automatically malicious" in report
    assert "a connection is not compromise" in report
    assert "a DNS query is not exfiltration" in report
    assert "encrypted traffic limits visibility" in report
    assert "absence from a capture proves nothing" in report
    assert "DNS associations are capture-window observations, not permanent ownership proof" in report
    assert "TLS SNI/version metadata does not prove a successful TLS handshake" in report
    assert "HTTP requests without response codes are not completed HTTP transactions" in report
    assert "raw tshark stdout should not appear" not in report
    assert "secret-value" not in report
