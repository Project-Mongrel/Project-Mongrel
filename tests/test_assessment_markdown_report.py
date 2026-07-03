from datetime import UTC, datetime

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
    assert "- Only completed and partial tools are represented in the scan summary." in report


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
    assert "- httpx: 2 HTTP service/URL observation(s) recorded." in report
    assert "- Validate observed HTTP services, redirects, page titles, and technology fingerprints against intended exposure." in report


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
    assert "- URLs/endpoints: 3" in report
    assert "- Unique hosts: 1" in report
    assert "- JavaScript files: 1" in report
    assert "- Query parameters: 1" in report
    assert "- Forms/actions: 1" in report
    assert "- Max observed crawl depth: 2" in report
    assert "https://example.com/search?q=test type=parameterized_url depth=2 params=q forms=1" in report
    assert "- Katana: 3 crawled URL/endpoint observation(s) recorded." in report
    assert "- Review crawled URLs, JavaScript files, forms, and query parameters to prioritize manual web testing." in report


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
    assert "- Forms/inputs: 1 forms / 4 inputs" in report
    assert "- Links: 12" in report
    assert "- Console/network summary: 2 console / 1 network / 0 page errors" in report
    assert "- Screenshot/artifact metadata: not captured" in report
    assert "- Playwright: passive browser observation recorded for https://www.example.com." in report
    assert "- Review browser-observed forms, links, console issues, and network failures before deeper manual testing." in report


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
    assert "- Discovered paths: 3" in report
    assert "- Status codes: 200=1, 302=1, 403=1" in report
    assert "- Redirects: 1" in report
    assert "https://example.com/login status=302 classification=redirect redirect=https://example.com/sso" in report
    assert "- ffuf: 3 hidden-content path observation(s) recorded." in report
    assert "- Review discovered hidden-content paths and status codes as follow-up candidates before manual validation." in report
