import pytest
from unittest.mock import patch

from app.services.findings_store import add_finding, close_findings_database, configure_findings_database
from app.services.report_generator import build_report_ai_assessment_prompt, generate_markdown_report


@pytest.fixture(autouse=True)
def sqlite_findings_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_report_generation_from_nmap_findings() -> None:
    add_finding(
        user_id=9001,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )

    report = generate_markdown_report(user_id=9001, target="127.0.0.1")

    assert "# Project Mongrel" in report
    assert "Security Assessment Report" in report
    assert "Report ID:\nPM-" in report
    assert "Target / Scope:\n127.0.0.1" in report
    assert "Generated:" in report
    assert "Overall Risk:\nMEDIUM" in report
    assert "## Executive Summary" in report
    assert "## Assessment Statistics" in report
    assert "- Tools Used: Nmap" in report
    assert "- Nmap" in report
    assert "- Highest Risk: MEDIUM" in report
    assert "Nmap identified 1 open port(s)" in report
    assert "22/tcp ssh" in report
    assert "## Appendix / Scan History" in report


def test_report_generation_from_inconclusive_nmap_does_not_claim_no_open_ports() -> None:
    add_finding(
        user_id=9020,
        finding={
            "source": "nmap",
            "target": "this-host-does-not-exist-123456.example",
            "assessment_result": "inconclusive",
            "risk_level": "unknown",
            "open_ports": [],
        },
    )

    report = generate_markdown_report(user_id=9020, target="this-host-does-not-exist-123456.example")

    assert "did not establish an assessable target state" in report
    assert "No conclusion about exposed ports or vulnerabilities can be drawn from that run." in report
    assert "Nmap found no open ports" not in report


def test_report_generation_from_nuclei_findings() -> None:
    add_finding(
        user_id=9002,
        finding={
            "source": "nuclei",
            "target": "https://example.com",
            "risk_level": "high",
            "finding_count": 1,
            "nuclei_findings": [
                {
                    "template_id": "git-config-exposure",
                    "severity": "high",
                    "name": "Exposed Git Repository",
                }
            ],
        },
    )

    report = generate_markdown_report(user_id=9002, target="https://example.com")

    assert "- Nuclei" in report
    assert "- Highest Risk: HIGH" in report
    assert "Nuclei reported 1 scanner finding(s)" in report
    assert "Exposed Git Repository (scanner severity: HIGH) - template=git-config-exposure" in report
    assert "- Manually validate matched Nuclei findings before remediation planning." in report


def test_report_generation_from_bbot_uses_reconnaissance_wording() -> None:
    add_finding(
        user_id=9021,
        finding={
            "source": "bbot",
            "target": "example.com",
            "risk_level": "info",
            "finding_count": 1,
            "observation_counts": {"subdomain": 1},
        },
    )

    report = generate_markdown_report(user_id=9021, target="example.com")

    assert "BBOT reconnaissance observation for example.com" in report
    assert "BBOT finding for example.com" not in report


def test_report_generation_preserves_nuclei_info_severity() -> None:
    add_finding(
        user_id=9022,
        finding={
            "source": "nuclei",
            "target": "https://example.com",
            "risk_level": "info",
            "finding_count": 1,
            "severity_summary": {"info": 1},
            "nuclei_findings": [
                {
                    "template_id": "graphql-detect",
                    "severity": "info",
                    "name": "GraphQL Endpoint Detection",
                    "host": "https://example.com/graphql",
                }
            ],
        },
    )

    report = generate_markdown_report(user_id=9022, target="https://example.com")

    assert "GraphQL Endpoint Detection (scanner severity: INFO) - template=graphql-detect" in report
    assert "scanner severity: LOW" not in report
    assert "low and info" not in report.lower()


def test_report_generation_from_httpx_uses_response_observation_wording() -> None:
    add_finding(
        user_id=9024,
        finding={
            "source": "httpx",
            "target": "https://example.com",
            "risk_level": "info",
            "finding_count": 1,
            "httpx_services": [
                {
                    "url": "https://example.com",
                    "status_code": 200,
                    "title": "Example",
                    "web_server": "nginx",
                    "technologies": ["nginx"],
                }
            ],
        },
    )

    report = generate_markdown_report(user_id=9024, target="https://example.com")

    assert "httpx reported 1 HTTP response/URL observation(s)" in report
    assert "status=200 title=Example server=nginx technologies=nginx" in report
    assert "httpx finding for https://example.com" not in report
    assert "not proof of vulnerability, compromise, application health, or full service availability" in report


def test_report_generation_from_empty_httpx_preserves_uncertainty() -> None:
    add_finding(
        user_id=9025,
        finding={
            "source": "httpx",
            "target": "https://example.com",
            "risk_level": "info",
            "finding_count": 1,
            "httpx_services": [],
        },
    )

    report = generate_markdown_report(user_id=9025, target="https://example.com")

    assert "httpx recorded no usable structured response observations" in report
    assert "No conclusion about host availability, web application existence, vulnerabilities, or security posture" in report


def test_report_generation_from_katana_uses_crawl_observation_wording() -> None:
    add_finding(
        user_id=9027,
        finding={
            "source": "katana",
            "target": "https://example.com",
            "risk_level": "info",
            "finding_count": 2,
            "katana_summary": {
                "host_count": 1,
                "javascript_count": 1,
                "query_parameter_count": 1,
                "form_count": 1,
                "max_depth": 2,
            },
            "katana_observations": [
                {
                    "url": "https://example.com/app.js",
                    "endpoint_type": "javascript",
                    "depth": 1,
                },
                {
                    "url": "https://example.com/search?id=1",
                    "endpoint_type": "parameterized_url",
                    "status_code": 200,
                    "depth": 2,
                    "query_parameters": ["id"],
                    "forms": [{"action": "/login"}],
                },
            ],
        },
    )

    report = generate_markdown_report(user_id=9027, target="https://example.com")

    assert "Katana recorded 2 URL/endpoint crawl observation(s)" in report
    assert "crawl-summary: hosts=1 scripts=1 parameters=1 forms=1 max_depth=2" in report
    assert "params_observed=id forms_observed=1" in report
    assert "Katana crawl observations do not prove vulnerability, exploitability, sensitive exposure" in report
    assert "Katana finding for https://example.com" not in report
    assert "vulnerable to SQL injection" not in report


def test_report_generation_from_empty_katana_preserves_coverage_uncertainty() -> None:
    add_finding(
        user_id=9028,
        finding={
            "source": "katana",
            "target": "https://example.com",
            "risk_level": "info",
            "finding_count": 0,
            "katana_observations": [],
        },
    )

    report = generate_markdown_report(user_id=9028, target="https://example.com")

    assert "Katana recorded no usable structured crawl observations" in report
    assert "No conclusion about forms, endpoints, parameters, scripts, hidden content, vulnerabilities, or coverage" in report


def test_report_generation_from_playwright_uses_passive_observation_wording() -> None:
    add_finding(
        user_id=9026,
        finding={
            "source": "playwright",
            "target": "https://example.com",
            "risk_level": "info",
            "finding_count": 1,
            "playwright_observation": {
                "requested_url": "https://example.com",
                "final_url": "https://example.com",
                "title": "Example",
                "load_status": "domcontentloaded",
                "status_code": 429,
                "forms_count": 0,
                "inputs_count": 0,
                "links_count": 0,
            },
        },
    )

    report = generate_markdown_report(user_id=9026, target="https://example.com")

    assert "Playwright recorded passive browser-state observation" in report
    assert "status=429 load=domcontentloaded title=Example" in report
    assert "returned-state counts: forms=0 inputs=0 links=0" in report
    assert "HTTP 429 was observed as a rate-limited response; cause is unknown" in report
    assert "does not test XSS, SQL injection, CSRF" in report
    assert "Playwright finding for https://example.com" not in report
    assert "too many requests were sent" not in report.lower()


def test_report_generation_from_ffuf_uses_fuzzing_observation_wording() -> None:
    add_finding(
        user_id=9029,
        finding={
            "source": "ffuf",
            "target": "https://example.com",
            "risk_level": "info",
            "finding_count": 2,
            "ffuf_summary": {
                "status_codes": {"200": 1, "403": 1},
                "redirect_count": 0,
                "forbidden_count": 1,
                "server_error_count": 0,
            },
            "ffuf_results": [
                {
                    "url": "https://example.com/admin",
                    "path": "/admin",
                    "status_code": 200,
                    "content_length": 120,
                    "classification": "public",
                    "input_word": "admin",
                },
                {
                    "url": "https://example.com/config",
                    "path": "/config",
                    "status_code": 403,
                    "classification": "forbidden",
                    "input_word": "config",
                },
            ],
        },
    )

    report = generate_markdown_report(user_id=9029, target="https://example.com")

    assert "ffuf recorded 2 fuzzing response observation(s)" in report
    assert "fuzz-summary: statuses=200:1, 403:1 redirects=0 forbidden=1 server_errors=0" in report
    assert "/admin status=200 classification=public length=120 word=admin" in report
    assert "ffuf response observations do not prove vulnerability, exploitability, sensitive exposure" in report
    assert "ffuf finding for https://example.com" not in report
    assert "Sensitive files are exposed" not in report


def test_report_generation_from_empty_ffuf_preserves_coverage_uncertainty() -> None:
    add_finding(
        user_id=9030,
        finding={
            "source": "ffuf",
            "target": "https://example.com",
            "risk_level": "info",
            "finding_count": 0,
            "ffuf_results": [],
        },
    )

    report = generate_markdown_report(user_id=9030, target="https://example.com")

    assert "ffuf recorded no usable structured fuzzing response observations" in report
    assert "No conclusion about hidden content, endpoints, directories, files, parameters, virtual hosts, vulnerabilities, or coverage" in report


def test_report_generation_from_testssl_preserves_scanner_uncertainty() -> None:
    add_finding(
        user_id=9031,
        finding={
            "source": "testssl",
            "target": "example.com:443",
            "risk_level": "info",
            "finding_count": 2,
            "testssl_summary": {
                "supported_protocols": ["TLS 1.2", "TLS 1.3"],
                "notable_count": 2,
                "weak_protocol_count": 0,
            },
            "testssl_evidence": {
                "target": "example.com:443",
                "host": "example.com",
                "port": 443,
                "protocols": [
                    {"id": "TLS1_2", "name": "TLS 1.2", "finding": "offered", "severity": "OK"},
                    {"id": "TLS1_3", "name": "TLS 1.3", "finding": "offered", "severity": "OK"},
                ],
                "vulnerabilities": [
                    {
                        "id": "BREACH",
                        "finding": "potentially VULNERABLE, uses HTTP compression",
                        "severity": "MEDIUM",
                    }
                ],
                "notable_findings": [{"id": "early_data", "finding": "supported", "severity": "HIGH"}],
            },
        },
    )

    report = generate_markdown_report(user_id=9031, target="example.com:443")

    assert "testssl.sh recorded TLS scanner evidence for example.com:443" in report
    assert "Protocol observations: TLS 1.2, TLS 1.3" in report
    assert "BREACH severity=MEDIUM finding=potentially VULNERABLE, uses HTTP compression" in report
    assert "early_data severity=HIGH finding=supported" in report
    assert "preserve scanner severity/uncertainty and validate potential findings in context" in report
    assert "site is vulnerable to breach" not in report.lower()
    assert "robust" not in report.lower()
    assert "all ciphers are strong" not in report.lower()


def test_report_generation_from_tshark_preserves_packet_boundaries() -> None:
    add_finding(
        user_id=9032,
        finding={
            "source": "tshark",
            "target": "capture.pcap",
            "risk_level": "info",
            "finding_count": 3,
            "tshark_evidence": {
                "packet_count": 3,
                "byte_count": 354,
                "observed_protocols": [{"protocol": "dns", "packet_count": 1}, {"protocol": "tls", "packet_count": 1}],
                "observed_conversations": [{"src": "192.0.2.10", "dst": "198.51.100.20", "src_port": "53000", "dst_port": "443", "transport": "tcp", "packet_count": 2}],
                "dns_observations": [{"query_name": "example.com", "response_address": "93.184.216.34"}],
                "http_observations": [{"method": "GET", "host": "example.com", "uri": "/", "response_code": ""}],
                "tls_observations": [{"sni": "example.com", "version": "0x0303"}],
            },
        },
    )

    report = generate_markdown_report(user_id=9032, target="capture.pcap")

    assert "TShark recorded packet metadata for capture.pcap" in report
    assert "query=example.com capture_response=93.184.216.34" in report
    assert "request=GET host=example.com uri=/ response_status=not observed" in report
    assert "sni=example.com version=0x0303 handshake_success=not established by stored metadata" in report
    assert "do not prove exploitation, compromise, ownership, authentication success, vulnerability, successful TLS handshakes, or completed HTTP transactions" in report
    assert "exploit succeeded" not in report.lower()
    assert "tls handshake succeeded" not in report.lower()


def test_report_generation_from_gitleaks_preserves_secret_boundaries() -> None:
    add_finding(
        user_id=9033,
        finding={
            "source": "gitleaks",
            "target": "/tmp/artifact",
            "risk_level": "high",
            "finding_count": 1,
            "gitleaks_summary": {
                "finding_count": 1,
                "affected_files_count": 1,
                "rule_summary": {"github-pat": 1},
                "provider_summary": {"github": 1},
                "severity_summary": {"high": 1},
            },
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
        },
    )

    report = generate_markdown_report(user_id=9033, target="/tmp/artifact")

    assert "Gitleaks reported 1 redacted potential secret-pattern match(es)" in report
    assert "rule=github-pat file=src/config.py line=12 provider=github secret=<REDACTED> len=36 fingerprint=abc123 commit=deadbeef" in report
    assert "validity, current usability, ownership, unauthorized access, compromise, exfiltration, and repository security were not established" in report
    assert "active credentials" not in report.lower()
    assert "repository is compromised" not in report.lower()


def test_report_generation_from_empty_gitleaks_does_not_imply_no_secrets() -> None:
    add_finding(
        user_id=9034,
        finding={
            "source": "gitleaks",
            "target": "/tmp/artifact",
            "risk_level": "info",
            "finding_count": 0,
            "gitleaks_evidence": {"scan_root": "/tmp/artifact", "finding_count": 0, "findings": []},
        },
    )

    report = generate_markdown_report(user_id=9034, target="/tmp/artifact")

    assert "no matches were reported within the scanned scope/rules; this does not prove no secrets exist" in report
    assert "no secrets exist" in report
    assert "repository is secure" not in report.lower()


def test_report_generation_with_clean_nuclei_scan() -> None:
    add_finding(
        user_id=9003,
        finding={
            "source": "nuclei",
            "target": "hellosundaykids.com",
            "risk_level": "info",
            "finding_count": 0,
            "status": "clean",
            "summary": "No matching Nuclei findings were observed using the selected template/profile.",
        },
    )

    report = generate_markdown_report(user_id=9003, target="hellosundaykids.com")

    assert "Clean scan results recorded: 1." in report
    assert "## Clean Scan Notes" in report
    assert "Nuclei clean result for hellosundaykids.com" in report
    assert "No matching Nuclei findings were observed using the selected template/profile." in report
    assert "- Treat clean scans as point-in-time evidence, not proof that no vulnerabilities exist." in report


def test_report_sanitizes_legacy_clean_nuclei_fast_profile_without_metadata() -> None:
    add_finding(
        user_id=9023,
        finding={
            "source": "nuclei",
            "target": "legacy.example",
            "risk_level": "info",
            "finding_count": 0,
            "status": "clean",
            "summary": "No matching Nuclei findings were identified using the fast scan profile.",
        },
    )

    report = generate_markdown_report(user_id=9023, target="legacy.example")

    assert "No matching Nuclei findings were observed using the selected template/profile." in report
    assert "fast scan profile" not in report


def test_report_generation_with_mixed_scan_history() -> None:
    add_finding(
        user_id=9004,
        finding={
            "source": "nmap",
            "target": "example.com",
            "risk_level": "medium",
            "open_ports": [{"port": "443", "protocol": "tcp", "service": "https"}],
        },
    )
    add_finding(
        user_id=9004,
        finding={
            "source": "nuclei",
            "target": "example.com",
            "risk_level": "high",
            "finding_count": 1,
            "nuclei_findings": [{"template_id": "missing-security-headers", "severity": "low"}],
        },
    )
    add_finding(
        user_id=9004,
        finding={
            "source": "nmap_xml",
            "target": "example.com",
            "risk_level": "low",
            "open_ports": [{"port": "80", "protocol": "tcp", "service": "http"}],
        },
    )

    report = generate_markdown_report(user_id=9004, target="example.com")

    assert "example.com has 3 recorded scan run(s)" in report
    assert "- Nmap" in report
    assert "- Nmap XML Upload" in report
    assert "- Nuclei" in report
    assert "- Highest Risk: HIGH" in report
    assert "443/tcp https" in report
    assert "80/tcp http" in report
    assert "missing-security-headers" in report


def test_empty_history_handling() -> None:
    report = generate_markdown_report(user_id=9005, target="missing.example")

    assert "# Project Mongrel" in report
    assert "missing.example" in report
    assert "No scan history is available for this user or target." in report
    assert "- None" in report
    assert "No technical findings were recorded." in report
    assert "No historical scan runs found." in report


def test_ai_assessment_section_included_when_ai_succeeds() -> None:
    add_finding(
        user_id=9006,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        },
    )

    with patch("app.services.report_generator.ask_ai", return_value="Overall risk is medium. Prioritize SSH hardening.") as ask_ai:
        report = generate_markdown_report(user_id=9006, target="127.0.0.1", include_ai_assessment=True)

    prompt = ask_ai.call_args.args[0]
    assert "## Executive Assessment" in report
    assert "Overall risk is medium. Prioritize SSH hardening." in report
    assert "Only use the provided scan history and findings." in prompt
    assert "22/tcp ssh" in prompt


def test_ai_assessment_fallback_when_ai_disabled() -> None:
    add_finding(user_id=9007, finding={"source": "nuclei", "target": "example.com", "risk_level": "low"})

    with patch("app.services.report_generator.ask_ai", return_value="AI integration is not configured yet."):
        report = generate_markdown_report(user_id=9007, target="example.com", include_ai_assessment=True)

    assert "## Executive Assessment" in report
    assert "AI assessment unavailable: AI integration is not configured yet." in report
    assert "# Project Mongrel" in report
    assert "## Technical Findings" in report


def test_ai_assessment_fallback_when_ai_errors() -> None:
    add_finding(user_id=9008, finding={"source": "nuclei", "target": "example.com", "risk_level": "high"})

    with patch("app.services.report_generator.ask_ai", side_effect=TimeoutError("timeout")):
        report = generate_markdown_report(user_id=9008, target="example.com", include_ai_assessment=True)

    assert "AI assessment unavailable: timeout" in report
    assert "The deterministic report remains based on persisted scan history." in report


def test_report_generation_still_works_without_ai() -> None:
    add_finding(user_id=9009, finding={"source": "nmap", "target": "127.0.0.1", "risk_level": "low"})

    with patch("app.services.report_generator.ask_ai") as ask_ai:
        report = generate_markdown_report(user_id=9009, target="127.0.0.1")

    ask_ai.assert_not_called()
    assert "## Executive Assessment" not in report
    assert "## Recommendations" in report


def test_report_ai_prompt_is_grounded() -> None:
    prompt = build_report_ai_assessment_prompt(
        [
            {
                "source": "nuclei",
                "target": "example.com",
                "risk_level": "high",
                "finding_count": 1,
                "nuclei_findings": [{"template_id": "git-config-exposure", "severity": "high"}],
            }
        ],
        target="example.com",
    )

    assert "Only use the provided scan history and findings." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not invent CVEs." in prompt
    assert "git-config-exposure" in prompt
    assert "Never recommend closing ports blindly." in prompt
    assert "without inferring safety from absence of findings" in prompt
    assert "Treat TShark evidence as packet metadata only" in prompt
    assert "appears clean" not in prompt
    assert "Review whether the service is required" in prompt or "reviewing whether the service is required" in prompt


def test_report_uses_readable_timestamps_and_header() -> None:
    add_finding(user_id=9010, finding={"source": "nmap", "target": "127.0.0.1", "risk_level": "low"})

    report = generate_markdown_report(user_id=9010, target="127.0.0.1")

    assert "# Project Mongrel\nSecurity Assessment Report" in report
    assert "Target / Scope:\n127.0.0.1" in report
    generated_line = report.split("Generated:\n", 1)[1].split("\n", 1)[0]
    assert "UTC" in generated_line
    assert "+00:00" not in generated_line
    assert "-" not in generated_line


def test_single_target_report_does_not_say_multiple_targets() -> None:
    add_finding(user_id=9011, finding={"source": "nmap", "target": "localhost (127.0.0.1)", "risk_level": "low"})
    add_finding(user_id=9011, finding={"source": "nuclei", "target": "127.0.0.1", "risk_level": "info", "finding_count": 0})

    report = generate_markdown_report(user_id=9011)

    assert "Target / Scope:\n127.0.0.1" in report
    assert "Target / Scope:\nMultiple targets" not in report


def test_finding_aware_recommendations_appear() -> None:
    add_finding(
        user_id=9012,
        finding={
            "source": "nmap",
            "target": "example.com",
            "risk_level": "high",
            "open_ports": [
                {"port": "22", "protocol": "tcp", "service": "ssh"},
                {"port": "445", "protocol": "tcp", "service": "microsoft-ds"},
                {"port": "443", "protocol": "tcp", "service": "https"},
                {"port": "5432", "protocol": "tcp", "service": "postgresql"},
            ],
        },
    )

    report = generate_markdown_report(user_id=9012, target="example.com")

    assert "SSH: restrict access to trusted IPs or VPN" in report
    assert "SMB: block internet exposure" in report
    assert "HTTP/HTTPS: review security headers" in report
    assert "Databases: restrict network access" in report


def test_repeated_nmap_findings_are_deduplicated() -> None:
    ports = [{"port": "22", "protocol": "tcp", "service": "ssh"}]
    add_finding(user_id=9013, finding={"source": "nmap", "target": "127.0.0.1", "risk_level": "high", "open_ports": ports})
    add_finding(user_id=9013, finding={"source": "nmap", "target": "127.0.0.1", "risk_level": "high", "open_ports": ports})

    report = generate_markdown_report(user_id=9013, target="127.0.0.1")

    assert report.count("Nmap identified 1 open port(s)") == 1
    assert "Previous matching Nmap scan found; no port changes detected." in report
    assert "Nmap History" in report
    assert report.count("   - Target: 127.0.0.1") == 2


def test_report_header_supports_investigation_name() -> None:
    add_finding(user_id=9014, finding={"source": "nuclei", "target": "example.com", "risk_level": "low"})

    report = generate_markdown_report(user_id=9014, target="example.com", investigation_name="External perimeter review")

    assert "Investigation:\nExternal perimeter review" in report


def test_repeated_clean_nuclei_scans_are_deduplicated() -> None:
    clean_finding = {
        "source": "nuclei",
        "target": "example.com",
        "risk_level": "info",
        "finding_count": 0,
        "status": "clean",
        "summary": "No matching Nuclei findings were observed using the selected template/profile.",
    }
    add_finding(user_id=9015, finding=clean_finding)
    add_finding(user_id=9015, finding=clean_finding)

    report = generate_markdown_report(user_id=9015, target="example.com")

    assert "Two consecutive Nuclei scans completed with no matching findings." in report
    assert "Latest:" in report
    assert "Previous:" in report
    assert report.count("No matching Nuclei findings were observed using the selected template/profile.") < 3


def test_report_appendix_groups_history_by_tool() -> None:
    add_finding(user_id=9016, finding={"source": "nmap", "target": "example.com", "risk_level": "low"})
    add_finding(user_id=9016, finding={"source": "nuclei", "target": "example.com", "risk_level": "info", "finding_count": 0})

    report = generate_markdown_report(user_id=9016, target="example.com")

    assert "Nmap History" in report
    assert "Nuclei History" in report
    assert report.index("Nmap History") < report.index("Nuclei History")


def test_report_generation_includes_prowler_provider_context_counts_and_failed_checks() -> None:
    add_finding(
        user_id=9017,
        finding={
            "source": "prowler",
            "target": "standalone-aws",
            "target_key": "standalone-aws",
            "provider": "aws",
            "cloud_context": "standalone-aws",
            "risk_level": "info",
            "finding_count": 2,
            "status": "completed",
            "summary": "Prowler recorded 2 scanner-reported cloud posture finding(s) for AWS context standalone-aws.",
            "prowler_summary": {
                "finding_count": 2,
                "failed_count": 1,
                "passed_count": 1,
                "highest_severity": "Critical",
                "top_failed_services": ["iam: 1"],
            },
            "prowler_evidence": {
                "provider": "aws",
                "cloud_context": "standalone-aws",
                "finding_count": 2,
                "findings": [
                    {
                        "status": "FAIL",
                        "severity": "Critical",
                        "check_id": "iam_root_mfa",
                        "check_title": "Root MFA check",
                        "service": "iam",
                        "region": "global",
                        "resource_identifier": "AKIAABCDEFGHIJKLMNOP",
                    },
                    {"status": "PASS", "severity": "informational", "check_id": "s3_public_block", "service": "s3"},
                ],
            },
        },
    )

    report = generate_markdown_report(user_id=9017, target="standalone-aws")

    assert "- Prowler" in report
    assert "Provider: AWS" in report
    assert "Context: standalone-aws" in report
    assert "Total checks/findings parsed: 2" in report
    assert "Failed checks: 1" in report
    assert "Passed checks: 1" in report
    assert "Highest scanner-reported severity: Critical" in report
    assert "FAIL iam_root_mfa severity=Critical service=iam" in report
    assert "AKIAABCDEFGHIJKLMNOP" not in report
    assert "{\"" not in report


def test_report_generation_includes_metasploit_validation_without_raw_console_dump() -> None:
    add_finding(
        user_id=9018,
        finding={
            "source": "metasploit",
            "target": "example.com",
            "target_key": "example.com",
            "risk_level": "high",
            "finding_count": 1,
            "status": "completed",
            "summary": "Metasploit reported validation evidence. This is not proof of full compromise.",
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
                "proposal_id": "proposal-123",
                "artifact_ref": "assessment_artifact:9",
                "module": "auxiliary/scanner/http/http_version",
                "action_type": "auxiliary_validation",
                "port": 80,
            },
        },
    )

    report = generate_markdown_report(user_id=9018, target="example.com")

    assert "- Metasploit" in report
    assert "Module: auxiliary/scanner/http/http_version" in report
    assert "Action: auxiliary_validation" in report
    assert "Validation State: VALIDATED" in report
    assert "Subprocess Success: True" in report
    assert "Module Executed: True" in report
    assert "Session Established: False" in report
    assert "Proposal Reference: proposal-123" in report
    assert "Artifact Reference: assessment_artifact:9" in report
    assert "The target appears vulnerable" in report
    assert "not proof of full compromise" in report
    assert "Subprocess success, target response, network evidence, or module compatibility alone is not exploit success." in report
    assert "Session, persistence, privilege level, lateral movement, or data access is not inferred unless explicitly present" in report
    assert ("RAW " * 20) not in report
