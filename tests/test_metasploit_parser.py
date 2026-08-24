from app.parsers.metasploit_parser import parse_metasploit_validation_result


def test_metasploit_parser_validated_is_not_full_compromise() -> None:
    parsed = parse_metasploit_validation_result(
        {
            "success": True,
            "module": "exploit/multi/http/struts2_content_type_ognl",
            "action_type": "check",
            "target": "example.com",
            "port": 80,
            "output": "The target appears vulnerable.",
        }
    )

    assert parsed["validation_state"] == "VALIDATED"
    assert parsed["subprocess_success"] is True
    assert parsed["module_executed"] is True
    assert parsed["session_established"] is False
    assert "not proof of full compromise" in parsed["summary"]
    assert "Subprocess success means msfconsole completed" in " ".join(parsed["limitations"])
    assert "No CVE, session, persistence" in " ".join(parsed["limitations"])


def test_metasploit_parser_not_reproduced_does_not_mean_secure() -> None:
    parsed = parse_metasploit_validation_result({"success": True, "output": "The target does not appear to be vulnerable."})

    assert parsed["validation_state"] == "NOT_REPRODUCED"
    assert "not proof that the target is secure" in parsed["summary"]


def test_metasploit_parser_timeout_is_blocked_not_safe() -> None:
    parsed = parse_metasploit_validation_result({"success": False, "error_type": "timeout", "error": "timeout"})

    assert parsed["validation_state"] == "BLOCKED"
    assert "does not mean the target is safe" in parsed["summary"]


def test_metasploit_parser_execution_failure_is_failed_not_safe() -> None:
    parsed = parse_metasploit_validation_result({"success": False, "error_type": "execution_failed", "error": "boom"})

    assert parsed["validation_state"] == "FAILED"
    assert "does not mean the target is safe" in parsed["summary"]


def test_metasploit_parser_ssh_version_banner_is_detected_not_vulnerable() -> None:
    parsed = parse_metasploit_validation_result(
        {
            "success": True,
            "module": "auxiliary/scanner/ssh/ssh_version",
            "action_type": "auxiliary_validation",
            "target": "example.com",
            "port": 22,
            "output": "[+] 10.0.0.1:22 - SSH server version: SSH-2.0-OpenSSH_8.9p1 Ubuntu",
        }
    )

    assert parsed["validation_state"] == "DETECTED"
    assert "service or version metadata" in parsed["summary"]
    assert "not proof of vulnerability, exploitation, or compromise" in parsed["summary"]
    lowered = parsed["summary"].lower()
    assert "exploited" not in lowered
    assert "appears vulnerable" not in lowered


def test_metasploit_parser_http_version_banner_is_detected_not_vulnerable() -> None:
    parsed = parse_metasploit_validation_result(
        {
            "success": True,
            "module": "auxiliary/scanner/http/http_version",
            "action_type": "auxiliary_validation",
            "target": "example.com",
            "port": 80,
            "output": "[+] 203.0.113.10:80 Apache/2.4.58 (Ubuntu)",
        }
    )

    assert parsed["validation_state"] == "DETECTED"
    assert "service or version metadata" in parsed["summary"]
    assert "not proof of vulnerability, exploitation, or compromise" in parsed["summary"]


def test_metasploit_parser_unknown_success_output_remains_inconclusive() -> None:
    parsed = parse_metasploit_validation_result(
        {
            "success": True,
            "module": "auxiliary/scanner/ssh/ssh_version",
            "output": "Module completed without structured metadata.",
        }
    )

    assert parsed["validation_state"] == "INCONCLUSIVE"
    assert parsed["subprocess_success"] is True
    assert parsed["session_established"] is False


def test_metasploit_parser_subprocess_success_does_not_imply_exploit_success() -> None:
    parsed = parse_metasploit_validation_result(
        {
            "success": True,
            "module": "exploit/multi/http/struts2_content_type_ognl",
            "action_type": "exploit_validation",
            "target": "example.com",
            "port": 80,
            "output": "Module completed successfully, no session was created.",
            "returncode": 0,
        }
    )

    assert parsed["validation_state"] == "INCONCLUSIVE"
    assert parsed["subprocess_success"] is True
    assert parsed["session_established"] is False
    assert "conclusive validation result" in parsed["summary"]


def test_metasploit_parser_session_established_is_explicit_state() -> None:
    parsed = parse_metasploit_validation_result(
        {
            "success": True,
            "module": "exploit/multi/http/struts2_content_type_ognl",
            "action_type": "exploit_validation",
            "target": "example.com",
            "port": 80,
            "output": "[*] Command shell session 1 opened (10.0.0.1:4444 -> 10.0.0.2:49152)",
            "returncode": 0,
        }
    )

    assert parsed["validation_state"] == "SESSION_ESTABLISHED"
    assert parsed["session_established"] is True
    assert "session was established" in parsed["summary"]
    assert "does not prove persistence, privilege level, lateral movement, or data access" in parsed["summary"]


def test_metasploit_parser_module_compatibility_does_not_imply_vulnerability() -> None:
    parsed = parse_metasploit_validation_result(
        {
            "success": True,
            "module": "exploit/multi/http/struts2_content_type_ognl",
            "action_type": "check",
            "target": "example.com",
            "port": 80,
            "output": "This module is compatible with the selected target type.",
            "returncode": 0,
        }
    )

    assert parsed["validation_state"] == "INCONCLUSIVE"
    assert "conclusive validation result" in parsed["summary"]
