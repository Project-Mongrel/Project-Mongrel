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
    assert "not proof of full compromise" in parsed["summary"]
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


def test_metasploit_parser_unknown_success_output_remains_inconclusive() -> None:
    parsed = parse_metasploit_validation_result(
        {
            "success": True,
            "module": "auxiliary/scanner/ssh/ssh_version",
            "output": "Module completed without structured metadata.",
        }
    )

    assert parsed["validation_state"] == "INCONCLUSIVE"
