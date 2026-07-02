from app.services.assessment_guard import (
    LOCKED_TOOL_LIMITATIONS,
    SECURE_PREAMBLE,
    build_assessment_guard,
    build_guard_prompt_section,
    is_secure_question,
)


def test_assessment_guard_identifies_missing_locked_tool_coverage() -> None:
    guard = build_assessment_guard(
        {
            "targets": [{"address": "example.com"}],
            "scans": [
                {"tool": "nmap", "status": "completed"},
                {"tool": "bbot", "status": "partial"},
                {"tool": "nuclei", "status": "failed"},
                {"tool": "httpx", "status": "completed"},
                {"tool": "katana", "status": "completed"},
            ],
            "findings": [
                {
                    "target": "example.com",
                    "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
                    "observation_counts": {"subdomain": 1},
                }
            ],
        },
        question="Is this secure?",
    )

    assert guard["completed_tools"] == ["httpx", "katana", "nmap"]
    assert guard["partial_tools"] == ["bbot"]
    assert guard["failed_tools"] == ["nuclei"]
    assert guard["represented_tools"] == ["bbot", "httpx", "katana", "nmap"]
    assert guard["missing_core_tools"] == []
    assert guard["is_complete"] is False
    assert guard["is_secure_question"] is True
    assert guard["secure_preamble"] == SECURE_PREAMBLE
    assert guard["observed_assets"]["hosts"] == ["example.com"]
    assert "22/tcp ssh" in guard["observed_assets"]["services"]
    assert "subdomain: 1" in guard["observed_assets"]["services"]
    assert "httpx not run" not in guard["locked_tool_limitations"]
    assert "Katana not run" not in guard["locked_tool_limitations"]
    assert "Metasploit validation not run" in guard["locked_tool_limitations"]
    assert set(LOCKED_TOOL_LIMITATIONS).issubset(set(guard["locked_tool_limitations"]))


def test_guard_prompt_section_lists_limitations_and_partial_evidence() -> None:
    prompt_section = build_guard_prompt_section(
        {
            "targets": [{"address": "example.com"}],
            "scans": [{"tool": "bbot", "status": "partial"}],
            "findings": [{"target": "example.com", "observation_counts": {"subdomain": 1}}],
        },
        question="Is it safe?",
    )

    assert "Partial tools: bbot" in prompt_section
    assert "Missing core tools: nmap, nuclei, httpx, katana" in prompt_section
    assert "httpx not run" not in prompt_section
    assert "Katana not run" not in prompt_section
    assert "TShark not run" in prompt_section
    assert "Observed hosts/targets: example.com" in prompt_section
    assert "Observed services: subdomain: 1" in prompt_section
    assert "Never state or imply that the target is secure or safe." in prompt_section
    assert SECURE_PREAMBLE in prompt_section


def test_is_secure_question_detects_safe_and_secure_language() -> None:
    assert is_secure_question("Is this secure?") is True
    assert is_secure_question("Is the target safe?") is True
    assert is_secure_question("What ports are open?") is False
