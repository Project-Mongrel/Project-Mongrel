import pytest

from app.services.metasploit_policy import build_metasploit_action_request, metasploit_request_fingerprint


def test_metasploit_policy_accepts_supported_actions() -> None:
    request = build_metasploit_action_request(
        module="auxiliary/scanner/http/http_version",
        action_type="auxiliary_validation",
        target="example.com",
        port=80,
        options={"TARGETURI": "/"},
        timeout_seconds=60,
    )

    assert request["module"] == "auxiliary/scanner/http/http_version"
    assert request["action_type"] == "auxiliary_validation"
    assert request["risk_tier"] == "low"
    assert request["fingerprint"] == metasploit_request_fingerprint(request)


def test_metasploit_policy_rejects_unknown_or_malformed_modules() -> None:
    with pytest.raises(ValueError):
        build_metasploit_action_request(module="auxiliary/scanner/unknown", action_type="auxiliary_validation", target="example.com", port=80)
    with pytest.raises(ValueError):
        build_metasploit_action_request(module="auxiliary/scanner/http/http_version; sessions", action_type="auxiliary_validation", target="example.com", port=80)


def test_metasploit_policy_rejects_unsupported_actions_and_options() -> None:
    with pytest.raises(ValueError):
        build_metasploit_action_request(module="auxiliary/scanner/http/http_version", action_type="exploit_validation", target="example.com", port=80)
    with pytest.raises(ValueError):
        build_metasploit_action_request(module="auxiliary/scanner/http/http_version", action_type="auxiliary_validation", target="example.com", port=80, options={"CMD": "id"})


def test_metasploit_policy_rejects_injection_values() -> None:
    with pytest.raises(ValueError):
        build_metasploit_action_request(module="auxiliary/scanner/http/http_version", action_type="auxiliary_validation", target="example.com;id", port=80)
    with pytest.raises(ValueError):
        build_metasploit_action_request(
            module="auxiliary/scanner/http/http_version",
            action_type="auxiliary_validation",
            target="example.com",
            port=80,
            options={"TARGETURI": "/\nrun"},
        )
