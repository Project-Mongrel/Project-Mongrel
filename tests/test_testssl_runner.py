import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.parsers.testssl_parser import normalize_testssl_output, summarize_testssl_evidence
from app.tools.testssl_runner import _build_testssl_command, _resolve_testssl_executable, run_testssl_scan


TESTSSL_JSON = """
[
  {"id":"cert_commonName","severity":"INFO","finding":"example.com"},
  {"id":"cert_issuer","severity":"INFO","finding":"Example CA"},
  {"id":"cert_notAfter","severity":"INFO","finding":"2030-01-01 00:00 +0000"},
  {"id":"cert_subjectAltName","severity":"INFO","finding":"DNS:example.com, DNS:www.example.com"},
  {"id":"TLS1","severity":"LOW","finding":"offered"},
  {"id":"TLS1_2","severity":"OK","finding":"offered"},
  {"id":"TLS1_3","severity":"OK","finding":"offered"},
  {"id":"heartbleed","severity":"OK","finding":"not vulnerable"},
  {"id":"cipherlist_NULL","severity":"HIGH","finding":"NULL ciphers not offered"},
  {"id":"HSTS","severity":"INFO","finding":"max-age=31536000"}
]
"""


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["testssl.sh"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_testssl_runner_success_uses_safe_subprocess_args() -> None:
    settings = Settings(_env_file=None, testssl_scan_timeout_seconds=19)

    def run_side_effect(command, **kwargs):
        Path(command[2]).write_text(TESTSSL_JSON, encoding="utf-8")
        return _completed(stdout="human output")

    with (
        patch("app.tools.testssl_runner.get_settings", return_value=settings),
        patch("app.tools.testssl_runner.shutil.which", return_value="testssl.sh"),
        patch("app.tools.testssl_runner.subprocess.run", side_effect=run_side_effect) as run_mock,
    ):
        result = run_testssl_scan("https://example.com")

    command = run_mock.call_args.args[0]
    assert command[0] == "testssl.sh"
    assert command[1] == "--jsonfile-pretty"
    assert command[-1] == "example.com:443"
    assert run_mock.call_args.kwargs["shell"] is False
    assert run_mock.call_args.kwargs["check"] is False
    assert run_mock.call_args.kwargs["timeout"] == 19
    assert result["success"] is True
    assert result["target"] == "example.com:443"
    assert result["json_output"].strip().startswith("[")


def test_testssl_missing_binary_is_clean_failure() -> None:
    with (
        patch("app.tools.testssl_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.testssl_runner.shutil.which", return_value=None),
        patch("app.tools.testssl_runner.Path.is_file", return_value=False),
        patch("app.tools.testssl_runner.subprocess.run") as run_mock,
    ):
        result = run_testssl_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "missing_binary"
    assert result["command"] is None
    run_mock.assert_not_called()


def test_testssl_timeout_is_clean_failure() -> None:
    with (
        patch("app.tools.testssl_runner.get_settings", return_value=Settings(_env_file=None, testssl_scan_timeout_seconds=1)),
        patch("app.tools.testssl_runner.shutil.which", return_value="testssl.sh"),
        patch("app.tools.testssl_runner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="testssl.sh", timeout=1, output="", stderr="slow")),
    ):
        result = run_testssl_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert result["error"] == "slow"


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_testssl_target_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_testssl_scan(target)


def test_testssl_path_discovery() -> None:
    with patch("app.tools.testssl_runner.shutil.which", return_value="/opt/bin/testssl.sh"):
        assert _resolve_testssl_executable() == "/opt/bin/testssl.sh"


def test_build_testssl_command_uses_explicit_argv() -> None:
    command = _build_testssl_command("testssl.sh", "example.com:443", Path("out.json"))

    assert command == [
        "testssl.sh",
        "--jsonfile-pretty",
        "out.json",
        "--warnings",
        "batch",
        "--connect-timeout",
        "10",
        "--openssl-timeout",
        "5",
        "--quiet",
        "example.com:443",
    ]


def test_build_testssl_command_supports_validated_profile_options() -> None:
    settings = Settings(
        _env_file=None,
        testssl_connect_timeout_seconds=999,
        testssl_openssl_timeout_seconds=999,
        testssl_ip_mode="one",
        testssl_starttls_protocol="smtp",
        testssl_ids_friendly=True,
    )

    command = _build_testssl_command("testssl.sh", "mail.example.com:25", Path("out.json"), settings)

    assert command == [
        "testssl.sh",
        "--jsonfile-pretty",
        "out.json",
        "--warnings",
        "batch",
        "--connect-timeout",
        "30",
        "--openssl-timeout",
        "30",
        "--quiet",
        "--ip",
        "one",
        "--starttls",
        "smtp",
        "--ids-friendly",
        "mail.example.com:25",
    ]


def test_build_testssl_command_supports_ipv4_and_ipv6_modes() -> None:
    ipv4_command = _build_testssl_command("testssl.sh", "example.com:443", Path("out.json"), Settings(_env_file=None, testssl_ip_mode="4"))
    ipv6_command = _build_testssl_command("testssl.sh", "example.com:443", Path("out.json"), Settings(_env_file=None, testssl_ip_mode="6"))

    assert "-4" in ipv4_command
    assert "-6" in ipv6_command


def test_testssl_rejects_invalid_config_without_subprocess() -> None:
    settings = Settings(_env_file=None, testssl_starttls_protocol="smtp;whoami")

    with (
        patch("app.tools.testssl_runner.get_settings", return_value=settings),
        patch("app.tools.testssl_runner.shutil.which", return_value="testssl.sh"),
        patch("app.tools.testssl_runner.subprocess.run") as run_mock,
    ):
        result = run_testssl_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "invalid_configuration"
    assert result["command"] is None
    run_mock.assert_not_called()


def test_testssl_ipv6_target_is_bracketed_for_testssl() -> None:
    with (
        patch("app.tools.testssl_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.testssl_runner.shutil.which", return_value="testssl.sh"),
        patch("app.tools.testssl_runner.subprocess.run", return_value=_completed()) as run_mock,
    ):
        result = run_testssl_scan("https://[2001:db8::1]")

    assert result["target"] == "[2001:db8::1]:443"
    assert run_mock.call_args.args[0][-1] == "[2001:db8::1]:443"


def test_testssl_oversized_json_is_clean_failure() -> None:
    settings = Settings(_env_file=None, testssl_max_json_bytes=10)

    def run_side_effect(command, **kwargs):
        Path(command[2]).write_text("[" + (" " * 12_000) + "]", encoding="utf-8")
        return _completed(stdout="human output")

    with (
        patch("app.tools.testssl_runner.get_settings", return_value=settings),
        patch("app.tools.testssl_runner.shutil.which", return_value="testssl.sh"),
        patch("app.tools.testssl_runner.subprocess.run", side_effect=run_side_effect),
    ):
        result = run_testssl_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "output_too_large"
    assert result["output_truncated"] is True
    assert result["json_len"] < 11_000


def test_testssl_json_normalization_extracts_tls_evidence() -> None:
    evidence = normalize_testssl_output(TESTSSL_JSON, target="example.com:443")
    summary = summarize_testssl_evidence(evidence)

    assert evidence["host"] == "example.com"
    assert evidence["port"] == 443
    assert evidence["certificate"]["issuer"] == "Example CA"
    assert evidence["certificate"]["subject_alt_names"] == "DNS:example.com, DNS:www.example.com"
    assert "TLS 1.0: offered" in evidence["weak_protocols"]
    assert evidence["vulnerabilities"][0]["id"] == "heartbleed"
    assert evidence["cipher_findings"][0]["id"] == "cipherlist_NULL"
    assert evidence["security_headers"][0]["id"] == "HSTS"
    assert summary["supported_protocols"] == ["TLS 1.0", "TLS 1.2", "TLS 1.3"]
    assert evidence["raw_record_count"] == 10
    assert "raw_json" not in evidence


def test_testssl_json_normalization_handles_nested_scan_result_shape() -> None:
    output = {
        "scanResult": [
            {
                "targetHost": "example.com",
                "serverDefaults": [
                    {"id": "cert_commonName", "severity": "INFO", "finding": "example.com"},
                    {"id": "cert_issuer", "severity": "INFO", "finding": "Example CA"},
                    {"id": "cert_notAfter_local", "severity": "INFO", "finding": "2030-01-01"},
                ],
                "scanResult": [
                    {"id": "TLS 1.2", "severity": "OK", "finding": "offered"},
                    {"id": "TLS 1.3", "severity": "OK", "finding": "offered"},
                    {"id": "cert_subjectAltName", "severity": "INFO", "finding": ["DNS:example.com", "DNS:www.example.com"]},
                    {"id": "heartbleed", "severity": "OK", "finding": "not vulnerable"},
                    {"id": "HSTS", "severity": "INFO", "finding": "not offered"},
                ],
            }
        ]
    }

    evidence = normalize_testssl_output(output, target="example.com:443")
    summary = summarize_testssl_evidence(evidence)

    assert evidence["certificate"]["common_name"] == "example.com"
    assert evidence["certificate"]["issuer"] == "Example CA"
    assert evidence["certificate"]["not_after"] == "2030-01-01"
    assert evidence["certificate"]["subject_alt_names"] == "DNS:example.com, DNS:www.example.com"
    assert summary["supported_protocols"] == ["TLS 1.2", "TLS 1.3"]
    assert evidence["vulnerabilities"][0]["id"] == "heartbleed"


def test_testssl_normalization_excludes_sensitive_header_material() -> None:
    output = """
[
  {"id":"header_set_cookie","severity":"INFO","finding":"Set-Cookie: sessionid=secret; HttpOnly"},
  {"id":"HSTS","severity":"INFO","finding":"max-age=31536000"},
  {"id":"TLS1_2","severity":"OK","finding":"offered"}
]
"""
    evidence = normalize_testssl_output(output, target="example.com:443")

    rendered = str(evidence)
    assert "sessionid=secret" not in rendered
    assert "Set-Cookie" not in rendered
    assert evidence["security_headers"] == [{"id": "HSTS", "finding": "max-age=31536000", "severity": "INFO"}]
