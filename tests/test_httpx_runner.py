import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.parsers.httpx_parser import parse_httpx_output, summarize_httpx_services
from app.tools.httpx_runner import _build_httpx_command, _resolve_httpx_executable, run_httpx_scan


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["httpx"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_httpx_runner_success_uses_safe_subprocess_args() -> None:
    output = '{"url":"https://example.com","status_code":200,"title":"Example","webserver":"nginx","tech":["React"],"content_length":125}\n'
    settings = Settings(
        _env_file=None,
        httpx_scan_timeout_seconds=17,
        httpx_request_timeout_seconds=8,
        httpx_retries=2,
        httpx_threads=12,
        httpx_rate_limit=60,
        httpx_ports="http:80,https:443,8443",
        httpx_max_redirects=4,
        httpx_max_response_size_bytes=200_000,
    )

    with (
        patch("app.tools.httpx_runner.get_settings", return_value=settings),
        patch("app.tools.httpx_runner.shutil.which", return_value="httpx"),
        patch("app.tools.httpx_runner.subprocess.run", return_value=_completed(stdout=output)) as run_mock,
    ):
        result = run_httpx_scan("example.com")

    expected_command = _build_httpx_command(
        "httpx",
        "https://example.com",
        threads=12,
        rate_limit=60,
        request_timeout_seconds=8,
        retries=2,
        ports="http:80,https:443,8443",
        max_redirects=4,
        max_response_size_bytes=200_000,
    )
    run_mock.assert_called_once_with(
        expected_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=17,
        cwd=str(Path.cwd().resolve()),
        shell=False,
        check=False,
    )
    assert result["success"] is True
    assert result["target"] == "https://example.com"
    assert result["output"] == output
    assert result["error_type"] is None
    assert "-ports" in expected_command
    assert "http:80,https:443,8443" in expected_command
    assert "-ob" in expected_command
    assert "-i" not in expected_command


def test_httpx_missing_binary_is_clean_failure() -> None:
    with (
        patch("app.tools.httpx_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.httpx_runner.shutil.which", return_value=None),
        patch("app.tools.httpx_runner.Path.is_file", return_value=False),
        patch("app.tools.httpx_runner.subprocess.run") as run_mock,
    ):
        result = run_httpx_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "missing_binary"
    assert result["command"] is None
    run_mock.assert_not_called()


def test_httpx_timeout_is_clean_failure() -> None:
    with (
        patch("app.tools.httpx_runner.get_settings", return_value=Settings(_env_file=None, httpx_scan_timeout_seconds=1)),
        patch("app.tools.httpx_runner.shutil.which", return_value="httpx"),
        patch("app.tools.httpx_runner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="httpx", timeout=1, output="", stderr="slow")),
    ):
        result = run_httpx_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert result["error"] == "slow"


def test_httpx_command_uses_bounded_professional_metadata_profile() -> None:
    command = _build_httpx_command(
        "httpx",
        "https://example.com",
        threads=5000,
        rate_limit=9999,
        request_timeout_seconds=999,
        retries=99,
        ports="http:80,https:443,https:443",
        max_redirects=99,
        max_response_size_bytes=99_999_999,
    )

    assert command[0:3] == ["httpx", "-u", "https://example.com"]
    for flag in [
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-content-length",
        "-content-type",
        "-location",
        "-response-time",
        "-method",
        "-ip",
        "-cdn",
        "-cname",
        "-asn",
        "-probe",
        "-tls-probe",
        "-tls-grab",
        "-follow-host-redirects",
        "-ob",
    ]:
        assert flag in command
    assert command[command.index("-t") + 1] == "100"
    assert command[command.index("-rl") + 1] == "500"
    assert command[command.index("-timeout") + 1] == "30"
    assert command[command.index("-retries") + 1] == "5"
    assert command[command.index("-maxr") + 1] == "10"
    assert command[command.index("-rstr") + 1] == "5000000"
    assert command[command.index("-ports") + 1] == "http:80,https:443"


def test_httpx_rejects_malformed_ports_configuration() -> None:
    settings = Settings(_env_file=None, httpx_ports="80;whoami")
    with (
        patch("app.tools.httpx_runner.get_settings", return_value=settings),
        patch("app.tools.httpx_runner.shutil.which", return_value="httpx"),
        patch("app.tools.httpx_runner.subprocess.run") as run_mock,
    ):
        result = run_httpx_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "invalid_configuration"
    assert result["command"] is None
    run_mock.assert_not_called()


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_httpx_target_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_httpx_scan(target)


def test_httpx_path_discovery() -> None:
    with patch("app.tools.httpx_runner.shutil.which", return_value="/opt/bin/httpx"):
        assert _resolve_httpx_executable() == "/opt/bin/httpx"


def test_httpx_parser_normalizes_jsonl() -> None:
    services = parse_httpx_output(
        "\n".join(
            [
                '{"url":"https://example.com","status_code":301,"title":"Old","location":"https://www.example.com","tech":["nginx"],"cdn":true,"ip":"93.184.216.34","content_type":"text/html"}',
                '{"url":"https://www.example.com","status_code":200,"title":"Home","server":"Apache","content-length":42,"tls":{"probe":true,"authorization":"secret"},"cname":["edge.example.net"],"response_time":"120ms","header":{"set-cookie":"secret","server":"Apache"},"body":"secret body"}',
            ]
        )
    )
    summary = summarize_httpx_services(services)

    assert services[0]["redirect_location"] == "https://www.example.com"
    assert services[1]["web_server"] == "Apache"
    assert services[1]["content_length"] == 42
    assert services[1]["tls"] == {"probe": True}
    assert services[1]["cname"] == ["edge.example.net"]
    assert services[1]["response_time"] == "120ms"
    assert "body" not in services[1]["raw"]
    assert "header" not in services[1]["raw"]
    assert summary["service_count"] == 2
    assert summary["status_codes"] == {"301": 1, "200": 1}
    assert summary["technologies"] == ["nginx"]
    assert summary["ip_count"] == 1
    assert summary["cdn_count"] == 1
    assert summary["cname_count"] == 1
    assert summary["tls_count"] == 1
    assert summary["content_types"] == ["text/html"]
