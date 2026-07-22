import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.parsers.katana_parser import parse_katana_output, summarize_katana_observations
from app.tools.katana_runner import _build_katana_command, _normalize_field_scope, _normalize_known_files, _resolve_katana_executable, run_katana_scan


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["katana"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_katana_runner_success_uses_safe_subprocess_args() -> None:
    output = '{"url":"https://example.com/app.js","depth":1}\n'
    settings = Settings(_env_file=None, katana_scan_timeout_seconds=19, katana_crawl_depth=3, katana_concurrency=7, katana_rate_limit=40, katana_crawl_duration_seconds=90, katana_field_scope="fqdn", katana_known_files="robotstxt,sitemapxml")

    with (
        patch("app.tools.katana_runner.get_settings", return_value=settings),
        patch("app.tools.katana_runner.shutil.which", return_value="katana"),
        patch("app.tools.katana_runner.subprocess.run", return_value=_completed(stdout=output)) as run_mock,
    ):
        result = run_katana_scan("example.com")

    expected_command = _build_katana_command("katana", "https://example.com", crawl_depth=3, concurrency=7, rate_limit=40, crawl_duration_seconds=90, field_scope="fqdn", known_files="robotstxt,sitemapxml")
    run_mock.assert_called_once_with(
        expected_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=19,
        cwd=str(Path.cwd().resolve()),
        shell=False,
        check=False,
    )
    assert result["success"] is True
    assert result["target"] == "https://example.com"
    assert result["output"] == output
    assert result["error_type"] is None
    assert "-jc" in expected_command
    assert "-fx" in expected_command
    assert expected_command[expected_command.index("-fs") + 1] == "fqdn"
    assert _katana_flag_values(expected_command, "-kf") == ["robotstxt", "sitemapxml"]
    assert expected_command[expected_command.index("-ct") + 1] == "90s"
    assert "-ob" in expected_command


def test_katana_missing_binary_is_clean_failure() -> None:
    with (
        patch("app.tools.katana_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.katana_runner.shutil.which", return_value=None),
        patch("app.tools.katana_runner.Path.is_file", return_value=False),
        patch("app.tools.katana_runner.subprocess.run") as run_mock,
    ):
        result = run_katana_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "missing_binary"
    assert result["command"] is None
    run_mock.assert_not_called()


def test_katana_timeout_is_clean_failure() -> None:
    with (
        patch("app.tools.katana_runner.get_settings", return_value=Settings(_env_file=None, katana_scan_timeout_seconds=1)),
        patch("app.tools.katana_runner.shutil.which", return_value="katana"),
        patch("app.tools.katana_runner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="katana", timeout=1, output="", stderr="slow")),
    ):
        result = run_katana_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert result["error"] == "slow"


def test_katana_exit_code_two_stdout_diagnostic_is_clean_failure() -> None:
    diagnostic = 'invalid value "robotstxt,sitemapxml" for flag -kf: allowed values are all, robotstxt, sitemapxml\n'
    with (
        patch("app.tools.katana_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.katana_runner.shutil.which", return_value="katana"),
        patch("app.tools.katana_runner.subprocess.run", return_value=_completed(stdout=f"\x1b[31m{diagnostic}\x1b[0m", stderr="", returncode=2)),
    ):
        result = run_katana_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "execution_failed"
    assert result["returncode"] == 2
    assert result["error"] == diagnostic.strip()
    assert "\x1b" not in str(result["error"])


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_katana_target_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_katana_scan(target)


def test_katana_path_discovery() -> None:
    with patch("app.tools.katana_runner.shutil.which", return_value="/opt/bin/katana"):
        assert _resolve_katana_executable() == "/opt/bin/katana"


def test_katana_parser_normalizes_jsonl_and_json() -> None:
    services = parse_katana_output(
        "\n".join(
            [
                '{"url":"https://example.com/app.js","depth":1,"source":"https://example.com","response":{"status_code":200}}',
                '{"url":"https://example.com/search?q=test","method":"GET","depth":2,"forms":[{"action":"/login","method":"POST","inputs":["user"]}]}',
            ]
        )
    )
    summary = summarize_katana_observations(services)

    assert services[0]["endpoint_type"] == "javascript"
    assert services[0]["status_code"] == 200
    assert services[1]["query_parameters"] == ["q"]
    assert services[1]["forms"] == [{"action": "/login", "method": "POST", "inputs": ["user"]}]
    assert summary["url_count"] == 2
    assert summary["host_count"] == 1
    assert summary["javascript_count"] == 1
    assert summary["query_parameters"] == ["q"]
    assert summary["form_count"] == 1
    assert summary["max_depth"] == 2


def test_katana_command_clamps_professional_bounded_profile() -> None:
    command = _build_katana_command("katana", "https://example.com", crawl_depth=99, concurrency=999, rate_limit=999, crawl_duration_seconds=9999, max_response_size_bytes=99_999_999)

    assert command[command.index("-d") + 1] == "10"
    assert command[command.index("-c") + 1] == "50"
    assert command[command.index("-rl") + 1] == "300"
    assert command[command.index("-ct") + 1] == "900s"
    assert command[command.index("-mrs") + 1] == "8388608"


def test_katana_command_can_disable_optional_discovery_without_raw_flags() -> None:
    command = _build_katana_command("katana", "https://example.com", js_crawl=False, form_extraction=False, known_files="")

    assert "-jc" not in command
    assert "-fx" not in command
    assert "-kf" not in command
    assert "-j" in command
    assert "-silent" in command


def test_katana_command_uses_repeated_known_file_flags_for_installed_cli() -> None:
    command = _build_katana_command("katana", "https://example.com", known_files="robotstxt,sitemapxml")

    assert _katana_flag_values(command, "-kf") == ["robotstxt", "sitemapxml"]
    assert "robotstxt,sitemapxml" not in command


def test_katana_scope_and_known_files_are_validated() -> None:
    assert _normalize_field_scope("rdn") == "rdn"
    assert _normalize_known_files("robotstxt,sitemapxml,robotstxt") == ["robotstxt", "sitemapxml"]
    assert _normalize_known_files("all,robotstxt") == ["all"]

    with pytest.raises(ValueError, match="field scope"):
        _normalize_field_scope(".*")
    with pytest.raises(ValueError, match="known-files"):
        _normalize_known_files("robotstxt;id")
    with pytest.raises(ValueError, match="known-files"):
        _normalize_known_files("private")


def test_katana_invalid_configuration_fails_cleanly() -> None:
    with (
        patch("app.tools.katana_runner.get_settings", return_value=Settings(_env_file=None, katana_field_scope=".*")),
        patch("app.tools.katana_runner.shutil.which", return_value="katana"),
        patch("app.tools.katana_runner.subprocess.run") as run_mock,
    ):
        result = run_katana_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "invalid_configuration"
    assert result["command"] is None
    run_mock.assert_not_called()


def _katana_flag_values(command: list[str], flag: str) -> list[str]:
    return [command[index + 1] for index, value in enumerate(command[:-1]) if value == flag]
