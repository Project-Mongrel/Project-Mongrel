import subprocess
from unittest.mock import Mock, patch

import pytest

from app.core.config import Settings
from app.tools.nuclei_runner import run_nuclei_scan


def _expected_nuclei_command(executable: str = "nuclei") -> list[str]:
    return [
        executable,
        "-u",
        "example.com",
        "-jsonl",
        "-silent",
        "-severity",
        "low,medium,high,critical",
        "-tags",
        "exposure,misconfig,tech,panel,headers",
        "-rate-limit",
        "25",
        "-timeout",
        "5",
        "-retries",
        "1",
    ]


def test_empty_nuclei_target_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        run_nuclei_scan("   ")


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_nuclei_target_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_nuclei_scan(target)


def test_nuclei_subprocess_called_with_list_args_and_shell_false() -> None:
    completed_process = Mock(returncode=0, stdout='{"template-id":"one"}\n', stderr="")
    settings = Settings(_env_file=None)

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.subprocess.run", return_value=completed_process) as run_mock,
    ):
        result = run_nuclei_scan("https://example.com")

    run_mock.assert_called_once_with(
        _expected_nuclei_command(),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        shell=False,
    )
    assert result == {
        "target": "example.com",
        "success": True,
        "output": '{"template-id":"one"}\n',
        "error": "",
        "returncode": 0,
    }


def test_nuclei_command_uses_custom_configured_path() -> None:
    completed_process = Mock(returncode=0, stdout="", stderr="")
    settings = Settings(_env_file=None, nuclei_path="C:\\Tools\\Nuclei\\nuclei.exe")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.subprocess.run", return_value=completed_process) as run_mock,
    ):
        run_nuclei_scan("https://example.com")

    assert run_mock.call_args.args[0] == _expected_nuclei_command("C:\\Tools\\Nuclei\\nuclei.exe")


def test_nuclei_subprocess_timeout_uses_config_value() -> None:
    completed_process = Mock(returncode=0, stdout="", stderr="")
    settings = Settings(_env_file=None, nuclei_scan_timeout_seconds=444)

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.subprocess.run", return_value=completed_process) as run_mock,
    ):
        run_nuclei_scan("https://example.com")

    assert run_mock.call_args.kwargs["timeout"] == 444


def test_nuclei_command_uses_configured_rate_limit_timeout_and_retries() -> None:
    completed_process = Mock(returncode=0, stdout="", stderr="")
    settings = Settings(
        _env_file=None,
        nuclei_tags="exposure,tech",
        nuclei_rate_limit=10,
        nuclei_request_timeout=3,
        nuclei_retries=2,
    )

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.subprocess.run", return_value=completed_process) as run_mock,
    ):
        run_nuclei_scan("https://example.com")

    assert run_mock.call_args.args[0] == [
        "nuclei",
        "-u",
        "example.com",
        "-jsonl",
        "-silent",
        "-severity",
        "low,medium,high,critical",
        "-tags",
        "exposure,tech",
        "-rate-limit",
        "10",
        "-timeout",
        "3",
        "-retries",
        "2",
    ]


def test_nuclei_timeout_handled() -> None:
    timeout = subprocess.TimeoutExpired(
        cmd=_expected_nuclei_command(),
        timeout=180,
        output="partial output",
    )

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.subprocess.run", side_effect=timeout),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result == {
        "target": "example.com",
        "success": False,
        "output": "partial output",
        "error": "Nuclei fast scan timed out. Try a smaller target or use a deeper scan profile later.",
        "returncode": None,
    }


def test_nuclei_missing_executable_handled() -> None:
    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None, nuclei_path="missing-nuclei")),
        patch("app.tools.nuclei_runner.subprocess.run", side_effect=FileNotFoundError),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result == {
        "target": "example.com",
        "success": False,
        "output": "",
        "error": "Nuclei executable was not found.",
        "returncode": None,
    }
