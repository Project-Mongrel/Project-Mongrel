import subprocess
from unittest.mock import Mock, patch

import pytest

from app.core.config import Settings
from app.tools.nuclei_runner import NUCLEI_TIMEOUT_SECONDS, run_nuclei_scan


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
        ["nuclei", "-u", "https://example.com", "-jsonl", "-silent"],
        capture_output=True,
        text=True,
        timeout=NUCLEI_TIMEOUT_SECONDS,
        check=False,
        shell=False,
    )
    assert result == {
        "target": "https://example.com",
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

    assert run_mock.call_args.args[0] == [
        "C:\\Tools\\Nuclei\\nuclei.exe",
        "-u",
        "https://example.com",
        "-jsonl",
        "-silent",
    ]


def test_nuclei_timeout_handled() -> None:
    timeout = subprocess.TimeoutExpired(
        cmd=["nuclei", "-u", "https://example.com", "-jsonl", "-silent"],
        timeout=NUCLEI_TIMEOUT_SECONDS,
        output="partial output",
        stderr="partial error",
    )

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.subprocess.run", side_effect=timeout),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result == {
        "target": "https://example.com",
        "success": False,
        "output": "partial output",
        "error": "partial error",
        "returncode": None,
    }


def test_nuclei_missing_executable_handled() -> None:
    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None, nuclei_path="missing-nuclei")),
        patch("app.tools.nuclei_runner.subprocess.run", side_effect=FileNotFoundError),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result == {
        "target": "https://example.com",
        "success": False,
        "output": "",
        "error": "Nuclei executable was not found.",
        "returncode": None,
    }
