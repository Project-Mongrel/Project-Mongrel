import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.parsers.katana_parser import parse_katana_output, summarize_katana_observations
from app.tools.katana_runner import _build_katana_command, _resolve_katana_executable, run_katana_scan


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["katana"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_katana_runner_success_uses_safe_subprocess_args() -> None:
    output = '{"url":"https://example.com/app.js","depth":1}\n'
    settings = Settings(_env_file=None, katana_scan_timeout_seconds=19, katana_crawl_depth=2)

    with (
        patch("app.tools.katana_runner.get_settings", return_value=settings),
        patch("app.tools.katana_runner.shutil.which", return_value="katana"),
        patch("app.tools.katana_runner.subprocess.run", return_value=_completed(stdout=output)) as run_mock,
    ):
        result = run_katana_scan("example.com")

    expected_command = _build_katana_command("katana", "https://example.com", 2)
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


def test_katana_command_clamps_depth() -> None:
    assert _build_katana_command("katana", "https://example.com", 99)[6] == "5"
