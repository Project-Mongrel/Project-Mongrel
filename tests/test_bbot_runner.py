from io import StringIO
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.tools import bbot_runner
from app.tools.bbot_runner import (
    BBOT_RUNTIME_INCOMPATIBLE_ERROR,
    BBOT_UNAPPROVED_PROFILE_ERROR,
    check_bbot_readiness,
    is_bbot_available,
    run_bbot_scan,
)


def _expected_bbot_command(executable: str = "bbot", target: str = "example.com", output_dir: Path | None = None) -> list[str]:
    output_dir = output_dir or Path("data") / "bbot" / target / "run-fixed"
    return [
        executable,
        "-t",
        target,
        "-o",
        str(output_dir),
        "-y",
        "--json",
        "-om",
        "json",
        "stdout",
        "-p",
        "subdomain-enum",
        "-rf",
        "passive",
        "-c",
        "scope.search_distance=0",
        "scope.report_distance=0",
        "dns.threads=10",
        "dns.brute_threads=100",
        "dns.timeout=5",
        "dns.retries=1",
        "web.http_timeout=10",
        "web.http_retries=1",
        "web.spider_distance=0",
        "web.spider_depth=1",
        "web.spider_links_per_page=10",
    ]


def test_is_bbot_available_true() -> None:
    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
    ):
        assert is_bbot_available() is True


def test_is_bbot_available_from_system_fallback() -> None:
    linux_bbot = Path("/usr/local/bin/bbot")

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.bbot_runner.shutil.which", return_value=None),
        patch("app.tools.bbot_runner.Path.is_file", autospec=True, side_effect=lambda path: path == linux_bbot),
    ):
        assert is_bbot_available() is True


def test_is_bbot_available_false() -> None:
    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.bbot_runner.shutil.which", return_value=None),
        patch("app.tools.bbot_runner.Path.is_file", return_value=False),
    ):
        assert is_bbot_available() is False


def test_empty_target_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        run_bbot_scan("   ")


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_shell_characters_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_bbot_scan(target)


def test_bbot_subprocess_called_with_list_args_and_shell_false(tmp_path: Path) -> None:
    process = FakeBbotProcess(returncode=0, stdout="bbot output\n", stderr="")

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        result = run_bbot_scan("https://example.com/path")

    expected_command = _expected_bbot_command("bbot", "example.com", tmp_path / "example.com" / "run-fixed")
    popen_mock.assert_called_once_with(
        expected_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        cwd=str(Path.cwd().resolve()),
        shell=False,
    )
    assert "env" not in popen_mock.call_args.kwargs
    assert result["success"] is True
    assert result["target"] == "example.com"
    assert result["output"] == "bbot output"
    assert result["error"] == ""
    assert result["returncode"] == 0
    assert "elapsed_seconds" in result
    assert result["output_dir"] == str(tmp_path / "example.com" / "run-fixed")
    assert result["command"] == expected_command
    assert result["working_directory"] == str(Path.cwd().resolve())
    assert process.wait_timeouts == [600]


def test_bbot_timeout_handled(tmp_path: Path) -> None:
    process = FakeBbotProcess(returncode=-9, stdout="partial output\n", stderr="partial error\n", timeout=True)

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["output"] == "partial output"
    assert result["error"] == "partial error"
    assert result["returncode"] == -9
    assert process.killed is True


def test_bbot_timeout_harvests_json_output(tmp_path: Path) -> None:
    json_output_dir = tmp_path / "example.com" / "run-fixed" / "scan" / "output"
    json_output_dir.mkdir(parents=True)
    json_file = json_output_dir / "output.jsonl"
    json_file.write_text('{"type":"DNS_NAME","data":"partial.example.com"}\n', encoding="utf-8")
    process = FakeBbotProcess(returncode=-9, stdout="partial stdout\n", stderr="partial error\n", timeout=True)

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert "partial stdout" in result["output"]
    assert '{"type":"DNS_NAME","data":"partial.example.com"}' in result["output"]
    assert result["json_output_found"] is True
    assert result["json_output_paths"] == [str(json_file)]
    assert process.killed is True


def test_bbot_missing_binary_handled(tmp_path: Path) -> None:
    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value=None),
        patch("app.tools.bbot_runner.Path.is_file", return_value=False),
        patch("app.tools.bbot_runner.subprocess.Popen") as popen_mock,
    ):
        result = run_bbot_scan("example.com")

    popen_mock.assert_not_called()
    assert result["success"] is False
    assert result["output"] == ""
    assert result["error"] == "BBOT is not installed or not available on PATH."
    assert result["returncode"] is None


def test_bbot_subprocess_uses_configured_external_binary(tmp_path: Path) -> None:
    process = FakeBbotProcess(returncode=0, stdout="bbot output\n", stderr="")
    external_bbot = "/opt/bbot/bin/bbot"

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None, bbot_binary=external_bbot)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        result = run_bbot_scan("example.com")

    popen_mock.assert_called_once_with(
        _expected_bbot_command(external_bbot, "example.com", tmp_path / "example.com" / "run-fixed"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        cwd=str(Path.cwd().resolve()),
        shell=False,
    )
    assert result["success"] is True
    assert result["command"][0] == external_bbot


def test_bbot_command_supports_validated_professional_profile(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        bbot_presets="subdomain-enum,email-enum,web-basic",
        bbot_modules="http,sslcert,wafw00f",
        bbot_require_flags="safe",
        bbot_exclude_flags="active,web",
        bbot_scope_search_distance=9,
        bbot_scope_report_distance=9,
        bbot_dns_threads=999,
        bbot_dns_brute_threads=999,
        bbot_dns_timeout_seconds=999,
        bbot_dns_retries=999,
        bbot_web_http_timeout_seconds=999,
        bbot_web_http_retries=999,
        bbot_web_spider_distance=999,
        bbot_web_spider_depth=999,
        bbot_web_spider_links_per_page=999,
    )

    command = bbot_runner._build_bbot_command("bbot", "example.com", tmp_path, settings)

    assert "-p" in command
    assert "subdomain-enum" in command
    assert "email-enum" in command
    assert "web-basic" in command
    assert "-m" in command
    assert "http" in command
    assert "sslcert" in command
    assert "wafw00f" in command
    assert "scope.search_distance=2" in command
    assert "scope.report_distance=2" in command
    assert "dns.threads=50" in command
    assert "dns.brute_threads=500" in command
    assert "dns.timeout=20" in command
    assert "dns.retries=5" in command
    assert "web.http_timeout=30" in command
    assert "web.http_retries=5" in command
    assert "web.spider_distance=2" in command
    assert "web.spider_depth=4" in command
    assert "web.spider_links_per_page=50" in command
    assert "--json" in command
    assert "-om" in command
    assert "json" in command
    assert "stdout" in command
    assert "--no-color" not in command
    assert "-eom" not in command
    assert "-ef" in command
    assert "active" in command
    assert "web" in command
    assert "loud" not in command
    assert "invasive" not in command
    assert "deadly" not in command


def test_bbot_default_argv_uses_bbot_286_compatible_flags(tmp_path: Path) -> None:
    command = bbot_runner._build_bbot_command("bbot", "example.com", tmp_path, Settings(_env_file=None))

    assert command[0] == "bbot"
    assert "--json" in command
    assert "-om" in command
    assert "json" in command
    assert "stdout" in command
    assert command[command.index("-rf") + 1] == "passive"
    assert "-ef" not in command
    assert "--no-color" not in command
    assert "-eom" not in command
    for unsupported_flag in ("loud", "invasive", "deadly", "web-heavy", "web-screenshots", "portscan"):
        assert unsupported_flag not in command


def test_bbot_unsupported_286_exclude_flags_rejected_without_subprocess(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, bbot_exclude_flags="loud,invasive,deadly,web-heavy,web-screenshots,portscan")

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=settings),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen") as popen_mock,
    ):
        result = run_bbot_scan("example.com")

    popen_mock.assert_not_called()
    assert result["success"] is False
    assert result["error_type"] == "invalid_configuration"
    assert "BBOT excluded flags contains unsupported value: loud." in str(result["error"])


def test_bbot_rejects_unknown_and_aggressive_profiles(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported value"):
        bbot_runner._build_bbot_command("bbot", "example.com", tmp_path, Settings(_env_file=None, bbot_presets="unknown"))

    with pytest.raises(ValueError, match=BBOT_UNAPPROVED_PROFILE_ERROR):
        bbot_runner._build_bbot_command("bbot", "example.com", tmp_path, Settings(_env_file=None, bbot_presets="kitchen-sink"))


def test_bbot_rejects_flag_injection_without_subprocess(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, bbot_modules="http;whoami")

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=settings),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen") as popen_mock,
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["error_type"] == "invalid_configuration"
    assert result["command"] is None
    popen_mock.assert_not_called()


def test_bbot_readiness_version_check() -> None:
    completed = subprocess.CompletedProcess(args=["bbot", "--version"], returncode=0, stdout="bbot 2.8.6\n", stderr="")
    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.bbot_runner.shutil.which", return_value="/usr/local/bin/bbot"),
        patch("app.tools.bbot_runner.subprocess.run", return_value=completed) as run_mock,
    ):
        result = check_bbot_readiness()

    assert run_mock.call_args.args[0] == ["/usr/local/bin/bbot", "--version"]
    assert run_mock.call_args.kwargs["shell"] is False
    assert result["ready"] is True
    assert result["version"] == "bbot 2.8.6"


def test_fcntl_error_classified_as_runtime_incompatible(tmp_path: Path) -> None:
    traceback = "Traceback (most recent call last):\n  File \"bbot\", line 1\nModuleNotFoundError: No module named 'fcntl'"
    process = FakeBbotProcess(returncode=1, stdout="", stderr=traceback)

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["error_type"] == "runtime_incompatible"
    assert result["error"] == BBOT_RUNTIME_INCOMPATIBLE_ERROR
    assert "Traceback" not in result["error"]
    assert "fcntl" not in result["error"]
    assert result["output"] == ""


def test_resource_error_classified_as_runtime_incompatible_if_fatal(tmp_path: Path) -> None:
    traceback = 'Traceback (most recent call last):\nModuleNotFoundError: No module named "resource"'
    process = FakeBbotProcess(returncode=1, stdout=traceback, stderr="")

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["error_type"] == "runtime_incompatible"
    assert result["error"] == BBOT_RUNTIME_INCOMPATIBLE_ERROR
    assert "Traceback" not in result["error"]
    assert "resource" not in result["error"]


def test_bbot_failure_result_shape(tmp_path: Path) -> None:
    process = FakeBbotProcess(returncode=2, stdout="", stderr="bad target\n")

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["target"] == "example.com"
    assert result["output"] == ""
    assert result["error"] == "bad target"
    assert result["error_type"] == "bbot_failed"
    assert result["returncode"] == 2
    assert "elapsed_seconds" in result


def test_bbot_failure_stderr_strips_ansi_control_sequences(tmp_path: Path) -> None:
    process = FakeBbotProcess(returncode=2, stdout="", stderr="\x1b[31mbad target\x1b[0m\r\n\x1b[?25h")

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["error"] == "bad target"
    assert "\x1b" not in str(result["error"])


def test_bbot_failed_run_does_not_harvest_stale_target_output(tmp_path: Path) -> None:
    stale_output_dir = tmp_path / "example.com" / "run-old" / "scan" / "output"
    stale_output_dir.mkdir(parents=True)
    stale_file = stale_output_dir / "output.jsonl"
    stale_file.write_text('{"type":"DNS_NAME","data":"stale.example.com"}\n', encoding="utf-8")
    process = FakeBbotProcess(returncode=2, stdout="", stderr="bad target\n")

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fresh")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["output"] == ""
    assert result["json_output_found"] is False
    assert result["json_output_paths"] == []
    assert str(stale_file) not in str(result)
    assert result["output_dir"] == str(tmp_path / "example.com" / "run-fresh")


def test_bbot_json_output_is_harvested_after_process_exit(tmp_path: Path) -> None:
    json_output_dir = tmp_path / "example.com" / "run-fixed" / "scan" / "output"
    json_output_dir.mkdir(parents=True)
    json_file = json_output_dir / "output.jsonl"
    json_file.write_text('{"type":"DNS_NAME","data":"app.example.com"}\n', encoding="utf-8")
    process = FakeBbotProcess(returncode=0, stdout="bbot complete\n", stderr="")

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is True
    assert "bbot complete" in result["output"]
    assert '{"type":"DNS_NAME","data":"app.example.com"}' in result["output"]
    assert result["json_output_found"] is True
    assert result["json_output_paths"] == [str(json_file)]


def test_bbot_json_output_is_bounded(tmp_path: Path) -> None:
    json_output_dir = tmp_path / "example.com" / "run-fixed" / "scan" / "output"
    json_output_dir.mkdir(parents=True)
    json_file = json_output_dir / "output.jsonl"
    json_file.write_text("x" * 20_000, encoding="utf-8")
    process = FakeBbotProcess(returncode=0, stdout="", stderr="")

    with (
        patch("app.tools.bbot_runner.get_settings", return_value=Settings(_env_file=None, bbot_max_output_bytes=10)),
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.uuid4", return_value=SimpleNamespace(hex="fixed")),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is True
    assert result["output_truncated"] is True
    assert "[json truncated at 10000 bytes]" in result["output"]


class FakeBbotProcess:
    def __init__(self, returncode: int, stdout: str, stderr: str, timeout: bool = False) -> None:
        self.returncode = returncode
        self.stdout = StringIO(stdout)
        self.stderr = StringIO(stderr)
        self.timeout = timeout
        self.killed = False
        self.wait_calls = 0
        self.wait_timeouts: list[int] = []

    def wait(self, timeout: int | None = None) -> int:
        self.wait_calls += 1
        if timeout is not None:
            self.wait_timeouts.append(timeout)
        if self.timeout and self.wait_calls == 1:
            raise subprocess.TimeoutExpired(cmd=["bbot"], timeout=timeout)
        return self.returncode

    def kill(self) -> None:
        self.killed = True
