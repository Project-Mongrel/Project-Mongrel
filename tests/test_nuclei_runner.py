from io import StringIO
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.parsers.nuclei_parser import parse_nuclei_results
from app.tools.nuclei_runner import _build_nuclei_command, _resolve_nuclei_executable, run_nuclei_scan


def _expected_nuclei_command(executable: str = "nuclei", target: str = "https://example.com") -> list[str]:
    return [
        executable,
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-no-color",
        "-omit-raw",
        "-omit-template",
        "-disable-update-check",
        "-severity",
        "info,low,medium,high,critical",
        "-type",
        "http,ssl,dns,tcp,whois",
        "-follow-host-redirects",
        "-max-redirects",
        "3",
        "-rate-limit",
        "25",
        "-concurrency",
        "10",
        "-bulk-size",
        "10",
        "-timeout",
        "5",
        "-retries",
        "1",
        "-response-size-read",
        "1048576",
        "-no-stdin",
        "-tags",
        "exposure,misconfig,tech,panel,headers",
        "-exclude-tags",
        "dos,fuzz,bruteforce,intrusive",
    ]


def test_empty_nuclei_target_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        run_nuclei_scan("   ")


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_nuclei_target_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_nuclei_scan(target)


def test_nuclei_preserves_https_url_scheme() -> None:
    process = FakeNucleiProcess(returncode=0, stdout="", stderr="")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        result = run_nuclei_scan("https://scanme.nmap.org")

    assert result["target"] == "https://scanme.nmap.org"
    assert popen_mock.call_args.args[0] == _expected_nuclei_command(target="https://scanme.nmap.org")


def test_nuclei_preserves_http_url_scheme() -> None:
    process = FakeNucleiProcess(returncode=0, stdout="", stderr="")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        result = run_nuclei_scan("http://example.com")

    assert result["target"] == "http://example.com"
    assert popen_mock.call_args.args[0] == _expected_nuclei_command(target="http://example.com")


def test_nuclei_defaults_bare_hostname_to_https() -> None:
    process = FakeNucleiProcess(returncode=0, stdout="", stderr="")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        result = run_nuclei_scan("scanme.nmap.org")

    assert result["target"] == "https://scanme.nmap.org"
    assert popen_mock.call_args.args[0] == _expected_nuclei_command(target="https://scanme.nmap.org")


@pytest.mark.parametrize("target", ["https://", "https:///scanme.nmap.org", "ftp://example.com"])
def test_malformed_nuclei_url_rejected_cleanly(target: str) -> None:
    with pytest.raises(ValueError, match="valid http or https URL or hostname"):
        run_nuclei_scan(target)


def test_nuclei_subprocess_called_with_list_args_and_shell_false() -> None:
    process = FakeNucleiProcess(returncode=0, stdout='{"template-id":"one"}\n', stderr="")
    settings = Settings(_env_file=None)

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        result = run_nuclei_scan("https://example.com")

    popen_mock.assert_called_once_with(
        _expected_nuclei_command(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        cwd=str(Path.cwd().resolve()),
        shell=False,
    )
    assert result["target"] == "https://example.com"
    assert result["success"] is True
    assert result["output"] == '{"template-id":"one"}'
    assert result["error"] == ""
    assert result["error_type"] is None
    assert result["returncode"] == 0
    assert result["exit_code"] == 0
    assert result["command"] == _expected_nuclei_command()
    assert result["working_directory"] == str(Path.cwd().resolve())
    assert result["stdout_len"] == len('{"template-id":"one"}')
    assert result["stderr_len"] == 0


def test_nuclei_command_uses_custom_configured_path() -> None:
    process = FakeNucleiProcess(returncode=0, stdout="", stderr="")
    settings = Settings(_env_file=None, nuclei_path="C:\\Tools\\Nuclei\\nuclei.exe")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        run_nuclei_scan("https://example.com")

    assert popen_mock.call_args.args[0] == _expected_nuclei_command("C:\\Tools\\Nuclei\\nuclei.exe")


def test_nuclei_subprocess_timeout_uses_config_value() -> None:
    process = FakeNucleiProcess(returncode=-9, stdout="", stderr="", timeout=True)
    settings = Settings(_env_file=None, nuclei_scan_timeout_seconds=444)

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process),
    ):
        result = run_nuclei_scan("https://example.com")

    assert process.wait_timeouts == [444]
    assert result["error_type"] == "timeout"


def test_nuclei_command_uses_configured_rate_limit_timeout_and_retries() -> None:
    process = FakeNucleiProcess(returncode=0, stdout="", stderr="")
    settings = Settings(
        _env_file=None,
        nuclei_tags="exposure,tech",
        nuclei_rate_limit=10,
        nuclei_request_timeout=3,
        nuclei_retries=2,
    )

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        run_nuclei_scan("https://example.com")

    assert popen_mock.call_args.args[0] == [
        "nuclei",
        "-u",
        "https://example.com",
        "-jsonl",
        "-silent",
        "-no-color",
        "-omit-raw",
        "-omit-template",
        "-disable-update-check",
        "-severity",
        "info,low,medium,high,critical",
        "-type",
        "http,ssl,dns,tcp,whois",
        "-follow-host-redirects",
        "-max-redirects",
        "3",
        "-rate-limit",
        "10",
        "-concurrency",
        "10",
        "-bulk-size",
        "10",
        "-timeout",
        "3",
        "-retries",
        "2",
        "-response-size-read",
        "1048576",
        "-no-stdin",
        "-tags",
        "exposure,tech",
        "-exclude-tags",
        "dos,fuzz,bruteforce,intrusive",
    ]


def test_nuclei_command_supports_professional_filters_and_template_selection() -> None:
    settings = Settings(
        _env_file=None,
        nuclei_tags="exposure,cve",
        nuclei_exclude_tags="dos,intrusive",
        nuclei_severities="low,medium,high,critical",
        nuclei_exclude_severities="info",
        nuclei_protocol_types="http,ssl",
        nuclei_template_paths="http/exposures,ssl",
        nuclei_template_profile="profiles/web-basic.yaml",
        nuclei_template_ids="git-config,ssl-dns-names",
        nuclei_exclude_template_ids="default-login",
        nuclei_rate_limit=999,
        nuclei_concurrency=999,
        nuclei_bulk_size=999,
        nuclei_request_timeout=999,
        nuclei_retries=999,
        nuclei_max_redirects=999,
        nuclei_response_size_read=99_999_999,
    )

    command = _build_nuclei_command("nuclei", "https://example.com", settings)

    assert command[command.index("-severity") + 1] == "low,medium,high,critical"
    assert command[command.index("-exclude-severity") + 1] == "info"
    assert command[command.index("-type") + 1] == "http,ssl"
    assert command[command.index("-tags") + 1] == "exposure,cve"
    assert command[command.index("-exclude-tags") + 1] == "dos,intrusive"
    assert command[command.index("-template-id") + 1] == "git-config,ssl-dns-names"
    assert command[command.index("-exclude-id") + 1] == "default-login"
    assert command[command.index("-templates") + 1] == "http/exposures,ssl"
    assert command[command.index("-profile") + 1] == "profiles/web-basic.yaml"
    assert command[command.index("-rate-limit") + 1] == "300"
    assert command[command.index("-concurrency") + 1] == "50"
    assert command[command.index("-bulk-size") + 1] == "50"
    assert command[command.index("-timeout") + 1] == "30"
    assert command[command.index("-retries") + 1] == "5"
    assert command[command.index("-max-redirects") + 1] == "10"
    assert command[command.index("-response-size-read") + 1] == "5000000"
    assert "-debug" not in command
    assert "-include-rr" not in command
    assert "-headless" not in command


def test_nuclei_rejects_malformed_configuration_without_subprocess() -> None:
    settings = Settings(_env_file=None, nuclei_tags="exposure;whoami")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen") as popen_mock,
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "invalid_configuration"
    assert result["command"] is None
    popen_mock.assert_not_called()


def test_nuclei_rejects_unsupported_protocol_type() -> None:
    settings = Settings(_env_file=None, nuclei_protocol_types="http,code")

    with pytest.raises(ValueError, match="unsupported value"):
        _build_nuclei_command("nuclei", "https://example.com", settings)


def test_nuclei_stream_output_is_bounded() -> None:
    process = FakeNucleiProcess(returncode=0, stdout=("x" * 12_000) + "\n" + ("y" * 40) + "\n", stderr="")
    settings = Settings(_env_file=None, nuclei_max_output_bytes=10)

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process),
    ):
        result = run_nuclei_scan("https://example.com")

    assert "[stdout truncated at 10000 bytes]" in str(result["output"])
    assert len(str(result["output"])) < 10_100


def test_nuclei_timeout_handled() -> None:
    process = FakeNucleiProcess(returncode=-9, stdout="partial output\n", stderr="", timeout=True)

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["target"] == "https://example.com"
    assert result["success"] is False
    assert result["output"] == "partial output"
    assert result["error"] == "Nuclei fast scan timed out. Try a smaller target or use a deeper scan profile later."
    assert result["error_type"] == "timeout"
    assert result["returncode"] == -9
    assert result["exit_code"] == -9
    assert result["stdout_len"] == len("partial output")
    assert result["stderr_len"] == 0
    assert process.killed is True


def test_nuclei_configured_executable_missing_at_subprocess_handled() -> None:
    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None, nuclei_path="missing-nuclei")),
        patch("app.tools.nuclei_runner.subprocess.Popen", side_effect=FileNotFoundError),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["target"] == "https://example.com"
    assert result["success"] is False
    assert result["output"] == ""
    assert result["error"] == "Nuclei executable was not found."
    assert result["error_type"] == "missing_binary"
    assert result["returncode"] is None


def test_nuclei_path_discovery() -> None:
    with patch("app.tools.nuclei_runner.shutil.which", return_value="/opt/bin/nuclei"):
        assert _resolve_nuclei_executable() == "/opt/bin/nuclei"


def test_nuclei_linux_executable_discovery() -> None:
    linux_nuclei = Path("/usr/local/bin/nuclei")

    with (
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.is_file", autospec=True, side_effect=lambda path: path == linux_nuclei),
    ):
        assert _resolve_nuclei_executable() == str(linux_nuclei)


def test_nuclei_home_go_bin_executable_discovery() -> None:
    home_directory = Path("/home/mongrel")
    go_bin_nuclei = home_directory / "go" / "bin" / "nuclei"

    with (
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.home", return_value=home_directory),
        patch("app.tools.nuclei_runner.Path.is_file", autospec=True, side_effect=lambda path: path == go_bin_nuclei),
    ):
        assert _resolve_nuclei_executable() == str(go_bin_nuclei)


def test_nuclei_windows_executable_discovery() -> None:
    windows_nuclei = Path(".venv") / "Scripts" / "nuclei.exe"

    with (
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.is_file", autospec=True, side_effect=lambda path: path == windows_nuclei),
    ):
        assert _resolve_nuclei_executable() == str(windows_nuclei)


def test_nuclei_linux_venv_executable_discovery() -> None:
    linux_venv_nuclei = Path(".venv") / "bin" / "nuclei"

    with (
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.is_file", autospec=True, side_effect=lambda path: path == linux_venv_nuclei),
    ):
        assert _resolve_nuclei_executable() == str(linux_venv_nuclei)


def test_nuclei_missing_binary_handled_before_subprocess() -> None:
    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.is_file", return_value=False),
        patch("app.tools.nuclei_runner.subprocess.Popen") as popen_mock,
    ):
        result = run_nuclei_scan("https://example.com")

    popen_mock.assert_not_called()
    assert result["success"] is False
    assert result["error"] == "Nuclei executable was not found."
    assert result["error_type"] == "missing_binary"
    assert result["command"] is None


def test_nuclei_execution_failure_classified() -> None:
    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", side_effect=PermissionError("denied")),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["success"] is False
    assert result["error"] == "Nuclei execution failed."
    assert result["error_type"] == "execution_failed"
    assert result["returncode"] is None


def test_nuclei_nonzero_exit_classified_as_execution_failed() -> None:
    process = FakeNucleiProcess(returncode=2, stdout="", stderr="bad flags\n")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["success"] is False
    assert result["error"] == "bad flags"
    assert result["error_type"] == "execution_failed"
    assert result["returncode"] == 2
    assert result["exit_code"] == 2


def test_nuclei_runner_error_classified() -> None:
    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", side_effect=RuntimeError("boom")),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["success"] is False
    assert result["error"] == "Nuclei runner error."
    assert result["error_type"] == "runner_error"


def test_nuclei_argv_generation() -> None:
    settings = Settings(_env_file=None, nuclei_tags="exposure", nuclei_rate_limit=7, nuclei_request_timeout=3, nuclei_retries=0)

    assert _build_nuclei_command("/usr/local/bin/nuclei", "scanme.nmap.org", settings) == [
        "/usr/local/bin/nuclei",
        "-u",
        "scanme.nmap.org",
        "-jsonl",
        "-silent",
        "-no-color",
        "-omit-raw",
        "-omit-template",
        "-disable-update-check",
        "-severity",
        "info,low,medium,high,critical",
        "-type",
        "http,ssl,dns,tcp,whois",
        "-follow-host-redirects",
        "-max-redirects",
        "3",
        "-rate-limit",
        "7",
        "-concurrency",
        "10",
        "-bulk-size",
        "10",
        "-timeout",
        "3",
        "-retries",
        "0",
        "-response-size-read",
        "1048576",
        "-no-stdin",
        "-tags",
        "exposure",
        "-exclude-tags",
        "dos,fuzz,bruteforce,intrusive",
    ]


def test_nuclei_linux_regression_uses_common_path_when_path_lookup_fails() -> None:
    process = FakeNucleiProcess(returncode=0, stdout="", stderr="")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.is_file", autospec=True, side_effect=lambda path: path == Path("/usr/local/bin/nuclei")),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        result = run_nuclei_scan("https://scanme.nmap.org")

    assert result["success"] is True
    assert popen_mock.call_args.args[0][0] == str(Path("/usr/local/bin/nuclei"))


def test_nuclei_streaming_stdout_jsonl_can_be_parsed_into_findings() -> None:
    process = FakeNucleiProcess(
        returncode=0,
        stdout='{"template-id":"one","info":{"severity":"high","name":"One"},"host":"https://example.com"}\n',
        stderr="",
    )

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process),
    ):
        result = run_nuclei_scan("https://example.com")

    findings = parse_nuclei_results(str(result["output"]))
    assert result["success"] is True
    assert findings[0]["template_id"] == "one"
    assert findings[0]["severity"] == "high"
    assert findings[0]["host"] == "https://example.com"


def test_nuclei_stderr_streaming_does_not_block() -> None:
    stderr = "\n".join(f"debug line {index}" for index in range(50)) + "\n"
    process = FakeNucleiProcess(returncode=0, stdout="", stderr=stderr)

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["success"] is True
    assert str(result["error"]).startswith("debug line 0")
    assert result["stderr_len"] == len(stderr.rstrip("\n"))


def test_nuclei_manual_success_empty_output_is_clean_scan() -> None:
    process = FakeNucleiProcess(returncode=0, stdout="", stderr="")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.Popen", return_value=process),
    ):
        result = run_nuclei_scan("https://scanme.nmap.org")

    assert result["success"] is True
    assert result["output"] == ""
    assert result["error"] == ""
    assert result["error_type"] is None
    assert result["stdout_len"] == 0
    assert result["stderr_len"] == 0


class FakeNucleiProcess:
    def __init__(self, returncode: int, stdout: str, stderr: str, timeout: bool = False) -> None:
        self.returncode = returncode
        self.stdout = StringIO(stdout)
        self.stderr = StringIO(stderr)
        self.timeout = timeout
        self.killed = False
        self.wait_timeouts: list[int] = []

    def wait(self, timeout: int | None = None) -> int:
        if timeout is not None:
            self.wait_timeouts.append(timeout)
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired(cmd="nuclei", timeout=timeout)

        return self.returncode

    def kill(self) -> None:
        self.killed = True
