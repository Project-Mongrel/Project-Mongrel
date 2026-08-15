import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.parsers.ffuf_parser import parse_ffuf_output, summarize_ffuf_results
from app.tools.ffuf_runner import (
    DEFAULT_FFUF_WORDLIST,
    FFUF_MATCH_STATUS_CODES,
    FFUF_PROFILE_DEEP,
    FFUF_PROFILE_QUICK,
    FFUF_PROFILE_STANDARD,
    _build_ffuf_command,
    _build_fuzz_url,
    _count_wordlist_entries,
    _normalize_ffuf_extensions,
    _resolve_ffuf_executable,
    resolve_ffuf_profile_wordlist,
    run_ffuf_scan,
)


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["ffuf"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_ffuf_runner_success_uses_safe_subprocess_args(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\napi\n", encoding="utf-8")
    output = '{"results":[{"url":"https://example.com/admin","status":200,"length":120,"words":10,"lines":3,"input":{"FUZZ":"admin"}}]}'
    settings = Settings(_env_file=None, ffuf_scan_timeout_seconds=17, ffuf_threads=3, ffuf_rate_limit=11, ffuf_wordlist_path=wordlist)

    with (
        patch("app.tools.ffuf_runner.get_settings", return_value=settings),
        patch("app.tools.ffuf_runner.shutil.which", return_value="ffuf"),
        patch("app.tools.ffuf_runner.subprocess.run", return_value=_completed(stdout=output)) as run_mock,
    ):
        result = run_ffuf_scan("example.com")

    expected_command = _build_ffuf_command("ffuf", "https://example.com/FUZZ", wordlist, threads=3, rate_limit=11)
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
    assert result["wordlist_count"] == 2
    assert result["fuzz_url"] == "https://example.com/FUZZ"
    assert result["ffuf_profile"] == "custom"
    assert expected_command[expected_command.index("-mc") + 1] == FFUF_MATCH_STATUS_CODES


def test_ffuf_missing_binary_is_clean_failure(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")

    with (
        patch("app.tools.ffuf_runner.get_settings", return_value=Settings(_env_file=None, ffuf_wordlist_path=wordlist)),
        patch("app.tools.ffuf_runner.shutil.which", return_value=None),
        patch("app.tools.ffuf_runner._ffuf_executable_candidates", return_value=()),
        patch("app.tools.ffuf_runner.subprocess.run") as run_mock,
    ):
        result = run_ffuf_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "missing_binary"
    assert result["command"] is None
    run_mock.assert_not_called()


def test_ffuf_missing_wordlist_is_clean_failure(tmp_path: Path) -> None:
    missing = tmp_path / "missing.txt"
    with (
        patch("app.tools.ffuf_runner.get_settings", return_value=Settings(_env_file=None, ffuf_wordlist_path=missing)),
        patch("app.tools.ffuf_runner.shutil.which", return_value="ffuf"),
        patch("app.tools.ffuf_runner.subprocess.run") as run_mock,
    ):
        result = run_ffuf_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "missing_wordlist"
    run_mock.assert_not_called()


def test_ffuf_quick_profile_uses_bundled_wordlist() -> None:
    info = resolve_ffuf_profile_wordlist(FFUF_PROFILE_QUICK, settings=Settings(_env_file=None))

    assert info["available"] is True
    assert info["profile"] == FFUF_PROFILE_QUICK
    assert info["wordlist_path"] == DEFAULT_FFUF_WORDLIST
    assert info["wordlist_count"] == 19


def test_ffuf_standard_profile_uses_configured_standard_wordlist(tmp_path: Path) -> None:
    wordlist = tmp_path / "standard.txt"
    wordlist.write_text("admin\napi\nlogin\n", encoding="utf-8")
    settings = Settings(_env_file=None, ffuf_wordlist_standard_path=wordlist)
    output = '{"results":[]}'

    with (
        patch("app.tools.ffuf_runner.get_settings", return_value=settings),
        patch("app.tools.ffuf_runner.shutil.which", return_value="ffuf"),
        patch("app.tools.ffuf_runner.subprocess.run", return_value=_completed(stdout=output)) as run_mock,
    ):
        result = run_ffuf_scan("example.com", FFUF_PROFILE_STANDARD)

    command = run_mock.call_args.args[0]
    assert command[command.index("-w") + 1] == str(wordlist)
    assert result["success"] is True
    assert result["ffuf_profile"] == FFUF_PROFILE_STANDARD
    assert result["wordlist_count"] == 3


def test_ffuf_deep_profile_uses_configured_deep_wordlist(tmp_path: Path) -> None:
    wordlist = tmp_path / "deep.txt"
    wordlist.write_text("admin\nbackup\nportal\napi\n", encoding="utf-8")
    settings = Settings(_env_file=None, ffuf_wordlist_deep_path=wordlist)

    with (
        patch("app.tools.ffuf_runner.get_settings", return_value=settings),
        patch("app.tools.ffuf_runner.shutil.which", return_value="ffuf"),
        patch("app.tools.ffuf_runner.subprocess.run", return_value=_completed(stdout='{"results":[]}')) as run_mock,
    ):
        result = run_ffuf_scan("example.com", FFUF_PROFILE_DEEP)

    command = run_mock.call_args.args[0]
    assert command[command.index("-w") + 1] == str(wordlist)
    assert result["success"] is True
    assert result["ffuf_profile"] == FFUF_PROFILE_DEEP
    assert result["wordlist_count"] == 4


def test_ffuf_standard_profile_missing_wordlist_fails_cleanly(tmp_path: Path) -> None:
    missing = tmp_path / "missing-standard.txt"
    with (
        patch("app.tools.ffuf_runner.get_settings", return_value=Settings(_env_file=None, ffuf_wordlist_standard_path=missing)),
        patch("app.tools.ffuf_runner.shutil.which", return_value="ffuf"),
        patch("app.tools.ffuf_runner.subprocess.run") as run_mock,
    ):
        result = run_ffuf_scan("https://example.com", FFUF_PROFILE_STANDARD)

    assert result["success"] is False
    assert result["error_type"] == "missing_wordlist"
    assert "Standard profile" in str(result["error"])
    run_mock.assert_not_called()


def test_ffuf_deep_profile_missing_wordlist_fails_cleanly(tmp_path: Path) -> None:
    missing = tmp_path / "missing-deep.txt"
    with (
        patch("app.tools.ffuf_runner.get_settings", return_value=Settings(_env_file=None, ffuf_wordlist_deep_path=missing)),
        patch("app.tools.ffuf_runner.shutil.which", return_value="ffuf"),
        patch("app.tools.ffuf_runner.subprocess.run") as run_mock,
    ):
        result = run_ffuf_scan("https://example.com", FFUF_PROFILE_DEEP)

    assert result["success"] is False
    assert result["error_type"] == "missing_wordlist"
    assert "Deep profile" in str(result["error"])
    run_mock.assert_not_called()


def test_ffuf_timeout_is_clean_failure(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    with (
        patch("app.tools.ffuf_runner.get_settings", return_value=Settings(_env_file=None, ffuf_scan_timeout_seconds=1, ffuf_wordlist_path=wordlist)),
        patch("app.tools.ffuf_runner.shutil.which", return_value="ffuf"),
        patch("app.tools.ffuf_runner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ffuf", timeout=1, output="", stderr="slow")),
    ):
        result = run_ffuf_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert result["error"] == "slow"


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_ffuf_target_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_ffuf_scan(target)


def test_ffuf_path_discovery() -> None:
    with patch("app.tools.ffuf_runner.shutil.which", return_value="/opt/bin/ffuf"):
        assert _resolve_ffuf_executable() == "/opt/bin/ffuf"


def test_ffuf_parser_normalizes_json_output() -> None:
    results = parse_ffuf_output(
        '{"results":['
        '{"url":"https://example.com/admin","status":200,"length":120,"words":10,"lines":3,"input":{"FUZZ":"admin"}},'
        '{"url":"https://example.com/login","status":302,"redirectlocation":"https://example.com/sso","input":{"FUZZ":"login"}},'
        '{"url":"https://example.com/config","status":403,"input":{"FUZZ":"config"}},'
        '{"url":"https://example.com/api","status":500,"input":{"FUZZ":"api"}}'
        "]}"
    )
    summary = summarize_ffuf_results(results)

    assert results[0]["path"] == "/admin"
    assert results[0]["classification"] == "public"
    assert results[1]["classification"] == "redirect"
    assert results[2]["classification"] == "forbidden"
    assert results[3]["classification"] == "server-error"
    assert summary["result_count"] == 4
    assert summary["status_codes"] == {"200": 1, "302": 1, "403": 1, "500": 1}
    assert summary["redirect_count"] == 1
    assert summary["forbidden_count"] == 1
    assert summary["server_error_count"] == 1


def test_default_ffuf_wordlist_exists_and_is_small() -> None:
    assert DEFAULT_FFUF_WORDLIST.is_file()
    count = _count_wordlist_entries(DEFAULT_FFUF_WORDLIST)
    assert 1 <= count <= 50


def test_ffuf_command_clamps_professional_bounded_limits(tmp_path: Path) -> None:
    command = _build_ffuf_command("ffuf", "https://example.com/FUZZ", tmp_path / "words.txt", threads=99, rate_limit=999)
    assert command[command.index("-t") + 1] == "50"
    assert command[command.index("-rate") + 1] == "500"
    assert command[command.index("-mc") + 1] == "200-299,300-399,401,403,405,407,409,429,500-599"


def test_ffuf_fuzz_url_preserves_base_path_without_query_unless_fuzz_is_explicit() -> None:
    assert _build_fuzz_url("https://example.com/app?x=1") == "https://example.com/app/FUZZ"
    assert _build_fuzz_url("https://example.com/api/FUZZ") == "https://example.com/api/FUZZ"
    assert _build_fuzz_url("https://example.com/search?q=FUZZ") == "https://example.com/search?q=FUZZ"


def test_ffuf_profile_selection_does_not_change_fuzz_placement(tmp_path: Path) -> None:
    wordlist = tmp_path / "standard.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    settings = Settings(_env_file=None, ffuf_wordlist_standard_path=wordlist)

    with (
        patch("app.tools.ffuf_runner.get_settings", return_value=settings),
        patch("app.tools.ffuf_runner.shutil.which", return_value="ffuf"),
        patch("app.tools.ffuf_runner.subprocess.run", return_value=_completed(stdout='{"results":[]}')) as run_mock,
    ):
        result = run_ffuf_scan("https://example.com/search?q=FUZZ", FFUF_PROFILE_STANDARD)

    command = run_mock.call_args.args[0]
    assert command[command.index("-u") + 1] == "https://example.com/search?q=FUZZ"
    assert result["fuzz_url"] == "https://example.com/search?q=FUZZ"


def test_ffuf_command_supports_safe_configured_extensions(tmp_path: Path) -> None:
    command = _build_ffuf_command("ffuf", "https://example.com/FUZZ", tmp_path / "words.txt", extensions="php,.txt,php")

    assert command[command.index("-e") + 1] == ".php,.txt"
    assert _normalize_ffuf_extensions("js,.bak") == [".js", ".bak"]


def test_ffuf_rejects_malformed_extension_configuration(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="extension"):
        _normalize_ffuf_extensions(".php;id")

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    with (
        patch("app.tools.ffuf_runner.get_settings", return_value=Settings(_env_file=None, ffuf_wordlist_path=wordlist, ffuf_extensions=".php;id")),
        patch("app.tools.ffuf_runner.shutil.which", return_value="ffuf"),
        patch("app.tools.ffuf_runner.subprocess.run") as run_mock,
    ):
        result = run_ffuf_scan("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "invalid_configuration"
    assert result["command"] is None
    run_mock.assert_not_called()
