import os
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import conftest
import pytest


def test_unique_basetemp_is_under_repo_local_pytest_tmp() -> None:
    first = conftest.build_unique_basetemp()
    second = conftest.build_unique_basetemp()

    assert first.parent == conftest.current_pytest_temp_root()
    assert second.parent == conftest.current_pytest_temp_root()
    assert first.is_absolute()
    assert first != second
    assert first.name.startswith("run-")


def test_pytest_temp_plugin_preserves_explicit_basetemp() -> None:
    config = conftest.config_stub("custom-temp")

    applied = conftest.configure_pytest_basetemp(config)

    assert applied is None
    assert config.option.basetemp == "custom-temp"


def test_pytest_temp_plugin_adds_unique_basetemp_when_missing() -> None:
    config = conftest.config_stub()

    applied = conftest.configure_pytest_basetemp(config)

    assert applied == Path(config.option.basetemp)
    assert Path(config.option.basetemp).parent == conftest.current_pytest_temp_root()
    assert Path(config.option.basetemp).name.startswith("run-")
    assert Path(config.option.basetemp).is_dir()


def test_pytest_temp_root_falls_back_when_primary_is_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    primary = tmp_path / ".pytest_tmp"
    primary.write_text("not a directory", encoding="utf-8")
    fallback = tmp_path / ".pytest_tmp_runs"
    monkeypatch.setattr(conftest, "PYTEST_TEMP_FALLBACK_ROOT", fallback)

    prepared = conftest.prepare_pytest_temp_root(primary)

    assert prepared == fallback.resolve()
    assert prepared.is_dir()


def test_pytest_temp_cleanup_removes_only_stale_generated_runs(tmp_path: Path) -> None:
    stale_run = tmp_path / "run-old"
    stale_run.mkdir()
    stale_file = stale_run / "leftover.txt"
    stale_file.write_text("generated", encoding="utf-8")
    unrelated = tmp_path / "keep-me"
    unrelated.mkdir()
    fresh_run = tmp_path / "run-fresh"
    fresh_run.mkdir()
    old_time = time.time() - conftest.PYTEST_TEMP_STALE_SECONDS - 60
    fresh_time = time.time()
    for path in (stale_run, stale_file):
        path.chmod(0o700)
        os.utime(path, (old_time, old_time))
    os.utime(stale_run, (old_time, old_time))
    os.utime(fresh_run, (fresh_time, fresh_time))

    conftest.prepare_pytest_temp_root(tmp_path)

    assert not stale_run.exists()
    assert unrelated.exists()
    assert fresh_run.exists()


def test_normal_pytest_startup_uses_repo_local_basetemp(tmp_path: Path) -> None:
    probe_dir = tmp_path / "probe-tests" / uuid4().hex
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe_file = probe_dir / "test_probe_basetemp.py"
    probe_file.write_text(
        "\n".join(
            [
                "def test_probe_basetemp(tmp_path_factory):",
                "    print('BASE=' + str(tmp_path_factory.getbasetemp()))",
            ]
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, "-m", "pytest", str(probe_file), "-q", "-s"],
        cwd=conftest.REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
        shell=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    base_lines = [line for line in completed.stdout.splitlines() if line.startswith("BASE=")]
    assert base_lines, completed.stdout
    basetemp = Path(base_lines[-1].removeprefix("BASE=")).resolve()
    assert basetemp.parent == conftest.current_pytest_temp_root()
    assert basetemp.name.startswith("run-")
