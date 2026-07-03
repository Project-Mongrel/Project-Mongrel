import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import conftest


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
