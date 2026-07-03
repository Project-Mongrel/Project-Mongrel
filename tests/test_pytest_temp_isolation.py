from pathlib import Path

from tests import pytest_temp_isolation


def test_unique_basetemp_is_under_repo_local_pytest_tmp() -> None:
    first = pytest_temp_isolation.build_unique_basetemp()
    second = pytest_temp_isolation.build_unique_basetemp()

    assert first.parent == Path(".pytest_tmp")
    assert second.parent == Path(".pytest_tmp")
    assert first != second
    assert first.name.startswith("run-")


def test_pytest_temp_plugin_preserves_explicit_basetemp() -> None:
    args = ["--basetemp", "custom-temp"]

    pytest_temp_isolation.pytest_load_initial_conftests(None, None, args)

    assert args == ["--basetemp", "custom-temp"]


def test_pytest_temp_plugin_adds_unique_basetemp_when_missing() -> None:
    args = ["-q"]

    pytest_temp_isolation.pytest_load_initial_conftests(None, None, args)

    assert args[:1] == ["-q"]
    assert args[1] == "--basetemp"
    assert args[2].startswith(str(Path(".pytest_tmp") / "run-"))
