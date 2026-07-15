from __future__ import annotations

import os
from pathlib import Path
import shutil
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest


REPO_ROOT = Path(__file__).resolve().parent
PYTEST_TEMP_ROOT = REPO_ROOT / ".pytest_tmp"
PYTEST_TEMP_FALLBACK_ROOT = REPO_ROOT / ".pytest_tmp_runs"
PYTEST_TEMP_ROOT_ENV = "MONGREL_PYTEST_TEMP_ROOT"
PYTEST_TEMP_STALE_SECONDS = 24 * 60 * 60


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: object) -> None:
    configure_pytest_basetemp(config)


def configure_pytest_basetemp(config: object) -> Path | None:
    option = getattr(config, "option", None)
    if option is None:
        return None
    if getattr(option, "basetemp", None):
        return None

    temp_root = prepare_pytest_temp_root(current_pytest_temp_root())
    basetemp = build_unique_basetemp(root=temp_root)
    basetemp.mkdir(parents=True, exist_ok=True)
    setattr(option, "basetemp", str(basetemp))
    return basetemp


def build_unique_basetemp(prefix: str = "run", root: Path | None = None) -> Path:
    run_id = f"{prefix}-{os.getpid()}-{time.time_ns()}-{uuid4().hex[:8]}"
    return (root or current_pytest_temp_root()) / run_id


def current_pytest_temp_root() -> Path:
    configured_root = os.environ.get(PYTEST_TEMP_ROOT_ENV)
    if not configured_root:
        return PYTEST_TEMP_ROOT

    path = Path(configured_root)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path.resolve()


def prepare_pytest_temp_root(root: Path) -> Path:
    prepared = _try_prepare_pytest_temp_root(root)
    if prepared is not None:
        return prepared

    fallback = _try_prepare_pytest_temp_root(PYTEST_TEMP_FALLBACK_ROOT)
    if fallback is not None:
        return fallback

    raise PermissionError(f"Unable to create a writable pytest temp root under {REPO_ROOT}.")


def _try_prepare_pytest_temp_root(root: Path) -> Path | None:
    try:
        if root.exists() and not root.is_dir():
            return None
        root.mkdir(parents=True, exist_ok=True)
        _remove_stale_pytest_runs(root)
        probe = root / f".probe-{os.getpid()}-{uuid4().hex}"
        probe.mkdir()
        probe.rmdir()
        return root.resolve()
    except PermissionError:
        return None
    except OSError:
        return None


def _remove_stale_pytest_runs(root: Path) -> None:
    cutoff = time.time() - PYTEST_TEMP_STALE_SECONDS
    try:
        children = list(root.iterdir())
    except OSError:
        return

    for child in children:
        if not child.name.startswith("run-"):
            continue
        try:
            if child.stat().st_mtime > cutoff:
                continue
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
        except OSError:
            continue


def config_stub(basetemp: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(option=SimpleNamespace(basetemp=basetemp))
