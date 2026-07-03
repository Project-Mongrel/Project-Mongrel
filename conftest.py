from __future__ import annotations

import os
from pathlib import Path
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest


REPO_ROOT = Path(__file__).resolve().parent
PYTEST_TEMP_ROOT = REPO_ROOT / ".pytest_tmp"
PYTEST_TEMP_ROOT_ENV = "MONGREL_PYTEST_TEMP_ROOT"


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: object) -> None:
    configure_pytest_basetemp(config)


def configure_pytest_basetemp(config: object) -> Path | None:
    option = getattr(config, "option", None)
    if option is None:
        return None
    if getattr(option, "basetemp", None):
        return None

    basetemp = build_unique_basetemp()
    setattr(option, "basetemp", str(basetemp))
    return basetemp


def build_unique_basetemp(prefix: str = "run") -> Path:
    run_id = f"{prefix}-{os.getpid()}-{time.time_ns()}-{uuid4().hex[:8]}"
    return current_pytest_temp_root() / run_id


def current_pytest_temp_root() -> Path:
    configured_root = os.environ.get(PYTEST_TEMP_ROOT_ENV)
    if not configured_root:
        return PYTEST_TEMP_ROOT

    path = Path(configured_root)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path.resolve()


def config_stub(basetemp: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(option=SimpleNamespace(basetemp=basetemp))
