from __future__ import annotations

import os
from pathlib import Path
import time
from uuid import uuid4


PYTEST_TEMP_ROOT = Path(".pytest_tmp")


def pytest_load_initial_conftests(early_config: object, parser: object, args: list[str]) -> None:
    if _has_basetemp(args):
        return

    args.extend(["--basetemp", str(build_unique_basetemp())])


def build_unique_basetemp() -> Path:
    run_id = f"run-{os.getpid()}-{time.time_ns()}-{uuid4().hex[:8]}"
    return PYTEST_TEMP_ROOT / run_id


def _has_basetemp(args: list[str]) -> bool:
    for index, arg in enumerate(args):
        if arg == "--basetemp":
            return index + 1 < len(args)
        if arg.startswith("--basetemp="):
            return True
    return False
