from pathlib import Path

from packaging.requirements import Requirement


WINDOWS_ONLY_PACKAGES = {"pywin32", "pypiwin32"}


def test_windows_only_requirements_have_platform_markers() -> None:
    requirements = _load_requirements()

    for requirement in requirements:
        if requirement.name.lower() in WINDOWS_ONLY_PACKAGES:
            assert requirement.marker is not None
            assert requirement.marker.evaluate({"platform_system": "Windows"}) is True
            assert requirement.marker.evaluate({"platform_system": "Linux"}) is False


def test_requirements_file_is_utf8_text() -> None:
    Path("requirements.txt").read_text(encoding="utf-8")


def _load_requirements() -> list[Requirement]:
    requirements = []
    for line in Path("requirements.txt").read_text(encoding="utf-8").splitlines():
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        requirements.append(Requirement(stripped_line))
    return requirements
