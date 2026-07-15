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


def test_runtime_requirements_exclude_semgrep_dependency_conflict() -> None:
    requirements = _load_requirements()
    names = {requirement.name.lower() for requirement in requirements}

    assert "bbot" not in names
    assert "semgrep" not in names
    assert _requirement_for(requirements, "PyJWT").specifier.contains("2.13.0")
    assert _requirement_for(requirements, "click").specifier.contains("8.3.3")


def test_semgrep_has_separate_optional_requirements_file() -> None:
    requirements = _load_requirements(Path("requirements-semgrep.txt"))
    names = {requirement.name.lower() for requirement in requirements}

    assert names == {"semgrep"}


def _load_requirements(path: Path = Path("requirements.txt")) -> list[Requirement]:
    requirements = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        requirements.append(Requirement(stripped_line))
    return requirements


def _requirement_for(requirements: list[Requirement], name: str) -> Requirement:
    for requirement in requirements:
        if requirement.name.lower() == name.lower():
            return requirement
    raise AssertionError(f"Requirement not found: {name}")
