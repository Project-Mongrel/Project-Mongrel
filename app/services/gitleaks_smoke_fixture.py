from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GitleaksSmokeFixture:
    path: Path
    values: tuple[str, ...]


def create_gitleaks_smoke_fixture(base_dir: Path | str = Path("data/gitleaks_smoke_fixture")) -> GitleaksSmokeFixture:
    """Create a local ignored Gitleaks smoke fixture with fake, non-live values."""
    fixture_dir = Path(base_dir).resolve()
    fixture_dir.mkdir(parents=True, exist_ok=True)
    values = _fake_values()
    content = "\n".join(
        [
            "# Fake Gitleaks smoke-test data only.",
            "# Non-live placeholders generated locally for detection tests.",
            f"FAKE_TEST_ONLY_AWS_ACCESS_KEY_ID={values[0]}",
            f"FAKE_TEST_ONLY_AWS_SECRET_ACCESS_KEY={values[1]}",
            f"FAKE_TEST_ONLY_GITHUB_TOKEN={values[2]}",
            f"FAKE_TEST_ONLY_SLACK_TOKEN={values[3]}",
            "",
        ]
    )
    (fixture_dir / "fake_secrets.env").write_text(content, encoding="utf-8")
    return GitleaksSmokeFixture(path=fixture_dir, values=values)


def _fake_values() -> tuple[str, str, str, str]:
    aws_key = "".join(("AK", "IA", "IOSFODNN7", "EXAMPLE"))
    aws_secret = "".join(("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", "EXAMPLE", "KEY"))
    github_token = "".join(("gh", "p_", "FAKEtestOnly", "NonProduction", "000000000000"))
    slack_token = "".join(("xo", "xb-", "000000000000-", "000000000000-", "FAKEtestOnly"))
    return aws_key, aws_secret, github_token, slack_token
