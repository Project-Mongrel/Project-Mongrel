from pathlib import Path

import pytest

from app.bot.handlers.scan import build_gitleaks_result_text, store_gitleaks_scan_result
from app.parsers.gitleaks_parser import contains_unredacted_secret, normalize_gitleaks_output
from app.services.assessment_ai import build_assessment_ai_prompt
from app.services.assessment_context import build_assessment_context
from app.services.assessment_markdown_report import generate_assessment_markdown_report
from app.services.assessment_store import add_assessment_target, create_assessment, record_assessment_scan
from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.gitleaks_smoke_fixture import GitleaksSmokeFixture, create_gitleaks_smoke_fixture
from app.tools.gitleaks_runner import _validate_scan_scope


@pytest.fixture(autouse=True)
def sqlite_gitleaks_fixture_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


@pytest.fixture
def smoke_fixture(tmp_path) -> GitleaksSmokeFixture:
    return create_gitleaks_smoke_fixture(Path("data/gitleaks_smoke_fixture"))


def _fixture_json(smoke_fixture: GitleaksSmokeFixture) -> str:
    fake_aws_key, _, fake_github_token, _ = smoke_fixture.values
    return f"""
    [
      {{
        "RuleID": "aws-access-token",
        "Description": "AWS Access Key",
        "File": "fake_secrets.env",
        "StartLine": 3,
        "Secret": "{fake_aws_key}",
        "Match": "FAKE_TEST_ONLY_AWS_ACCESS_KEY_ID={fake_aws_key}",
        "Entropy": 4.8,
        "Fingerprint": "fake-fixture-aws"
      }},
      {{
        "RuleID": "github-pat",
        "Description": "GitHub Personal Access Token",
        "File": "fake_secrets.env",
        "StartLine": 5,
        "Secret": "{fake_github_token}",
        "Match": "FAKE_TEST_ONLY_GITHUB_TOKEN={fake_github_token}",
        "Entropy": 4.7,
        "Fingerprint": "fake-fixture-github"
      }}
    ]
    """


def _stored_context(smoke_fixture: GitleaksSmokeFixture) -> dict:
    scope = str(smoke_fixture.path.resolve())
    evidence = normalize_gitleaks_output(_fixture_json(smoke_fixture), scan_root=scope)
    result = {"success": True, "target": scope, "elapsed_seconds": 1, "returncode": 1, "command": ["gitleaks"]}
    assessment = create_assessment("Gitleaks Smoke Fixture")
    target = add_assessment_target(assessment["id"], address=scope, target_type="artifact_dir")
    finding = store_gitleaks_scan_result(user_id=9300, result=result, evidence=evidence)
    record_assessment_scan(
        assessment["id"],
        tool="gitleaks",
        status="completed",
        target_id=target["id"],
        finding_id=finding["id"],
        risk="high",
    )
    return build_assessment_context(assessment["id"], user_id=9300)


def test_gitleaks_smoke_fixture_path_is_allowed(smoke_fixture: GitleaksSmokeFixture) -> None:
    assert smoke_fixture.path.exists()
    assert _validate_scan_scope(str(smoke_fixture.path)) == smoke_fixture.path.resolve()


def test_gitleaks_smoke_fixture_detections_are_redacted(smoke_fixture: GitleaksSmokeFixture) -> None:
    evidence = normalize_gitleaks_output(_fixture_json(smoke_fixture), scan_root=str(smoke_fixture.path.resolve()))

    assert evidence["finding_count"] == 2
    assert "<REDACTED>" in evidence["findings"][0]["redacted_secret_preview"]
    for value in smoke_fixture.values:
        assert not contains_unredacted_secret(evidence, value)


def test_gitleaks_smoke_fixture_outputs_do_not_expose_fake_values(smoke_fixture: GitleaksSmokeFixture) -> None:
    context = _stored_context(smoke_fixture)
    finding = context["findings"][0]
    evidence = finding["gitleaks_evidence"]
    result = {"success": True, "target": evidence["scan_root"], "elapsed_seconds": 1}
    card = build_gitleaks_result_text(result, evidence)
    markdown = generate_assessment_markdown_report(context)
    prompt = build_assessment_ai_prompt("Summarise Gitleaks evidence.", context)

    combined_public_output = "\n".join([card, markdown, prompt, str(evidence)])
    assert "<REDACTED>" in combined_public_output
    for value in smoke_fixture.values:
        assert value not in combined_public_output
