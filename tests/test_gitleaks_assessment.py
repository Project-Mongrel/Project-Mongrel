import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.fernet import Fernet

from app.bot.handlers.assessment import build_assessment_dashboard_keyboard, build_assessment_dashboard_text
from app.bot.handlers.assessment import ASSESSMENT_SCAN_CONTEXT_KEY
from app.bot.handlers.scan import (
    _handle_gitleaks_evidence_vault_callback,
    PENDING_NMAP_REQUEST_KEY,
    build_gitleaks_evidence_warning_text,
    build_gitleaks_result_actions,
    build_gitleaks_result_text,
    redact_gitleaks_result_for_public_state,
    scan_target_handler,
    store_gitleaks_scan_result,
    store_gitleaks_secret_vault_records,
)
from app.parsers.gitleaks_parser import contains_unredacted_secret, normalize_gitleaks_output
from app.services.assessment_ai import build_assessment_ai_prompt
from app.services.assessment_context import build_assessment_context
from app.services.assessment_guard import build_assessment_guard
from app.services.assessment_markdown_report import generate_assessment_markdown_report
from app.services.assessment_store import add_assessment_target, create_assessment, list_assessment_scans, record_assessment_scan
from app.services.findings_store import close_findings_database, configure_findings_database, get_user_findings
from app.services.scan_manager import clear_user_scan_requests, create_scan_request, mark_scan_request_awaiting_target
from app.services.evidence_vault import (
    EvidenceVaultUnavailable,
    close_evidence_vault,
    configure_evidence_vault,
    list_reveal_audit_events,
    reveal_secret_evidence,
)

RAW_SECRET = "ghp_1234567890abcdefghijklmnopqrstuv"
GITLEAKS_JSON = f"""
[
  {{
    "RuleID": "github-pat",
    "Description": "GitHub Personal Access Token",
    "File": "src/config.py",
    "StartLine": 12,
    "Secret": "{RAW_SECRET}",
    "Entropy": 4.9,
    "Fingerprint": "abc123"
  }}
]
"""


@pytest.fixture(autouse=True)
def sqlite_gitleaks_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    configure_evidence_vault(tmp_path / "vault.db", Fernet.generate_key().decode("utf-8"))
    yield
    close_findings_database()
    close_evidence_vault()
    configure_findings_database(None)
    configure_evidence_vault(None, None)


def _stored_context() -> dict:
    assessment = create_assessment("Secrets Assessment")
    target = add_assessment_target(assessment["id"], address="/tmp/artifact", target_type="artifact_dir")
    evidence = normalize_gitleaks_output(GITLEAKS_JSON, scan_root="/tmp/artifact")
    result = {"success": True, "target": "/tmp/artifact", "elapsed_seconds": 2, "returncode": 1, "command": ["gitleaks"]}
    finding = store_gitleaks_scan_result(user_id=9200, result=result, evidence=evidence)
    record_assessment_scan(
        assessment["id"],
        tool="gitleaks",
        status="completed",
        target_id=target["id"],
        finding_id=finding["id"],
        risk="high",
    )
    return build_assessment_context(assessment["id"], user_id=9200)


def _vaulted_gitleaks_assessment(user_id: int = 9200) -> tuple[dict, dict, dict]:
    assessment = create_assessment("Vaulted Secrets Assessment")
    target = add_assessment_target(assessment["id"], address="/tmp/artifact", target_type="artifact_dir")
    evidence = normalize_gitleaks_output(GITLEAKS_JSON, scan_root="/tmp/artifact")
    evidence = store_gitleaks_secret_vault_records(GITLEAKS_JSON, evidence, assessment_id=assessment["id"])
    result = {"success": True, "target": "/tmp/artifact", "elapsed_seconds": 2, "returncode": 1, "command": ["gitleaks"]}
    finding = store_gitleaks_scan_result(user_id=user_id, result=result, evidence=evidence)
    record_assessment_scan(
        assessment["id"],
        tool="gitleaks",
        status="completed",
        target_id=target["id"],
        finding_id=finding["id"],
        risk="high",
    )
    return assessment, finding, evidence


def _vault_query(action: str, assessment_id: int | str, finding_id: str, evidence_id: str, reply_value: object | None = None) -> SimpleNamespace:
    message = SimpleNamespace(reply_text=AsyncMock(return_value=reply_value or SimpleNamespace(delete=AsyncMock())))
    return SimpleNamespace(
        data=f"vault:{action}:{assessment_id}:{finding_id}:{evidence_id}",
        edit_message_text=AsyncMock(),
        message=message,
    )


def _gitleaks_json(records: list[dict]) -> str:
    import json

    return json.dumps(records)


def _live_style_gitleaks_scan(
    *,
    user_id: int,
    json_output: str,
    assessment_context: dict | None = None,
) -> tuple[SimpleNamespace, dict | None]:
    clear_user_scan_requests(user_id)
    scan_request = create_scan_request(user_id=user_id, scan_type="gitleaks")
    mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
    context = SimpleNamespace(user_data={PENDING_NMAP_REQUEST_KEY: scan_request.id})
    if assessment_context:
        context.user_data[ASSESSMENT_SCAN_CONTEXT_KEY] = assessment_context
    message = SimpleNamespace(text="/home/mongrel/Project-Mongrel/data/gitleaks_smoke_fixture", reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=user_id))
    result = {
        "success": True,
        "target": "/home/mongrel/Project-Mongrel/data/gitleaks_smoke_fixture",
        "json_output": json_output,
        "elapsed_seconds": 2,
        "returncode": 1,
        "command": ["gitleaks", "dir"],
    }

    with (
        patch("app.bot.handlers.scan.run_gitleaks_scan", return_value=result),
        patch("app.bot.handlers.scan.generate_gitleaks_ai_assessment", return_value=["Gitleaks AI assessment ready."]),
        patch("app.bot.handlers.scan.ScanProgressCard.start", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.start_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.stop_auto_refresh", new_callable=AsyncMock),
        patch("app.bot.handlers.scan.ScanProgressCard.complete", new_callable=AsyncMock),
    ):
        asyncio.run(scan_target_handler(update, context))

    return message, assessment_context


def _result_card_call(message: SimpleNamespace):
    for call in message.reply_text.call_args_list:
        if call.args and "Gitleaks Scan Complete" in str(call.args[0]):
            return call
    raise AssertionError("Gitleaks result card was not sent.")


def test_assessment_context_includes_redacted_gitleaks_evidence() -> None:
    context = _stored_context()

    assert context["scans"][0]["tool"] == "gitleaks"
    assert context["findings"][0]["source"] == "gitleaks"
    assert context["findings"][0]["gitleaks_evidence"]["findings"][0]["rule_id"] == "github-pat"
    assert not contains_unredacted_secret(context, RAW_SECRET)


def test_guard_recognizes_gitleaks_and_removes_locked_limitation() -> None:
    guard = build_assessment_guard(_stored_context())

    assert "gitleaks" in guard["completed_tools"]
    assert "Gitleaks not run" not in guard["locked_tool_limitations"]
    assert any("gitleaks github-pat" in value for value in guard["observed_assets"]["services"])


def test_dashboard_shows_gitleaks_status_and_button() -> None:
    assessment = create_assessment("Dashboard Secrets")
    record_assessment_scan(assessment["id"], tool="gitleaks", status="completed", elapsed_seconds=2, risk="high")
    dashboard = build_assessment_dashboard_text(assessment, [{"address": "/tmp/artifact"}], list_assessment_scans(assessment["id"]))
    keyboard = build_assessment_dashboard_keyboard(assessment["id"])
    buttons = [button.text for row in keyboard.inline_keyboard for button in row]

    assert "Gitleaks: Completed" in dashboard
    assert "Run Gitleaks" in buttons


def test_gitleaks_telegram_card_never_displays_raw_secret() -> None:
    evidence = normalize_gitleaks_output(GITLEAKS_JSON, scan_root="/tmp/artifact")
    card = build_gitleaks_result_text(
        {"success": True, "target": "/tmp/artifact", "elapsed_seconds": 2, "output": RAW_SECRET},
        evidence,
    )

    assert "Gitleaks Scan Complete" in card
    assert "Secret findings: 1" in card
    assert "Affected files: 1" in card
    assert "github-pat" in card
    assert "<REDACTED>" in card
    assert RAW_SECRET not in card


def test_markdown_report_includes_redacted_gitleaks_section() -> None:
    report = generate_assessment_markdown_report(_stored_context())

    assert "### Gitleaks" in report
    assert "Secret findings: 1" in report
    assert "github-pat" in report
    assert "<REDACTED>" in report
    assert RAW_SECRET not in report


def test_assessment_ai_prompt_includes_redacted_gitleaks_constraints() -> None:
    prompt = build_assessment_ai_prompt("What secrets were found?", _stored_context())

    assert "Treat Gitleaks detections as redacted secret-exposure evidence only." in prompt
    assert "Never include raw secret values" in prompt
    assert "Gitleaks redacted secret-exposure evidence" in prompt
    assert "<REDACTED>" in prompt
    assert RAW_SECRET not in prompt


def test_gitleaks_vault_records_attach_public_evidence_id() -> None:
    evidence = normalize_gitleaks_output(GITLEAKS_JSON, scan_root="/tmp/artifact")
    evidence = store_gitleaks_secret_vault_records(GITLEAKS_JSON, evidence, assessment_id=99)
    finding = evidence["findings"][0]

    revealed = reveal_secret_evidence(finding["evidence_id"])

    assert finding["evidence_id"]
    assert finding["secret_hash"]
    assert not contains_unredacted_secret(evidence, RAW_SECRET)
    assert revealed["assessment_id"] == "99"
    assert revealed["secret_payload"]["secret"] == RAW_SECRET


def test_gitleaks_vault_missing_key_prevents_public_evidence_storage(tmp_path) -> None:
    configure_evidence_vault(tmp_path / "vault.db", None)
    evidence = normalize_gitleaks_output(GITLEAKS_JSON, scan_root="/tmp/artifact")

    with pytest.raises(EvidenceVaultUnavailable):
        store_gitleaks_secret_vault_records(GITLEAKS_JSON, evidence, assessment_id=None)


def test_gitleaks_public_scan_result_does_not_keep_raw_json() -> None:
    public_result = redact_gitleaks_result_for_public_state(
        {"success": True, "target": "/tmp/artifact", "json_output": GITLEAKS_JSON, "json_len": len(GITLEAKS_JSON)}
    )

    assert public_result["json_output"] == ""
    assert public_result["json_redacted"] is True
    assert RAW_SECRET not in str(public_result)


def test_gitleaks_view_evidence_button_uses_only_opaque_references() -> None:
    assessment, finding, evidence = _vaulted_gitleaks_assessment()
    evidence_id = evidence["findings"][0]["evidence_id"]

    keyboard = build_gitleaks_result_actions(finding, {"assessment_id": assessment["id"]})
    callback_data = keyboard.inline_keyboard[1][0].callback_data

    assert callback_data == f"vault:view:{assessment['id']}:{finding['id']}:{evidence_id}"
    assert RAW_SECRET not in callback_data


def test_live_style_gitleaks_completion_renders_view_evidence_for_standalone_scan() -> None:
    user_id = 9310
    output = _gitleaks_json(
        [
            {
                "RuleID": "github-pat",
                "Description": "GitHub Personal Access Token",
                "File": "fake_secrets.env",
                "StartLine": 5,
                "Secret": RAW_SECRET,
                "Entropy": 4.9,
                "Fingerprint": "live-fixture-github",
            }
        ]
    )

    message, _ = _live_style_gitleaks_scan(user_id=user_id, json_output=output)
    result_call = _result_card_call(message)
    keyboard = result_call.kwargs["reply_markup"]
    buttons = [button for row in keyboard.inline_keyboard for button in row]
    view_button = [button for button in buttons if button.text == "View Evidence"][0]
    finding = get_user_findings(user_id)[0]
    evidence_id = finding["gitleaks_evidence"]["findings"][0]["evidence_id"]

    assert view_button.callback_data == f"vault:view:standalone:{finding['id']}:{evidence_id}"
    assert RAW_SECRET not in view_button.callback_data
    assert any("Gitleaks AI Assessment" in str(call.args[0]) for call in message.reply_text.call_args_list)
    assert result_call.kwargs["reply_markup"] is keyboard


def test_live_style_standalone_gitleaks_reveal_uses_vaulted_value() -> None:
    user_id = 9314
    output = _gitleaks_json(
        [
            {
                "RuleID": "github-pat",
                "Description": "GitHub Personal Access Token",
                "File": "fake_secrets.env",
                "StartLine": 5,
                "Secret": RAW_SECRET,
                "Entropy": 4.9,
                "Fingerprint": "live-fixture-github",
            }
        ]
    )
    message, _ = _live_style_gitleaks_scan(user_id=user_id, json_output=output)
    result_call = _result_card_call(message)
    view_button = [button for row in result_call.kwargs["reply_markup"].inline_keyboard for button in row if button.text == "View Evidence"][0]
    _, _, assessment_ref, finding_id, evidence_id = view_button.callback_data.split(":", 4)
    reveal_query = _vault_query("reveal", assessment_ref, finding_id, evidence_id)

    asyncio.run(_handle_gitleaks_evidence_vault_callback(reveal_query, user_id=user_id))

    assert assessment_ref == "standalone"
    assert RAW_SECRET not in view_button.callback_data
    assert RAW_SECRET in reveal_query.message.reply_text.call_args.args[0]


def test_live_style_gitleaks_completion_preserves_assessment_linkage_in_view_evidence() -> None:
    user_id = 9311
    assessment = create_assessment("Live Gitleaks Assessment")
    target = add_assessment_target(assessment["id"], address="/home/mongrel/Project-Mongrel/data/gitleaks_smoke_fixture", target_type="artifact_dir")
    output = _gitleaks_json(
        [
            {
                "RuleID": "github-pat",
                "Description": "GitHub Personal Access Token",
                "File": "fake_secrets.env",
                "StartLine": 5,
                "Secret": RAW_SECRET,
                "Entropy": 4.9,
                "Fingerprint": "live-fixture-github",
            }
        ]
    )

    message, _ = _live_style_gitleaks_scan(
        user_id=user_id,
        json_output=output,
        assessment_context={"assessment_id": assessment["id"], "target_id": target["id"], "tool": "gitleaks"},
    )
    result_call = _result_card_call(message)
    keyboard = result_call.kwargs["reply_markup"]
    buttons = [button for row in keyboard.inline_keyboard for button in row]
    view_button = [button for button in buttons if button.text == "View Evidence"][0]
    finding = get_user_findings(user_id)[0]
    evidence_id = finding["gitleaks_evidence"]["findings"][0]["evidence_id"]

    assert view_button.callback_data == f"vault:view:{assessment['id']}:{finding['id']}:{evidence_id}"
    assert list_assessment_scans(assessment["id"])[0]["finding_id"] == finding["id"]
    assert RAW_SECRET not in view_button.callback_data


def test_live_style_gitleaks_completion_without_vaulted_evidence_has_no_view_evidence() -> None:
    user_id = 9312

    message, _ = _live_style_gitleaks_scan(user_id=user_id, json_output="[]")
    result_call = _result_card_call(message)
    keyboard = result_call.kwargs["reply_markup"]
    button_texts = [button.text for row in keyboard.inline_keyboard for button in row]

    assert "AI Summary" in button_texts
    assert "View Evidence" not in button_texts


def test_live_style_gitleaks_multiple_findings_map_to_distinct_evidence_callbacks() -> None:
    user_id = 9313
    second_raw_value = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    output = _gitleaks_json(
        [
            {
                "RuleID": "github-pat",
                "Description": "GitHub Personal Access Token",
                "File": "fake_secrets.env",
                "StartLine": 5,
                "Secret": RAW_SECRET,
                "Entropy": 4.9,
                "Fingerprint": "first-fingerprint",
            },
            {
                "RuleID": "github-pat",
                "Description": "GitHub Personal Access Token",
                "File": "fake_secrets.env",
                "StartLine": 6,
                "Secret": second_raw_value,
                "Entropy": 4.8,
                "Fingerprint": "second-fingerprint",
            },
        ]
    )

    message, _ = _live_style_gitleaks_scan(user_id=user_id, json_output=output)
    result_call = _result_card_call(message)
    keyboard = result_call.kwargs["reply_markup"]
    view_buttons = [button for row in keyboard.inline_keyboard for button in row if button.text.startswith("View Evidence")]
    finding = get_user_findings(user_id)[0]
    evidence_ids = [item["evidence_id"] for item in finding["gitleaks_evidence"]["findings"]]
    callbacks = [button.callback_data for button in view_buttons]

    assert [button.text for button in view_buttons] == ["View Evidence #1", "View Evidence #2"]
    assert len(set(callbacks)) == 2
    for evidence_id in evidence_ids:
        assert any(callback.endswith(f":{evidence_id}") for callback in callbacks)
    assert RAW_SECRET not in str(callbacks)
    assert second_raw_value not in str(callbacks)


def test_gitleaks_view_evidence_warning_shows_no_raw_secret_before_confirmation() -> None:
    _, finding, evidence = _vaulted_gitleaks_assessment()
    evidence_id = evidence["findings"][0]["evidence_id"]

    warning = build_gitleaks_evidence_warning_text(finding, evidence_id)
    keyboard = build_gitleaks_result_actions(finding, {"assessment_id": 1})

    assert "Sensitive Evidence Warning" in warning
    assert "github-pat" in warning
    assert "<REDACTED>" in warning
    assert RAW_SECRET not in warning
    assert RAW_SECRET not in str(keyboard.to_dict())


def test_gitleaks_authorized_reveal_returns_exact_vaulted_value() -> None:
    assessment, finding, evidence = _vaulted_gitleaks_assessment()
    evidence_id = evidence["findings"][0]["evidence_id"]
    query = _vault_query("reveal", assessment["id"], finding["id"], evidence_id)

    asyncio.run(_handle_gitleaks_evidence_vault_callback(query, user_id=9200))

    revealed_text = query.message.reply_text.call_args.args[0]
    assert RAW_SECRET in revealed_text
    assert query.edit_message_text.call_args.args[0] == "Sensitive evidence revealed in a short-lived message."
    audit_events = list_reveal_audit_events(evidence_id)
    assert any(event["outcome"] == "success" for event in audit_events)
    assert RAW_SECRET not in str(audit_events)


def test_gitleaks_wrong_telegram_user_is_denied() -> None:
    assessment, finding, evidence = _vaulted_gitleaks_assessment(user_id=9200)
    evidence_id = evidence["findings"][0]["evidence_id"]
    query = _vault_query("reveal", assessment["id"], finding["id"], evidence_id)

    asyncio.run(_handle_gitleaks_evidence_vault_callback(query, user_id=9999))

    assert query.edit_message_text.call_args.args[0] == "Evidence access denied."
    assert not query.message.reply_text.called
    audit_events = list_reveal_audit_events(evidence_id)
    assert audit_events[-1]["outcome"] == "denied"
    assert audit_events[-1]["reason"] == "wrong_user_or_missing_finding"
    assert RAW_SECRET not in str(audit_events)


def test_gitleaks_wrong_assessment_is_denied() -> None:
    assessment, finding, evidence = _vaulted_gitleaks_assessment()
    other_assessment = create_assessment("Other Assessment")
    evidence_id = evidence["findings"][0]["evidence_id"]
    query = _vault_query("reveal", other_assessment["id"], finding["id"], evidence_id)

    asyncio.run(_handle_gitleaks_evidence_vault_callback(query, user_id=9200))

    assert assessment["id"] != other_assessment["id"]
    assert query.edit_message_text.call_args.args[0] == "Evidence access denied."
    assert not query.message.reply_text.called
    assert list_reveal_audit_events(evidence_id)[-1]["reason"] == "wrong_assessment"


def test_gitleaks_missing_evidence_is_denied() -> None:
    assessment, finding, _ = _vaulted_gitleaks_assessment()
    query = _vault_query("reveal", assessment["id"], finding["id"], "missing-evidence")

    asyncio.run(_handle_gitleaks_evidence_vault_callback(query, user_id=9200))

    assert query.edit_message_text.call_args.args[0] == "Evidence access denied."
    assert not query.message.reply_text.called
    assert list_reveal_audit_events("missing-evidence")[-1]["outcome"] == "denied"


def test_gitleaks_missing_vault_config_fails_closed(tmp_path) -> None:
    vault_path = tmp_path / "closed-vault.db"
    configure_evidence_vault(vault_path, Fernet.generate_key().decode("utf-8"))
    assessment, finding, evidence = _vaulted_gitleaks_assessment()
    evidence_id = evidence["findings"][0]["evidence_id"]
    configure_evidence_vault(vault_path, None)
    query = _vault_query("reveal", assessment["id"], finding["id"], evidence_id)

    asyncio.run(_handle_gitleaks_evidence_vault_callback(query, user_id=9200))

    assert query.edit_message_text.call_args.args[0] == "Evidence vault is unavailable."
    assert not query.message.reply_text.called


def test_gitleaks_decryption_failure_fails_closed(tmp_path) -> None:
    vault_path = tmp_path / "wrong-key-vault.db"
    configure_evidence_vault(vault_path, Fernet.generate_key().decode("utf-8"))
    assessment, finding, evidence = _vaulted_gitleaks_assessment()
    evidence_id = evidence["findings"][0]["evidence_id"]
    configure_evidence_vault(vault_path, Fernet.generate_key().decode("utf-8"))
    query = _vault_query("reveal", assessment["id"], finding["id"], evidence_id)

    asyncio.run(_handle_gitleaks_evidence_vault_callback(query, user_id=9200))

    assert query.edit_message_text.call_args.args[0] == "Evidence vault decrypt failed."
    assert not query.message.reply_text.called


def test_gitleaks_cancel_path_reveals_nothing() -> None:
    assessment, finding, evidence = _vaulted_gitleaks_assessment()
    evidence_id = evidence["findings"][0]["evidence_id"]
    query = _vault_query("cancel", assessment["id"], finding["id"], evidence_id)

    asyncio.run(_handle_gitleaks_evidence_vault_callback(query, user_id=9200))

    assert query.edit_message_text.call_args.args[0] == "Evidence reveal cancelled."
    assert not query.message.reply_text.called
    audit_events = list_reveal_audit_events(evidence_id)
    assert audit_events[-1]["outcome"] == "cancelled"
    assert RAW_SECRET not in str(audit_events)


def test_gitleaks_reveal_does_not_log_raw_secret(caplog) -> None:
    assessment, finding, evidence = _vaulted_gitleaks_assessment()
    evidence_id = evidence["findings"][0]["evidence_id"]
    query = _vault_query("reveal", assessment["id"], finding["id"], evidence_id)

    with caplog.at_level(logging.INFO):
        asyncio.run(_handle_gitleaks_evidence_vault_callback(query, user_id=9200))

    assert RAW_SECRET not in caplog.text


def test_gitleaks_vaulted_context_reports_and_ai_remain_redacted() -> None:
    assessment, _, _ = _vaulted_gitleaks_assessment()
    context = build_assessment_context(assessment["id"], user_id=9200)
    prompt = build_assessment_ai_prompt("Review vaulted Gitleaks evidence.", context)
    report = generate_assessment_markdown_report(context)

    combined_public_output = "\n".join([prompt, report, str(context)])
    assert "<REDACTED>" in combined_public_output
    assert RAW_SECRET not in combined_public_output
