from datetime import UTC, datetime

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.chat_state import clear_finding_analysis_context
from app.services.findings_store import add_report_metadata, get_user_report, get_user_reports, get_user_scan_runs
from app.services.report_generator import build_report_metadata, generate_markdown_report, generate_report_id
from app.services.target_normalizer import normalize_target_key

MAX_REPORT_MESSAGE_LENGTH = 3800


def build_reports_text(scan_runs: list[dict] | None = None) -> str:
    scan_count = len(scan_runs or [])
    return "\n".join(
        [
            "Reports",
            "",
            f"Persisted scan runs available: {scan_count}",
            "",
            "Generate Markdown reports from stored Nmap and Nuclei scan history.",
        ]
    )


def build_reports_keyboard(scan_runs: list[dict] | None = None) -> InlineKeyboardMarkup:
    buttons = [
        [InlineKeyboardButton("Generate Latest Report", callback_data="report:latest")],
        [InlineKeyboardButton("Generate Report with AI Assessment", callback_data="report:latest_ai")],
        [InlineKeyboardButton("Reports by Target", callback_data="report:targets")],
        [InlineKeyboardButton("Previous Reports / History", callback_data="report:history")],
        [InlineKeyboardButton("Back/Home", callback_data="report:home")],
    ]
    return InlineKeyboardMarkup(buttons)


def build_report_targets_text(targets: list[str]) -> str:
    if not targets:
        return "No scan targets available yet."

    return "Choose a target for the report."


def build_report_targets_keyboard(targets: list[str]) -> InlineKeyboardMarkup:
    buttons = [[InlineKeyboardButton(target, callback_data=f"report:target:{index}")] for index, target in enumerate(targets)]
    buttons.append([InlineKeyboardButton("Back to Reports", callback_data="report:menu")])
    buttons.append([InlineKeyboardButton("Back/Home", callback_data="report:home")])
    return InlineKeyboardMarkup(buttons)


def build_report_history_text(reports: list[dict]) -> str:
    if not reports:
        return "No previous reports generated yet."

    lines = ["Previous Reports / History", ""]
    for index, report in enumerate(reversed(reports[-10:]), start=1):
        lines.extend(
            [
                _format_report_timestamp(report),
                f"Report ID: {_format_readable_report_id(report)}",
                *_format_report_investigation_lines(report),
                f"Target: {report.get('target') or 'all targets'}",
                f"Type: {_format_report_type(report)}",
                f"Risk: {str(report.get('overall_risk') or 'unknown').upper()}",
                "",
            ]
        )
    return _truncate_message("\n".join(lines).strip())


def build_report_history_keyboard(reports: list[dict]) -> InlineKeyboardMarkup:
    buttons = []
    latest_reports = list(reversed(reports[-10:]))
    for index, report in enumerate(latest_reports):
        buttons.append(
            [
                InlineKeyboardButton(
                    f"View Report {index + 1}",
                    callback_data=f"report:history:{report.get('id')}",
                )
            ]
        )
    buttons.append([InlineKeyboardButton("Back to Reports", callback_data="report:menu")])
    buttons.append([InlineKeyboardButton("Back/Home", callback_data="report:home")])
    return InlineKeyboardMarkup(buttons)


def build_report_metadata_detail_text(report: dict | None) -> str:
    if report is None:
        return "Report metadata not found."

    return "\n".join(
        [
            "Report Details",
            "",
            f"Report ID: {_format_readable_report_id(report)}",
            f"Generated: {_format_report_timestamp(report)}",
            *_format_report_investigation_lines(report),
            f"Target: {report.get('target') or 'all targets'}",
            f"Type: {_format_report_type(report)}",
            f"Risk: {str(report.get('overall_risk') or 'unknown').upper()}",
            f"Scan Count: {report.get('scan_count', 0)}",
            f"Source Count: {report.get('source_count', 0)}",
            "",
            "Summary:",
            str(report.get("summary") or "No summary available."),
        ]
    )


def split_report_text(report: str, max_length: int = MAX_REPORT_MESSAGE_LENGTH) -> list[str]:
    if len(report) <= max_length:
        return [report]

    chunks = []
    remaining = report
    while len(remaining) > max_length:
        split_at = remaining.rfind("\n\n", 0, max_length)
        if split_at <= 0:
            split_at = remaining.rfind("\n", 0, max_length)
        if split_at <= 0:
            split_at = max_length
        chunks.append(remaining[:split_at].strip())
        remaining = remaining[split_at:].strip()
    if remaining:
        chunks.append(remaining)
    return chunks


async def reports_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is not None:
        clear_finding_analysis_context(user_id)

    scan_runs = get_user_scan_runs(user_id) if user_id is not None else []
    await update.message.reply_text(
        build_reports_text(scan_runs),
        reply_markup=build_reports_keyboard(scan_runs),
    )


async def reports_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return

    await query.answer()

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is None:
        await query.edit_message_text("Unable to identify Telegram user.")
        return

    scan_runs = get_user_scan_runs(user_id)
    reports = get_user_reports(user_id)
    data = query.data or ""

    if data in {"report:menu"}:
        await query.edit_message_text(build_reports_text(scan_runs), reply_markup=build_reports_keyboard(scan_runs))
        return

    if data == "report:home":
        await query.edit_message_text("Project Mongrel control panel")
        if query.message is not None:
            await query.message.reply_text("Main menu", reply_markup=build_main_menu_keyboard())
        return

    if data == "report:latest":
        await _send_report_from_callback(query, user_id=user_id, scan_runs=scan_runs)
        return

    if data == "report:latest_ai":
        await _send_report_from_callback(query, user_id=user_id, scan_runs=scan_runs, include_ai_assessment=True)
        return

    if data == "report:targets":
        targets = _extract_targets(scan_runs)
        await query.edit_message_text(
            build_report_targets_text(targets),
            reply_markup=build_report_targets_keyboard(targets) if targets else build_reports_keyboard(scan_runs),
        )
        return

    if data.startswith("report:target:"):
        targets = _extract_targets(scan_runs)
        try:
            target = targets[int(data.removeprefix("report:target:"))]
        except (IndexError, ValueError):
            await query.edit_message_text("Report target not found.", reply_markup=build_reports_keyboard(scan_runs))
            return
        await _send_report_from_callback(query, user_id=user_id, scan_runs=scan_runs, target=target)
        return

    if data == "report:history":
        await query.edit_message_text(
            build_report_history_text(reports),
            reply_markup=build_report_history_keyboard(reports) if reports else build_reports_keyboard(scan_runs),
        )
        return

    if data.startswith("report:history:"):
        report_id = data.removeprefix("report:history:")
        await query.edit_message_text(
            build_report_metadata_detail_text(get_user_report(user_id, report_id)),
            reply_markup=build_report_history_keyboard(reports) if reports else build_reports_keyboard(scan_runs),
        )


async def _send_report_from_callback(
    query: object,
    user_id: int,
    scan_runs: list[dict],
    target: str | None = None,
    include_ai_assessment: bool = False,
) -> None:
    if not scan_runs:
        await query.edit_message_text(
            "No scan history available yet. Run or upload scans before generating a report.",
            reply_markup=build_reports_keyboard(scan_runs),
        )
        return

    report_scan_runs = _scan_runs_for_target(scan_runs, target)
    report_id = generate_report_id(existing_report_count=len(get_user_reports(user_id)))
    report = generate_markdown_report(
        user_id=user_id,
        target=target,
        include_ai_assessment=include_ai_assessment,
        report_id=report_id,
    )
    add_report_metadata(
        user_id,
        build_report_metadata(
            report_scan_runs,
            target=target,
            include_ai_assessment=include_ai_assessment,
            report_id=report_id,
        ),
    )
    if query.message is None:
        await query.edit_message_text(_truncate_message(report))
        return

    await query.edit_message_text("Generating report...")
    for chunk in split_report_text(report):
        await query.message.reply_text(chunk)


def _extract_targets(scan_runs: list[dict]) -> list[str]:
    targets_by_key = {}
    for scan_run in scan_runs:
        target = scan_run.get("target")
        if not target:
            continue
        target_key = scan_run.get("target_key") or normalize_target_key(target) or str(target)
        targets_by_key.setdefault(target_key, str(target_key if _target_contains_key(str(target), str(target_key)) else target))

    return sorted(targets_by_key.values())


def _scan_runs_for_target(scan_runs: list[dict], target: str | None) -> list[dict]:
    if target is None:
        return scan_runs

    target_key = normalize_target_key(target)
    if target_key is None:
        return [scan_run for scan_run in scan_runs if scan_run.get("target") == target]

    return [
        scan_run
        for scan_run in scan_runs
        if (scan_run.get("target_key") or normalize_target_key(scan_run.get("target"))) == target_key
    ]


def _format_report_timestamp(report: dict) -> str:
    timestamp = report.get("generated_at") or report.get("created_at")
    if hasattr(timestamp, "strftime"):
        return timestamp.astimezone(UTC).strftime("%d %b %Y %H:%M UTC")
    if isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp).astimezone(UTC).strftime("%d %b %Y %H:%M UTC")
        except ValueError:
            return timestamp

    return str(timestamp or "unknown")


def _format_report_type(report: dict) -> str:
    if report.get("report_type") == "ai_assessment":
        return "Executive Assessment Report"

    return "Deterministic Report"


def _format_readable_report_id(report: dict) -> str:
    return str(report.get("report_id") or report.get("id") or "unknown")


def _format_report_investigation_lines(report: dict) -> list[str]:
    investigation_name = report.get("investigation_name")
    if not investigation_name:
        return []

    return [f"Investigation: {investigation_name}"]


def _target_contains_key(target: str, target_key: str) -> bool:
    return target_key != target and "(" in target and ")" in target


def _finding_count(scan_run: dict) -> int:
    if scan_run.get("finding_count") is not None:
        return int(scan_run.get("finding_count") or 0)
    if isinstance(scan_run.get("nuclei_findings"), list):
        return len(scan_run.get("nuclei_findings") or [])
    if isinstance(scan_run.get("open_ports"), list):
        return len(scan_run.get("open_ports") or [])
    return 0


def _truncate_message(message: str) -> str:
    if len(message) <= MAX_REPORT_MESSAGE_LENGTH:
        return message
    return f"{message[:MAX_REPORT_MESSAGE_LENGTH]}\n\n[output truncated]"
