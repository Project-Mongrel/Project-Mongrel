import asyncio
import logging
from datetime import UTC, datetime

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.bot.progress import run_progress_frames, safe_edit_text
from app.services.chat_state import clear_finding_analysis_context
from app.services.findings_store import add_report_metadata, get_user_report, get_user_reports, get_user_scan_runs
from app.services.icon_helper import icon_label, section_label
from app.services.investigation_store import (
    add_investigation_event,
    complete_investigation,
    get_investigation,
    get_investigation_events,
    get_latest_investigation_for_target,
    get_or_create_latest_open_investigation,
    get_user_investigations,
)
from app.services.report_generator import (
    build_report_metadata,
    format_report_ai_assessment,
    generate_markdown_report,
    generate_report_id,
)
from app.services.target_normalizer import normalize_target_key

MAX_REPORT_MESSAGE_LENGTH = 3800
AI_REPORT_PROGRESS_INTERVAL_SECONDS = 1.75
AI_REPORT_PROGRESS_FRAMES = [
    f"{icon_label('mongrel_ai', 'Generating AI report')} /",
    f"{icon_label('saved', 'Collecting scan history')} -",
    f"{icon_label('report', 'Building deterministic report')} \\",
    f"{icon_label('mongrel_ai', 'Asking Mongrel AI')} |",
    f"{icon_label('mongrel_ai', 'Writing Executive Assessment')} /",
    f"{icon_label('report', 'Finalising report')} -",
]
logger = logging.getLogger(__name__)


def build_reports_text(scan_runs: list[dict] | None = None) -> str:
    scan_count = len(scan_runs or [])
    return "\n".join(
        [
            section_label("report", "Reports"),
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
        [InlineKeyboardButton("Investigations", callback_data="report:investigations")],
        [InlineKeyboardButton("Latest Investigation", callback_data="report:latest_investigation")],
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

    lines = [section_label("report", "Previous Reports / History"), ""]
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
            section_label("report", "Report Details"),
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


def build_investigations_text(investigations: list[dict]) -> str:
    if not investigations:
        return "No investigations available yet."

    lines = [section_label("investigation", "Investigations"), ""]
    for investigation in reversed(investigations[-10:]):
        lines.extend(
            [
                _format_investigation_date(investigation),
                str(investigation.get("name") or "Unnamed investigation"),
                f"Target: {investigation.get('target') or 'unknown'}",
                f"Risk: {str(investigation.get('overall_risk') or 'unknown').upper()}",
                f"Status: {_title_status(investigation.get('status'))}",
                "",
            ]
        )
    return _truncate_message("\n".join(lines).strip())


def build_investigations_keyboard(investigations: list[dict]) -> InlineKeyboardMarkup:
    buttons = []
    for index, investigation in enumerate(reversed(investigations[-10:]), start=1):
        buttons.append(
            [
                InlineKeyboardButton(
                    f"Timeline {index}",
                    callback_data=f"report:investigation:{investigation.get('id')}",
                )
            ]
        )
    buttons.append([InlineKeyboardButton("Back to Reports", callback_data="report:menu")])
    buttons.append([InlineKeyboardButton("Back/Home", callback_data="report:home")])
    return InlineKeyboardMarkup(buttons)


def build_investigation_timeline_text(investigation: dict | None, events: list[dict]) -> str:
    if investigation is None:
        return "Investigation not found."

    lines = [*build_investigation_summary_lines(investigation, events), "", "Investigation Timeline", ""]
    if not events:
        lines.append("No timeline events recorded yet.")
        return "\n".join(lines)

    current_date = None
    for event in events:
        timestamp = event.get("created_at")
        event_date = _format_event_date(timestamp)
        if event_date != current_date:
            current_date = event_date
            lines.extend([event_date, ""])
        lines.extend([_format_event_time(timestamp), _format_event_label(event), ""])

    return _truncate_message("\n".join(lines).strip())


def build_investigation_summary_lines(investigation: dict, events: list[dict]) -> list[str]:
    return [
        section_label("investigation", "Investigation"),
        "",
        str(investigation.get("name") or "Unnamed investigation"),
        "",
        "Target:",
        str(investigation.get("target") or "unknown"),
        "",
        "Status:",
        _title_status(investigation.get("status")),
        "",
        "Started:",
        _format_compact_time(investigation.get("started_at")),
        "",
        "Completed:",
        _format_compact_time(investigation.get("completed_at")) if investigation.get("completed_at") else "Open",
        "",
        "Duration:",
        _format_investigation_duration(investigation),
        "",
        "Overall Risk:",
        str(investigation.get("overall_risk") or "unknown").upper(),
        "",
        "Tools Used:",
        _format_tools_used(events),
        "",
        "Scan Runs:",
        str(len([event for event in events if str(event.get("event_type")).endswith("_scan_completed")])),
        "",
        "Reports Generated:",
        str(len([event for event in events if event.get("event_type") in {"report_generated", "ai_report_generated"}])),
        "",
        "Last Updated:",
        _format_last_updated(investigation, events),
    ]


def split_report_text(report: str, max_length: int = MAX_REPORT_MESSAGE_LENGTH) -> list[str]:
    if len(report) <= max_length:
        return [report]

    chunks = []
    remaining = report
    while len(remaining) > max_length:
        split_at = remaining.rfind("\n\n", 0, max_length)
        delimiter_length = 2
        if split_at <= 0:
            split_at = remaining.rfind("\n", 0, max_length)
            delimiter_length = 1
        if split_at <= 0:
            split_at = max_length
            delimiter_length = 0
        split_at += delimiter_length
        chunks.append(remaining[:split_at])
        remaining = remaining[split_at:]
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
    investigations = get_user_investigations(user_id)
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

    if data == "report:investigations":
        await query.edit_message_text(
            build_investigations_text(investigations),
            reply_markup=build_investigations_keyboard(investigations) if investigations else build_reports_keyboard(scan_runs),
        )
        return

    if data == "report:latest_investigation":
        latest_investigation = investigations[-1] if investigations else None
        await query.edit_message_text(
            build_investigation_timeline_text(
                latest_investigation,
                get_investigation_events(latest_investigation["id"], user_id) if latest_investigation else [],
            ),
            reply_markup=build_investigations_keyboard(investigations) if investigations else build_reports_keyboard(scan_runs),
        )
        return

    if data.startswith("report:investigation:"):
        investigation_id = data.removeprefix("report:investigation:")
        investigation = get_investigation(investigation_id, user_id)
        await query.edit_message_text(
            build_investigation_timeline_text(
                investigation,
                get_investigation_events(investigation_id, user_id) if investigation else [],
            ),
            reply_markup=build_investigations_keyboard(investigations) if investigations else build_reports_keyboard(scan_runs),
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
    ai_assessment_lines = None
    if include_ai_assessment and query.message is not None:
        ai_assessment_lines = await _build_ai_report_assessment_with_progress(query, report_scan_runs, target)

    report = generate_markdown_report(
        user_id=user_id,
        target=target,
        include_ai_assessment=include_ai_assessment,
        report_id=report_id,
        ai_assessment_lines=ai_assessment_lines,
    )
    report_metadata = add_report_metadata(
        user_id,
        build_report_metadata(
            report_scan_runs,
            target=target,
            include_ai_assessment=include_ai_assessment,
            report_id=report_id,
        ),
    )
    _record_report_investigation_event(
        user_id=user_id,
        target=target,
        report_scan_runs=report_scan_runs,
        report_metadata=report_metadata,
        include_ai_assessment=include_ai_assessment,
    )
    if query.message is None:
        await query.edit_message_text(_truncate_message(report))
        return

    if include_ai_assessment:
        await _safe_edit_report_status(
            query,
            "AI unavailable. Sending deterministic report with fallback note."
            if _ai_assessment_unavailable(ai_assessment_lines)
            else "AI report ready.",
        )
    else:
        await query.edit_message_text("Generating report...")
    for chunk in split_report_text(report):
        await query.message.reply_text(chunk)


async def _build_ai_report_assessment_with_progress(
    query: object,
    scan_runs: list[dict],
    target: str | None,
) -> list[str]:
    await _safe_edit_report_status(query, AI_REPORT_PROGRESS_FRAMES[0])
    stop_event = asyncio.Event()
    progress_task = asyncio.create_task(_run_ai_report_progress(query, stop_event))
    try:
        return await asyncio.to_thread(format_report_ai_assessment, scan_runs, target)
    finally:
        stop_event.set()
        await progress_task


async def _run_ai_report_progress(query: object, stop_event: asyncio.Event) -> None:
    await run_progress_frames(
        query,
        AI_REPORT_PROGRESS_FRAMES,
        stop_event,
        interval_seconds=AI_REPORT_PROGRESS_INTERVAL_SECONDS,
        start_index=1,
        context="Report progress",
    )


async def _safe_edit_report_status(query: object, text: str) -> None:
    await safe_edit_text(query, text, context="Report progress")


def _ai_assessment_unavailable(ai_assessment_lines: list[str] | None) -> bool:
    return any(str(line).startswith("AI assessment unavailable:") for line in (ai_assessment_lines or []))


def _record_report_investigation_event(
    user_id: int,
    target: str | None,
    report_scan_runs: list[dict],
    report_metadata: dict,
    include_ai_assessment: bool,
) -> None:
    event_target = target or _infer_event_target(report_scan_runs)
    investigation = get_latest_investigation_for_target(user_id, event_target) if event_target else None
    if investigation is None:
        investigation = get_or_create_latest_open_investigation(user_id=user_id, target=event_target or "Multiple targets")

    add_investigation_event(
        investigation_id=investigation["id"],
        user_id=user_id,
        target=event_target or "Multiple targets",
        event_type="ai_report_generated" if include_ai_assessment else "report_generated",
        tool="report",
        status="completed",
        summary="AI report generated" if include_ai_assessment else "Report generated",
        metadata={"report_id": report_metadata.get("id"), "readable_report_id": report_metadata.get("report_id")},
    )
    complete_investigation(
        investigation_id=investigation["id"],
        user_id=user_id,
        overall_risk=report_metadata.get("overall_risk"),
        summary=report_metadata.get("summary"),
    )


def _extract_targets(scan_runs: list[dict]) -> list[str]:
    targets_by_key = {}
    for scan_run in scan_runs:
        target = scan_run.get("target")
        if not target:
            continue
        target_key = scan_run.get("target_key") or normalize_target_key(target) or str(target)
        targets_by_key.setdefault(target_key, str(target_key if _target_contains_key(str(target), str(target_key)) else target))

    return sorted(targets_by_key.values())


def _infer_event_target(scan_runs: list[dict]) -> str | None:
    targets = _extract_targets(scan_runs)
    if len(targets) == 1:
        return targets[0]
    if len(targets) > 1:
        return "Multiple targets"
    return None


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


def _format_investigation_date(investigation: dict) -> str:
    timestamp = investigation.get("started_at")
    if hasattr(timestamp, "strftime"):
        return timestamp.astimezone(UTC).strftime("%d %b %Y")
    if isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp).astimezone(UTC).strftime("%d %b %Y")
        except ValueError:
            return timestamp

    return "unknown date"


def _format_event_date(timestamp: object) -> str:
    if hasattr(timestamp, "strftime"):
        return timestamp.astimezone(UTC).strftime("%d %b %Y")
    if isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp).astimezone(UTC).strftime("%d %b %Y")
        except ValueError:
            return timestamp

    return "unknown date"


def _format_event_time(timestamp: object) -> str:
    if hasattr(timestamp, "strftime"):
        return timestamp.astimezone(UTC).strftime("%H:%M")
    if isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp).astimezone(UTC).strftime("%H:%M")
        except ValueError:
            return "??:??"

    return "??:??"


def _format_event_label(event: dict) -> str:
    labels = {
        "nmap_scan_started": icon_label("nmap", "Nmap Scan Started"),
        "nmap_scan_completed": icon_label("nmap", "Nmap Scan Completed"),
        "nuclei_scan_started": icon_label("nuclei", "Nuclei Scan Started"),
        "nuclei_scan_completed": icon_label("nuclei", "Nuclei Scan Completed"),
        "bbot_scan_started": icon_label("bbot", "BBOT Recon Started"),
        "bbot_scan_completed": icon_label("bbot", "BBOT Recon Completed"),
        "bbot_scan_failed": icon_label("bbot", "BBOT Recon Failed"),
        "bbot_ai_assessment_generated": icon_label("mongrel_ai", "BBOT AI Recon Assessment Generated"),
        "bbot_ai_assessment_fallback": icon_label("mongrel_ai", "BBOT AI Recon Assessment Fallback"),
        "report_generated": icon_label("report", "Security Report Generated"),
        "ai_report_generated": icon_label("mongrel_ai", "Executive Assessment Generated"),
    }
    return labels.get(str(event.get("event_type")), str(event.get("summary") or event.get("event_type") or "Timeline event"))


def _format_compact_time(timestamp: object) -> str:
    if hasattr(timestamp, "strftime"):
        return timestamp.astimezone(UTC).strftime("%H:%M")
    if isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp).astimezone(UTC).strftime("%H:%M")
        except ValueError:
            return timestamp

    return "unknown"


def _format_investigation_duration(investigation: dict) -> str:
    duration_seconds = (investigation.get("metadata") or {}).get("duration_seconds")
    if duration_seconds is None and investigation.get("started_at") and investigation.get("completed_at"):
        duration_seconds = int((investigation["completed_at"] - investigation["started_at"]).total_seconds())
    if duration_seconds is None:
        return "In progress"

    return _format_duration(int(duration_seconds))


def _format_duration(total_seconds: int) -> str:
    total_seconds = max(0, total_seconds)
    minutes, seconds = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def _format_tools_used(events: list[dict]) -> str:
    tools = sorted({str(event.get("tool")).title() for event in events if event.get("tool") and event.get("tool") != "report"})
    return ", ".join(tools) if tools else "None"


def _format_last_updated(investigation: dict, events: list[dict]) -> str:
    timestamps = [event.get("created_at") for event in events if event.get("created_at")]
    if investigation.get("completed_at"):
        timestamps.append(investigation.get("completed_at"))
    if not timestamps:
        timestamps.append(investigation.get("started_at"))

    latest = max((timestamp for timestamp in timestamps if hasattr(timestamp, "astimezone")), default=None)
    return _format_report_timestamp({"generated_at": latest}) if latest is not None else "unknown"


def _title_status(status: object) -> str:
    return str(status or "unknown").capitalize()


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
