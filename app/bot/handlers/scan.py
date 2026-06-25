import asyncio
import logging

from telegram import Update
from telegram.error import BadRequest, NetworkError, TimedOut
from telegram.ext import ContextTypes

from app.bot.handlers.home import build_home_text
from app.bot.handlers.findings import build_finding_followup_ai_prompt
from app.bot.keyboards import MAIN_MENU_BUTTONS, build_main_menu_keyboard, build_scan_type_keyboard
from app.models.scan_request import SUPPORTED_SCAN_TYPES
from app.parsers.nuclei_parser import NucleiParserError, parse_nuclei_results
from app.services.ai_client import ask_ai
from app.services.active_scan_state import (
    clear_active_scan,
    get_active_scan,
    set_active_scan,
    set_active_scan_status_task,
    set_active_scan_task,
)
from app.services.chat_state import clear_finding_analysis_context, get_finding_analysis_context, is_ai_waiting
from app.services.comparison_engine import compare_findings
from app.services.findings_store import add_finding, get_latest_user_finding_for_target
from app.services.impact_engine import assess_change_impact
from app.services.risk_rules import assess_nmap_ports
from app.services.scan_manager import (
    complete_scan_request,
    create_scan_request,
    get_scan_request,
    mark_scan_request_awaiting_target,
)
from app.services.service_intelligence import get_service_intelligence
from app.services.target_normalizer import normalize_target_key
from app.tools.nmap_parser import format_nmap_result, parse_nmap_output
from app.tools.nmap_runner import run_nmap_scan
from app.tools.nuclei_runner import run_nuclei_scan
from app.tools.target_normalizer import normalize_target

PENDING_NMAP_REQUEST_KEY = "pending_nmap_scan_request_id"
NUCLEI_STATUS_UPDATE_INTERVAL_SECONDS = 15
logger = logging.getLogger(__name__)


def build_scan_text() -> str:
    return "Choose a scan workflow to prepare. No external tools will run yet."


def build_scan_created_text(scan_type: str) -> str:
    return (
        f"{scan_type.upper()} scan request created with status: pending.\n\n"
        "Target collection and tool execution will be added in a later mission."
    )


def build_nmap_target_prompt() -> str:
    return "NMAP scan request created. Send the authorized target hostname or IP address to run the scan."


def build_nuclei_target_prompt() -> str:
    return "Nuclei scan request created. Send the authorized target URL or hostname to run the scan."


def build_nmap_scan_started_text(target: str) -> str:
    return f"Running NMAP scan for target: {target}"


def build_nuclei_scan_started_text() -> str:
    return "Running Nuclei scan..."


def build_nuclei_status_card(target: str, status: str, elapsed_seconds: int, reason: str | None = None) -> str:
    lines = [
        "Nuclei Fast Scan",
        "",
        "Target:",
        target or "unknown",
        "",
        "Status:",
        status,
        "",
        "Elapsed:",
        f"{elapsed_seconds}s",
    ]
    if reason:
        lines.extend(["", "Reason:", reason])
    if status in {"Initializing", "Running"}:
        lines.extend(["", "Press Cancel to stop."])

    return "\n".join(lines)


def build_clean_nuclei_verdict_text(target: str | None) -> str:
    return "\n".join(
        [
            "Nuclei Verdict",
            "",
            "Target:",
            str(target or "unknown"),
            "",
            "Risk Level:",
            "INFO",
            "",
            "Findings:",
            "0",
            "",
            "Summary:",
            "No matching Nuclei findings were identified using the fast scan profile.",
            "",
            "What this means:",
            "- The target was reachable.",
            "- Nuclei executed successfully.",
            "- No exposures, misconfigurations, or known issues matched the selected template set.",
            "",
            "Recommended Actions:",
            "- Continue regular patching and monitoring.",
            "- Re-scan after major site, server, or plugin changes.",
            "- Consider a deeper scan profile if additional assurance is required.",
        ]
    )


def store_clean_nuclei_scan(user_id: int, target: str | None) -> dict:
    summary = "No matching Nuclei findings were identified using the fast scan profile."
    return add_finding(
        user_id=user_id,
        finding={
            "source": "nuclei",
            "target": target,
            "target_key": normalize_target_key(target),
            "risk_level": "info",
            "finding_count": 0,
            "status": "clean",
            "summary": summary,
        },
    )


def build_nmap_scan_result_text(result: dict[str, object]) -> str:
    output = str(result.get("output") or "")
    fallback_output = str(result.get("error") or output or "No output returned.")
    parsed_output = parse_nmap_result(result)

    return format_nmap_result(parsed_output, fallback_output=fallback_output)


def append_change_summary(message: str, comparison: dict | None, impact: dict | None = None) -> str:
    if comparison is None:
        return message

    if comparison.get("has_previous") is False:
        return "\n".join(
            [
                message,
                "",
                "Comparison",
                comparison.get("summary", "No previous scan found for this target."),
                "",
                "This scan has been stored as the baseline for future comparisons.",
                "",
                "Impact Assessment",
                "Change Impact: N/A",
                "",
                "Summary:",
                "No historical comparison available.",
                "",
                "Reason:",
                "This is the first recorded scan for this target.",
            ]
        )

    lines = [
        message,
        "",
        "Comparison",
        comparison.get("summary", "No previous scan found for this target."),
        "",
        f"New Ports: {_format_ports(comparison.get('new_ports') or [])}",
        f"Removed Ports: {_format_ports(comparison.get('removed_ports') or [])}",
        f"Risk Change: {_format_risk_change(comparison)}",
        f"Unchanged Ports: {len(comparison.get('unchanged_ports') or [])}",
    ]
    if impact is not None:
        lines.extend(["", "Impact", impact.get("summary", "No material exposure changes detected.")])

    return "\n".join(lines)


def parse_nmap_result(result: dict[str, object]) -> dict:
    parsed_output = parse_nmap_output(str(result.get("output") or ""))
    if result.get("target") is not None and parsed_output.get("target") is None:
        parsed_output["target"] = result["target"]

    parsed_output.update(assess_nmap_ports(parsed_output.get("open_ports", [])))
    return parsed_output


def store_successful_nmap_finding(user_id: int, result: dict[str, object]) -> dict | None:
    if result.get("success") is not True:
        return None

    parsed_output = parse_nmap_result(result)
    return store_parsed_nmap_finding(user_id=user_id, parsed_output=parsed_output, source="nmap")


def store_parsed_nmap_finding(user_id: int, parsed_output: dict, source: str) -> dict:
    assessed_output = dict(parsed_output)
    assessed_output.update(assess_nmap_ports(assessed_output.get("open_ports", [])))
    enriched_open_ports = enrich_open_ports(assessed_output.get("open_ports", []))
    previous_finding = get_latest_user_finding_for_target(
        user_id,
        assessed_output.get("target"),
        sources=_comparison_sources_for(source),
    )
    comparison = compare_findings(
        previous=previous_finding,
        current={
            **assessed_output,
            "open_ports": enriched_open_ports,
        },
    )
    impact = assess_change_impact(comparison)
    return add_finding(
        user_id=user_id,
        finding={
            "source": source,
            "target": assessed_output.get("target"),
            "target_key": normalize_target_key(assessed_output.get("target")),
            "host_status": assessed_output.get("host_status"),
            "open_ports": enriched_open_ports,
            "duration": assessed_output.get("duration"),
            "risk_level": assessed_output.get("risk_level"),
            "risk_notes": assessed_output.get("risk_notes", []),
            "comparison": comparison,
            "impact": impact,
        },
    )


def _comparison_sources_for(source: str) -> set[str]:
    if source in {"nmap", "nmap_xml"}:
        return {"nmap", "nmap_xml"}
    if source == "nuclei":
        return {"nuclei"}

    return {source}


def enrich_open_ports(open_ports: list[dict]) -> list[dict]:
    enriched_ports = []
    for open_port in open_ports:
        enriched_ports.append(
            {
                **open_port,
                "intelligence": get_service_intelligence(
                    service_name=str(open_port.get("service", "")),
                    port=str(open_port.get("port", "")),
                ),
            }
        )

    return enriched_ports


def _format_ports(open_ports: list[dict]) -> str:
    if not open_ports:
        return "none"

    return ", ".join(
        f"{open_port.get('port')}/{open_port.get('protocol')} {open_port.get('service')}" for open_port in open_ports
    )


def _format_risk_change(comparison: dict) -> str:
    if comparison.get("risk_changed"):
        return f"{str(comparison.get('previous_risk')).upper()} -> {str(comparison.get('current_risk')).upper()}"

    return "none"


async def scan_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    if update.effective_user is not None:
        clear_finding_analysis_context(update.effective_user.id)

    await update.message.reply_text(
        build_scan_text(),
        reply_markup=build_scan_type_keyboard(),
    )


async def scan_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return

    await query.answer()

    if query.data == "nav:home":
        await query.edit_message_text(build_home_text())
        if query.message is not None:
            await query.message.reply_text(
                "Main menu",
                reply_markup=build_main_menu_keyboard(),
            )
        return

    if query.data is None or not query.data.startswith("scan:"):
        return

    scan_type = query.data.removeprefix("scan:")
    if scan_type not in SUPPORTED_SCAN_TYPES:
        await query.edit_message_text("Unsupported scan type.")
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is None:
        await query.edit_message_text("Unable to identify Telegram user.")
        return

    scan_request = create_scan_request(user_id=user_id, scan_type=scan_type)
    if scan_type == "nmap":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_nmap_target_prompt())
        return

    if scan_type == "nuclei":
        mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
        context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
        await query.edit_message_text(build_nuclei_target_prompt())
        return

    await query.edit_message_text(build_scan_created_text(scan_type))


async def scan_target_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    if user_id is not None:
        finding_analysis_context = get_finding_analysis_context(user_id)
        if finding_analysis_context is not None:
            if _is_finding_analysis_exit_message(update.message.text or ""):
                clear_finding_analysis_context(user_id)
                logger.info("Finding analysis ended for user_id=%s", user_id)
                await update.message.reply_text("Exited Finding Analysis Mode.", reply_markup=build_main_menu_keyboard())
                return

            logger.info("Finding analysis question for user_id=%s", user_id)
            await update.message.reply_text("Analyzing...")
            prompt = build_finding_followup_ai_prompt(finding_analysis_context, update.message.text or "")
            try:
                logger.info("AI request started for finding analysis user_id=%s", user_id)
                ai_response = await asyncio.to_thread(ask_ai, prompt)
                logger.info("AI request completed for finding analysis user_id=%s", user_id)
            except Exception:
                logger.exception("Finding analysis AI request failed for user_id=%s", user_id)
                await update.message.reply_text("AI request failed. Check bot logs.")
                return

            await update.message.reply_text(ai_response)
            return

    if user_id is not None and is_ai_waiting(user_id):
        logger.info("Ask Mongrel question received for user_id=%s", user_id)
        await update.message.reply_text("Analyzing...")
        try:
            logger.info("AI request started for user_id=%s", user_id)
            ai_response = await asyncio.to_thread(ask_ai, update.message.text or "")
            logger.info("AI request completed for user_id=%s", user_id)
        except Exception:
            logger.exception("AI request failed for user_id=%s", user_id)
            await update.message.reply_text("AI request failed. Check bot logs.")
            return

        await update.message.reply_text(ai_response)
        return

    if update.message.text in MAIN_MENU_BUTTONS:
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    scan_request_id = context.user_data.get(PENDING_NMAP_REQUEST_KEY)
    if user_id is None or not isinstance(scan_request_id, str):
        return

    scan_request = get_scan_request(user_id=user_id, scan_request_id=scan_request_id)
    if scan_request is None or scan_request.status != "awaiting_target":
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    if scan_request.scan_type == "nuclei":
        await _handle_nuclei_target(update, context, user_id, scan_request_id)
        return

    if scan_request.scan_type != "nmap":
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    target = update.message.text or ""
    await update.message.reply_text(build_nmap_scan_started_text(target.strip()))

    try:
        result = await asyncio.to_thread(run_nmap_scan, target)
    except ValueError as exc:
        await update.message.reply_text(f"Invalid NMAP target: {exc}")
        return

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result["target"]),
        result=result,
    )
    finding = store_successful_nmap_finding(user_id=user_id, result=result)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    await update.message.reply_text(
        append_change_summary(
            build_nmap_scan_result_text(result),
            finding.get("comparison") if finding else None,
            finding.get("impact") if finding else None,
        )
    )


def _is_finding_analysis_exit_message(text: str) -> bool:
    return text.strip().lower() in {"home", "cancel", "/home", "/cancel"}


async def _handle_nuclei_target(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    scan_request_id: str,
) -> None:
    if update.message is None:
        return

    target = update.message.text or ""
    display_target = normalize_target(target) or target.strip()
    status_message = await update.message.reply_text(build_nuclei_status_card(display_target, "Initializing", 0))
    active_scan = set_active_scan(
        user_id=user_id,
        scan_type="nuclei",
        target=display_target,
        status_message=status_message,
    )
    started_at = asyncio.get_running_loop().time()
    status_task = asyncio.create_task(_update_nuclei_status_card(user_id, status_message, display_target, started_at))
    task = asyncio.create_task(
        _run_nuclei_scan_background(
            user_id=user_id,
            scan_request_id=scan_request_id,
            target=target,
            message=update.message,
            status_message=status_message,
            display_target=display_target,
            started_at=started_at,
        )
    )
    set_active_scan_status_task(user_id, status_task)
    set_active_scan_task(user_id, task)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    logger.info(
        "Nuclei scan started for user_id=%s target=%s started_at=%s",
        user_id,
        active_scan.target,
        active_scan.started_at.isoformat(),
    )


async def _run_nuclei_scan_background(
    user_id: int,
    scan_request_id: str,
    target: str,
    message: object,
    status_message: object,
    display_target: str,
    started_at: float,
) -> None:
    try:
        result = await asyncio.to_thread(run_nuclei_scan, target)
    except ValueError as exc:
        _stop_nuclei_status_updates(user_id)
        clear_active_scan(user_id)
        await _finalize_nuclei_status(status_message, display_target, "Failed", started_at, str(exc))
        await _send_scan_message(message, f"Invalid Nuclei target: {exc}")
        return
    except asyncio.CancelledError:
        elapsed_seconds = asyncio.get_running_loop().time() - started_at
        await _finalize_nuclei_status(status_message, display_target, "Cancelled", started_at)
        logger.info("Nuclei scan cancelled for user_id=%s elapsed_seconds=%.2f", user_id, elapsed_seconds)
        raise

    active_scan = get_active_scan(user_id)
    if active_scan is None or active_scan.cancelled:
        elapsed_seconds = asyncio.get_running_loop().time() - started_at
        logger.info("Nuclei scan result discarded for user_id=%s elapsed_seconds=%.2f", user_id, elapsed_seconds)
        return

    complete_scan_request(
        user_id=user_id,
        scan_request_id=scan_request_id,
        target=str(result["target"]),
        result=result,
    )
    _stop_nuclei_status_updates(user_id)
    clear_active_scan(user_id)
    elapsed_seconds = asyncio.get_running_loop().time() - started_at
    logger.info("Nuclei scan completed for user_id=%s elapsed_seconds=%.2f", user_id, elapsed_seconds)

    if result.get("success") is not True:
        await _finalize_nuclei_status(
            status_message,
            display_target,
            "Failed",
            started_at,
            str(result.get("error") or "Unknown error."),
        )
        await _send_scan_message(message, f"Nuclei scan failed: {result.get('error') or 'Unknown error.'}")
        return

    await _finalize_nuclei_status(status_message, display_target, "Complete", started_at)
    output = str(result.get("output") or "")
    if not output.strip():
        clean_target = str(result.get("target") or target)
        store_clean_nuclei_scan(user_id=user_id, target=clean_target)
        await _send_scan_message(message, build_clean_nuclei_verdict_text(clean_target))
        return

    try:
        nuclei_findings = parse_nuclei_results(output)
    except NucleiParserError:
        await _send_scan_message(message, "Unable to parse Nuclei scan output.")
        return

    if not nuclei_findings:
        clean_target = str(result.get("target") or target)
        store_clean_nuclei_scan(user_id=user_id, target=clean_target)
        await _send_scan_message(message, build_clean_nuclei_verdict_text(clean_target))
        return

    from app.bot.handlers.upload import build_nuclei_import_success_text, store_nuclei_finding

    finding = store_nuclei_finding(user_id=user_id, nuclei_findings=nuclei_findings)
    await _send_scan_message(message, build_nuclei_import_success_text(finding))


async def _update_nuclei_status_card(user_id: int, status_message: object, target: str, started_at: float) -> None:
    try:
        while True:
            await asyncio.sleep(NUCLEI_STATUS_UPDATE_INTERVAL_SECONDS)
            active_scan = get_active_scan(user_id)
            if active_scan is None or active_scan.cancelled:
                return

            elapsed_seconds = int(asyncio.get_running_loop().time() - started_at)
            await _edit_status_message(status_message, build_nuclei_status_card(target, "Running", elapsed_seconds))
    except asyncio.CancelledError:
        return


def _stop_nuclei_status_updates(user_id: int) -> None:
    active_scan = get_active_scan(user_id)
    if active_scan is not None and active_scan.status_task is not None and not active_scan.status_task.done():
        active_scan.status_task.cancel()


async def _finalize_nuclei_status(
    status_message: object,
    target: str,
    status: str,
    started_at: float,
    reason: str | None = None,
) -> None:
    elapsed_seconds = int(asyncio.get_running_loop().time() - started_at)
    await _edit_status_message(status_message, build_nuclei_status_card(target, status, elapsed_seconds, reason))


async def _edit_status_message(status_message: object, text: str) -> None:
    edit_text = getattr(status_message, "edit_text", None)
    edit_method = edit_text or getattr(status_message, "edit_message_text", None)
    if edit_method is None:
        return

    try:
        await edit_method(text)
    except TimedOut as exc:
        logger.warning("Nuclei status card edit timed out: %s", exc)
    except NetworkError as exc:
        logger.warning("Nuclei status card edit failed due to Telegram network error: %s", exc)
    except BadRequest as exc:
        logger.warning("Nuclei status card edit was rejected by Telegram: %s", exc)
    except Exception:
        logger.warning("Nuclei status card edit failed unexpectedly.", exc_info=True)


async def _send_scan_message(message: object, text: str) -> None:
    reply_text = getattr(message, "reply_text", None)
    if reply_text is None:
        return

    try:
        await reply_text(text)
    except Exception:
        logger.exception("Failed to send Nuclei scan result message.")
