import asyncio

from telegram import Update
from telegram.ext import ContextTypes

from app.bot.handlers.home import build_home_text
from app.bot.keyboards import MAIN_MENU_BUTTONS, build_main_menu_keyboard, build_scan_type_keyboard
from app.models.scan_request import SUPPORTED_SCAN_TYPES
from app.services.findings_store import add_finding
from app.services.risk_rules import assess_nmap_ports
from app.services.scan_manager import (
    complete_scan_request,
    create_scan_request,
    get_scan_request,
    mark_scan_request_awaiting_target,
)
from app.services.service_intelligence import get_service_intelligence
from app.tools.nmap_parser import format_nmap_result, parse_nmap_output
from app.tools.nmap_runner import run_nmap_scan

PENDING_NMAP_REQUEST_KEY = "pending_nmap_scan_request_id"


def build_scan_text() -> str:
    return "Choose a scan workflow to prepare. No external tools will run yet."


def build_scan_created_text(scan_type: str) -> str:
    return (
        f"{scan_type.upper()} scan request created with status: pending.\n\n"
        "Target collection and tool execution will be added in a later mission."
    )


def build_nmap_target_prompt() -> str:
    return "NMAP scan request created. Send the authorized target hostname or IP address to run the scan."


def build_nmap_scan_started_text(target: str) -> str:
    return f"Running NMAP scan for target: {target}"


def build_nmap_scan_result_text(result: dict[str, object]) -> str:
    output = str(result.get("output") or "")
    fallback_output = str(result.get("error") or output or "No output returned.")
    parsed_output = parse_nmap_result(result)

    return format_nmap_result(parsed_output, fallback_output=fallback_output)


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
    enriched_open_ports = enrich_open_ports(parsed_output.get("open_ports", []))
    return add_finding(
        user_id=user_id,
        finding={
            "source": "nmap",
            "target": parsed_output.get("target"),
            "host_status": parsed_output.get("host_status"),
            "open_ports": enriched_open_ports,
            "duration": parsed_output.get("duration"),
            "risk_level": parsed_output.get("risk_level"),
            "risk_notes": parsed_output.get("risk_notes", []),
        },
    )


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


async def scan_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

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

    await query.edit_message_text(build_scan_created_text(scan_type))


async def scan_target_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    if update.message.text in MAIN_MENU_BUTTONS:
        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    scan_request_id = context.user_data.get(PENDING_NMAP_REQUEST_KEY)
    if user_id is None or not isinstance(scan_request_id, str):
        return

    scan_request = get_scan_request(user_id=user_id, scan_request_id=scan_request_id)
    if scan_request is None or scan_request.scan_type != "nmap" or scan_request.status != "awaiting_target":
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
    store_successful_nmap_finding(user_id=user_id, result=result)
    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    await update.message.reply_text(build_nmap_scan_result_text(result))
