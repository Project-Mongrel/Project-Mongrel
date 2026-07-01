from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.assessment_store import (
    add_assessment_target,
    create_assessment,
    get_assessment,
    list_assessment_scans,
    list_assessment_targets,
)
from app.services.assessment_ai import FALLBACK_REPORT, answer_assessment_question, generate_assessment_ai_report
from app.services.assessment_context import build_assessment_context
from app.services.assessment_markdown_report import generate_assessment_markdown_report
from app.services.icon_helper import icon_label, section_label

ASSESSMENT_FLOW_STATE_KEY = "assessment_flow_state"
ASSESSMENT_CHAT_STATE_KEY = "assessment_chat_state"
ASSESSMENT_SCAN_CONTEXT_KEY = "assessment_scan_context"
ASSESSMENT_STAGE_NAME = "awaiting_name"
ASSESSMENT_STAGE_TARGET = "awaiting_target"
ASSESSMENT_CALLBACK_PREFIX = "assessment"
ACTIVE_ASSESSMENT_ID_KEY = "active_assessment_id"


def build_assessment_chat_intro(assessment: dict, targets: list[dict] | None = None) -> str:
    targets = targets or []
    target_address = targets[0]["address"] if targets else "Not set"
    return "\n".join(
        [
            section_label("mongrel_ai", "Assessment AI"),
            "",
            "Assessment:",
            assessment.get("name") or "Untitled assessment",
            "",
            "Target:",
            target_address,
            "",
            "Ask anything about this assessment.",
            "",
            "I will answer only from collected evidence.",
        ]
    )


def build_new_assessment_name_prompt() -> str:
    return "\n".join(
        [
            section_label("investigation", "New Assessment"),
            "",
            "Send an assessment name.",
            "",
            "Example:",
            "Acme External Assessment",
        ]
    )


def build_assessment_target_prompt(name: str) -> str:
    return "\n".join(
        [
            section_label("target", "Primary Target"),
            "",
            f"Assessment: {name}",
            "",
            "Send the primary target address.",
            "",
            "Examples:",
            "example.com",
            "https://example.com",
            "192.168.1.10",
        ]
    )


def build_assessment_dashboard_text(assessment: dict, targets: list[dict] | None = None, scans: list[dict] | None = None) -> str:
    targets = targets or []
    scans = scans or []
    target_address = targets[0]["address"] if targets else "Not set"
    scan_status = _scan_statuses(scans)
    latest_activity = _latest_scan_time(scans) or assessment.get("updated_at")
    return "\n".join(
        [
            section_label("investigation", "Assessment Dashboard"),
            "",
            icon_label("summary", "Assessment"),
            assessment.get("name") or "Untitled assessment",
            "",
            icon_label("target", "Target"),
            target_address,
            "",
            icon_label("status", "Status"),
            str(assessment.get("status") or "active").title(),
            "",
            icon_label("elapsed", "Last Updated"),
            _format_dashboard_time(latest_activity),
            "",
            icon_label("scan", "Scans"),
            f"Nmap: {scan_status['nmap']}",
            f"BBOT: {scan_status['bbot']}",
            f"Nuclei: {scan_status['nuclei']}",
        ]
    )


def build_assessment_dashboard_keyboard(assessment_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Run Nmap", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:nmap:{assessment_id}"),
                InlineKeyboardButton("Run BBOT", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:bbot:{assessment_id}"),
            ],
            [InlineKeyboardButton("Run Nuclei", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:nuclei:{assessment_id}")],
            [
                InlineKeyboardButton("Ask Mongrel", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:ask:{assessment_id}"),
                InlineKeyboardButton("Generate AI Report", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:ai_report:{assessment_id}"),
            ],
            [
                InlineKeyboardButton("Markdown Report", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:markdown:{assessment_id}"),
                InlineKeyboardButton("History", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:history:{assessment_id}"),
            ],
            [InlineKeyboardButton("Home", callback_data="nav:home")],
        ]
    )


def build_assessment_history_text(assessment: dict, scans: list[dict] | None = None) -> str:
    scans = scans or []
    lines = [
        section_label("history", "Assessment History"),
        "",
        icon_label("summary", "Assessment"),
        assessment.get("name") or "Untitled assessment",
        "",
    ]
    if not scans:
        lines.append("No assessment scans recorded yet.")
        return "\n".join(lines)

    for scan in scans[-10:]:
        lines.extend(
            [
                f"{str(scan.get('tool') or 'unknown').upper()} - {str(scan.get('status') or 'unknown').title()}",
                f"Time: {_format_dashboard_time(_scan_time(scan))}",
            ]
        )
        if scan.get("risk"):
            lines.append(f"Risk: {str(scan['risk']).upper()}")
        if scan.get("elapsed_seconds") is not None:
            lines.append(f"Elapsed: {scan['elapsed_seconds']}s")
        lines.append("")
    return "\n".join(lines).rstrip()


def build_assessment_history_keyboard(assessment_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Back to Assessment", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:dashboard:{assessment_id}")],
            [InlineKeyboardButton("Home", callback_data="nav:home")],
        ]
    )


def is_assessment_flow_active(context: ContextTypes.DEFAULT_TYPE) -> bool:
    user_data = getattr(context, "user_data", None)
    return bool(isinstance(user_data, dict) and user_data.get(ASSESSMENT_FLOW_STATE_KEY))


def clear_assessment_flow_state(context: ContextTypes.DEFAULT_TYPE) -> None:
    user_data = getattr(context, "user_data", None)
    if isinstance(user_data, dict):
        user_data.pop(ASSESSMENT_FLOW_STATE_KEY, None)
        user_data.pop(ASSESSMENT_CHAT_STATE_KEY, None)


def clear_assessment_chat_state(context: ContextTypes.DEFAULT_TYPE) -> None:
    user_data = getattr(context, "user_data", None)
    if isinstance(user_data, dict):
        user_data.pop(ASSESSMENT_CHAT_STATE_KEY, None)


def is_assessment_chat_active(context: ContextTypes.DEFAULT_TYPE) -> bool:
    user_data = getattr(context, "user_data", None)
    return bool(isinstance(user_data, dict) and user_data.get(ASSESSMENT_CHAT_STATE_KEY))


async def new_assessment_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return

    context.user_data[ASSESSMENT_FLOW_STATE_KEY] = {"stage": ASSESSMENT_STAGE_NAME}
    await update.message.reply_text(build_new_assessment_name_prompt(), reply_markup=build_main_menu_keyboard())


async def assessment_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if update.message is None:
        return False

    state = context.user_data.get(ASSESSMENT_FLOW_STATE_KEY)
    if not isinstance(state, dict):
        return False

    text = str(update.message.text or "").strip()
    if not text:
        await update.message.reply_text("Please send a non-empty value.")
        return True

    if state.get("stage") == ASSESSMENT_STAGE_NAME:
        state["name"] = text
        state["stage"] = ASSESSMENT_STAGE_TARGET
        context.user_data[ASSESSMENT_FLOW_STATE_KEY] = state
        await update.message.reply_text(build_assessment_target_prompt(text), reply_markup=build_main_menu_keyboard())
        return True

    if state.get("stage") == ASSESSMENT_STAGE_TARGET:
        assessment = create_assessment(str(state.get("name") or "Untitled Assessment"))
        target = add_assessment_target(assessment["id"], address=text)
        clear_assessment_flow_state(context)
        await update.message.reply_text(
            build_assessment_dashboard_text(assessment, [target], []),
            reply_markup=build_assessment_dashboard_keyboard(assessment["id"]),
        )
        return True

    clear_assessment_flow_state(context)
    return False


async def assessment_chat_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if update.message is None:
        return False

    state = context.user_data.get(ASSESSMENT_CHAT_STATE_KEY)
    if not isinstance(state, dict):
        return False

    text = str(update.message.text or "").strip()
    if text.lower() in {"home", "back", "cancel"}:
        clear_assessment_chat_state(context)
        await update.message.reply_text("Exited assessment Ask Mongrel mode.", reply_markup=build_main_menu_keyboard())
        return True
    if not text:
        await update.message.reply_text("Please send a question about this assessment.")
        return True

    assessment_id = int(state.get(ACTIVE_ASSESSMENT_ID_KEY) or state.get("assessment_id"))
    user_id = update.effective_user.id if update.effective_user is not None else 0
    await update.message.reply_text("Reviewing assessment evidence...")
    try:
        assessment_context = build_assessment_context(assessment_id=assessment_id, user_id=user_id)
        answer = answer_assessment_question(text, assessment_context)
    except Exception:
        answer = "Assessment AI is unavailable. Review the assessment dashboard, scan history, and stored findings for next steps."
    await update.message.reply_text(answer)
    return True


async def assessment_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return

    await query.answer()
    data = str(query.data or "")
    parts = data.split(":")
    if len(parts) < 3 or parts[0] != ASSESSMENT_CALLBACK_PREFIX:
        await query.edit_message_text("Unsupported assessment action.")
        return

    action = parts[1]
    try:
        assessment_id = int(parts[-1])
    except ValueError:
        await query.edit_message_text("Assessment not found.")
        return

    assessment = get_assessment(assessment_id)
    if assessment is None:
        await query.edit_message_text("Assessment not found.")
        return

    if action == "dashboard":
        clear_assessment_chat_state(context)
        await query.edit_message_text(
            build_assessment_dashboard_text(
                assessment,
                list_assessment_targets(assessment_id),
                list_assessment_scans(assessment_id),
            ),
            reply_markup=build_assessment_dashboard_keyboard(assessment_id),
        )
        return

    if action == "history":
        await query.edit_message_text(
            build_assessment_history_text(assessment, list_assessment_scans(assessment_id)),
            reply_markup=build_assessment_history_keyboard(assessment_id),
        )
        return

    if action == "ask":
        targets = list_assessment_targets(assessment_id)
        context.user_data[ASSESSMENT_CHAT_STATE_KEY] = {
            "assessment_chat": True,
            ACTIVE_ASSESSMENT_ID_KEY: assessment_id,
            "assessment_id": assessment_id,
        }
        message = getattr(query, "message", None)
        reply_text = getattr(message, "reply_text", None)
        prompt = build_assessment_chat_intro(assessment, targets)
        if reply_text is not None:
            await reply_text(prompt)
        else:
            await query.edit_message_text(prompt)
        return

    if action == "ai_report":
        effective_user = getattr(update, "effective_user", None)
        user_id = effective_user.id if effective_user is not None else 0
        message = getattr(query, "message", None)
        reply_text = getattr(message, "reply_text", None)
        try:
            assessment_context = build_assessment_context(assessment_id=assessment_id, user_id=user_id)
            report = generate_assessment_ai_report(assessment_context)
        except Exception:
            report = FALLBACK_REPORT
        from app.bot.handlers.reports import split_report_text

        if reply_text is not None:
            for chunk in split_report_text(report):
                await reply_text(chunk)
        else:
            await query.edit_message_text(split_report_text(report)[0])
        return

    if action == "markdown":
        effective_user = getattr(update, "effective_user", None)
        user_id = effective_user.id if effective_user is not None else 0
        message = getattr(query, "message", None)
        reply_text = getattr(message, "reply_text", None)
        assessment_context = build_assessment_context(assessment_id=assessment_id, user_id=user_id)
        report = generate_assessment_markdown_report(assessment_context)
        from app.bot.handlers.reports import split_report_text

        if reply_text is not None:
            for chunk in split_report_text(report):
                await reply_text(chunk)
        else:
            await query.edit_message_text(split_report_text(report)[0])
        return

    if action != "run" or len(parts) != 4:
        await query.edit_message_text("Unsupported assessment action.")
        return

    tool = parts[2]
    targets = list_assessment_targets(assessment_id)
    if not targets:
        await query.edit_message_text("Assessment has no target configured.")
        return

    user_id = update.effective_user.id if update.effective_user is not None else None
    message = getattr(query, "message", None)
    if user_id is None or message is None:
        await query.edit_message_text("Unable to launch assessment scan.")
        return

    target = targets[0]
    await query.edit_message_text(
        f"Launching {tool.upper()} for assessment target:\n{target['address']}",
        reply_markup=build_assessment_dashboard_keyboard(assessment_id),
    )
    from app.bot.handlers.scan import PENDING_NMAP_REQUEST_KEY, scan_target_handler
    from app.services.scan_manager import create_scan_request, mark_scan_request_awaiting_target

    scan_request = create_scan_request(user_id=user_id, scan_type=tool)
    mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
    context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
    context.user_data[ASSESSMENT_SCAN_CONTEXT_KEY] = {
        "assessment_id": assessment_id,
        "target_id": target["id"],
        "tool": tool,
    }
    synthetic_update = type(
        "AssessmentScanUpdate",
        (),
        {
            "message": type(
                "AssessmentScanMessage",
                (),
                {"text": target["address"], "reply_text": message.reply_text},
            )(),
            "effective_user": update.effective_user,
        },
    )()
    await scan_target_handler(synthetic_update, context)


def _scan_statuses(scans: list[dict]) -> dict[str, str]:
    statuses = {"nmap": "Not run", "bbot": "Not run", "nuclei": "Not run"}
    for scan in scans:
        tool = str(scan.get("tool") or "").lower()
        if tool in statuses:
            statuses[tool] = str(scan.get("status") or "unknown").title()
    return statuses


def _latest_scan_time(scans: list[dict]) -> object | None:
    times = [_scan_time(scan) for scan in scans]
    times = [scan_time for scan_time in times if scan_time is not None]
    return max(times) if times else None


def _scan_time(scan: dict) -> object | None:
    return scan.get("completed_at") or scan.get("started_at") or scan.get("created_at") or scan.get("updated_at")


def _format_dashboard_time(value: object | None) -> str:
    if value is None:
        return "Not available"
    if hasattr(value, "astimezone"):
        return value.astimezone().strftime("%Y-%m-%d %H:%M")
    return str(value)
