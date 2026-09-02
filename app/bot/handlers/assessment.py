import logging
from pathlib import Path
from time import perf_counter

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import BadRequest
from telegram.ext import ContextTypes

from app.bot.keyboards import build_main_menu_keyboard
from app.services.assessment_store import (
    add_assessment_target,
    create_assessment,
    get_assessment,
    get_user_assessment,
    list_assessment_scans,
    list_assessment_targets,
)
from app.services.assessment_ai import FALLBACK_REPORT, generate_assessment_ai_report
from app.services.assessment_conversation_ai import FALLBACK_ANSWER, answer_assessment_conversation_question
from app.services.assessment_conversation_store import append_message, get_or_create_assessment_conversation, get_user_conversation
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
logger = logging.getLogger(__name__)


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
            "Your conversation is saved and will resume here next time.",
        ]
    )


def build_assessment_chat_keyboard(assessment_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Exit Conversation", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:exit_conversation:{assessment_id}")],
            [InlineKeyboardButton("Back to Assessment", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:dashboard:{assessment_id}")],
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
            f"httpx: {scan_status['httpx']}",
            f"Katana: {scan_status['katana']}",
            f"Playwright: {scan_status['playwright']}",
            f"ffuf: {scan_status['ffuf']}",
            f"testssl.sh: {scan_status['testssl']}",
            f"Gitleaks: {scan_status['gitleaks']}",
            f"Prowler: {scan_status['prowler']}",
            f"Metasploit: {scan_status['metasploit']}",
            f"TShark: {scan_status['tshark']}",
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
            [InlineKeyboardButton("Run httpx", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:httpx:{assessment_id}")],
            [InlineKeyboardButton("Run Katana", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:katana:{assessment_id}")],
            [InlineKeyboardButton("Run Playwright", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:playwright:{assessment_id}")],
            [InlineKeyboardButton("Run ffuf", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:ffuf:{assessment_id}")],
            [InlineKeyboardButton("Run testssl.sh", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:testssl:{assessment_id}")],
            [InlineKeyboardButton("Run Gitleaks", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:gitleaks:{assessment_id}")],
            [InlineKeyboardButton("Run Prowler", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:prowler:{assessment_id}")],
            [InlineKeyboardButton("Run Metasploit", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:metasploit:{assessment_id}")],
            [InlineKeyboardButton("Run TShark", callback_data=f"{ASSESSMENT_CALLBACK_PREFIX}:run:tshark:{assessment_id}")],
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


async def _safe_edit_assessment_dashboard(query: object, text: str, assessment_id: int, unchanged_notice: str | None = None) -> None:
    try:
        await query.edit_message_text(
            text,
            reply_markup=build_assessment_dashboard_keyboard(assessment_id),
        )
    except BadRequest as exc:
        if "message is not modified" in str(exc).lower():
            notice = unchanged_notice or "Assessment dashboard is already shown."
            message = getattr(query, "message", None)
            reply_text = getattr(message, "reply_text", None)
            if reply_text is not None and unchanged_notice:
                await reply_text(notice, reply_markup=build_assessment_dashboard_keyboard(assessment_id))
            await query.answer(notice)
            return
        raise


async def _send_assessment_skip_dashboard(query: object, text: str, assessment_id: int) -> None:
    message = getattr(query, "message", None)
    reply_text = getattr(message, "reply_text", None)
    if reply_text is not None:
        await reply_text(text, reply_markup=build_assessment_dashboard_keyboard(assessment_id))
        return
    await _safe_edit_assessment_dashboard(query, text, assessment_id, text.splitlines()[0] if text else None)


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
        user_id = update.effective_user.id if update.effective_user is not None else None
        assessment = create_assessment(str(state.get("name") or "Untitled Assessment"), user_id=user_id)
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
    if text.lower() in {"home", "back", "cancel", "exit conversation", "back to assessment"}:
        clear_assessment_chat_state(context)
        await update.message.reply_text("Exited assessment Ask Mongrel mode.", reply_markup=build_main_menu_keyboard())
        return True
    if not text:
        await update.message.reply_text("Please send a question about this assessment.")
        return True

    turn_started = perf_counter()
    try:
        assessment_id = int(state.get(ACTIVE_ASSESSMENT_ID_KEY) or state.get("assessment_id"))
    except (TypeError, ValueError):
        clear_assessment_chat_state(context)
        await update.message.reply_text("Assessment conversation is unavailable.", reply_markup=build_main_menu_keyboard())
        return True
    user_id = update.effective_user.id if update.effective_user is not None else None
    conversation_id = str(state.get("conversation_id") or "").strip()
    lookup_started = perf_counter()
    assessment = get_user_assessment(user_id, assessment_id) if user_id is not None else None
    if user_id is not None and conversation_id:
        get_user_conversation(user_id, conversation_id)
    lookup_ms = _assessment_ask_elapsed_ms(lookup_started)
    if assessment is None or not conversation_id:
        clear_assessment_chat_state(context)
        await update.message.reply_text("Assessment conversation not found.", reply_markup=build_main_menu_keyboard())
        return True

    user_persistence_started = perf_counter()
    try:
        append_message(
            conversation_id,
            user_id,
            "user",
            text,
            assessment_id=assessment_id,
            metadata={"source": "telegram"},
        )
    except Exception:
        await update.message.reply_text(
            "I could not save your question, so it was not sent to Ask Mongrel. Please try again.",
            reply_markup=build_assessment_chat_keyboard(assessment_id),
        )
        return True
    user_persistence_ms = _assessment_ask_elapsed_ms(user_persistence_started)

    await update.message.reply_text("Reviewing assessment evidence...")
    try:
        result = answer_assessment_conversation_question(
            user_id=user_id,
            assessment_id=assessment_id,
            conversation_id=conversation_id,
            question=text,
        )
    except Exception:
        result = {
            "answer": FALLBACK_ANSWER,
            "evidence_refs": {},
            "evidence_context_digest": None,
            "provenance": {"assessment_id": assessment_id, "user_id": user_id, "conversation_id": conversation_id},
            "fallback_reason": "exception",
        }

    answer = str(result.get("answer") or FALLBACK_ANSWER)
    assistant_persistence_started = perf_counter()
    try:
        append_message(
            conversation_id,
            user_id,
            "assistant",
            answer,
            assessment_id=assessment_id,
            evidence_refs=result.get("evidence_refs"),
            evidence_context_digest=result.get("evidence_context_digest"),
            metadata={
                "source": "telegram",
                "provenance": result.get("provenance") or {},
                "fallback_reason": result.get("fallback_reason"),
            },
        )
    except Exception:
        await update.message.reply_text(
            "Ask Mongrel generated a response, but I could not save it. The response was not added to this conversation; please try again.",
            reply_markup=build_assessment_chat_keyboard(assessment_id),
        )
        return True
    assistant_persistence_ms = _assessment_ask_elapsed_ms(assistant_persistence_started)

    await update.message.reply_text(answer, reply_markup=build_assessment_chat_keyboard(assessment_id))
    _log_assessment_ask_timing(
        assessment_id=assessment_id,
        conversation_id=conversation_id,
        lookup_ms=lookup_ms,
        user_persistence_ms=user_persistence_ms,
        assistant_persistence_ms=assistant_persistence_ms,
        total_ms=_assessment_ask_elapsed_ms(turn_started),
        instrumentation=result.get("instrumentation") or {},
        fallback_reason=result.get("fallback_reason"),
    )
    return True


def _log_assessment_ask_timing(
    *,
    assessment_id: int,
    conversation_id: str,
    lookup_ms: float,
    user_persistence_ms: float,
    assistant_persistence_ms: float,
    total_ms: float,
    instrumentation: dict,
    fallback_reason: object,
) -> None:
    logger.info(
        "assessment_ask_timing assessment_id=%s conversation_id=%s ownership_conversation_lookup_ms=%.3f context_ms=%.3f prompt_ms=%.3f "
        "ai_ms=%.3f postprocess_ms=%.3f user_persistence_ms=%.3f assistant_persistence_ms=%.3f persistence_ms=%.3f "
        "total_ms=%.3f prompt_chars=%s context_chars=%s history_message_count=%s evidence_scan_count=%s "
        "evidence_finding_count=%s evidence_artifact_count=%s output_token_budget=%s fallback_reason=%s",
        assessment_id,
        conversation_id,
        lookup_ms,
        float(instrumentation.get("context_ms") or 0.0),
        float(instrumentation.get("prompt_ms") or 0.0),
        float(instrumentation.get("ai_ms") or 0.0),
        float(instrumentation.get("postprocess_ms") or 0.0),
        user_persistence_ms,
        assistant_persistence_ms,
        user_persistence_ms + assistant_persistence_ms,
        total_ms,
        int(instrumentation.get("prompt_chars") or 0),
        int(instrumentation.get("context_chars") or 0),
        int(instrumentation.get("history_message_count") or 0),
        int(instrumentation.get("evidence_scan_count") or 0),
        int(instrumentation.get("evidence_finding_count") or 0),
        int(instrumentation.get("evidence_artifact_count") or 0),
        int(instrumentation.get("output_token_budget") or 0),
        str(fallback_reason or "none"),
    )


def _assessment_ask_elapsed_ms(started: float) -> float:
    return round((perf_counter() - started) * 1000, 3)


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

    effective_user = getattr(update, "effective_user", None)
    user_id = effective_user.id if effective_user is not None else None
    assessment = get_assessment(assessment_id)
    if assessment is None:
        await query.edit_message_text("Assessment not found.")
        return

    conversation_operation = action in {"ask", "exit_conversation"} or (
        action == "dashboard" and is_assessment_chat_active(context)
    )
    if conversation_operation and (user_id is None or get_user_assessment(user_id, assessment_id) is None):
        await query.edit_message_text("Assessment not found.")
        return

    if action == "dashboard":
        clear_assessment_chat_state(context)
        await _safe_edit_assessment_dashboard(
            query,
            build_assessment_dashboard_text(
                assessment,
                list_assessment_targets(assessment_id),
                list_assessment_scans(assessment_id),
            ),
            assessment_id,
        )
        return

    if action == "exit_conversation":
        clear_assessment_chat_state(context)
        message = getattr(query, "message", None)
        reply_text = getattr(message, "reply_text", None)
        if reply_text is not None:
            await reply_text("Exited assessment Ask Mongrel mode.", reply_markup=build_main_menu_keyboard())
        else:
            await query.edit_message_text("Exited assessment Ask Mongrel mode.")
        return

    if action == "history":
        await query.edit_message_text(
            build_assessment_history_text(assessment, list_assessment_scans(assessment_id)),
            reply_markup=build_assessment_history_keyboard(assessment_id),
        )
        return

    if action == "ask":
        targets = list_assessment_targets(assessment_id)
        try:
            conversation = get_or_create_assessment_conversation(
                user_id=user_id,
                assessment_id=assessment_id,
                title=f"Ask Mongrel — {assessment.get('name') or 'Untitled assessment'}",
                metadata={"source": "telegram"},
            )
        except Exception:
            await query.edit_message_text("Assessment conversation could not be opened. Please try again.")
            return
        context.user_data[ASSESSMENT_CHAT_STATE_KEY] = {
            "assessment_chat": True,
            ACTIVE_ASSESSMENT_ID_KEY: assessment_id,
            "assessment_id": assessment_id,
            "conversation_id": conversation["id"],
        }
        message = getattr(query, "message", None)
        reply_text = getattr(message, "reply_text", None)
        prompt = build_assessment_chat_intro(assessment, targets)
        if reply_text is not None:
            await reply_text(prompt, reply_markup=build_assessment_chat_keyboard(assessment_id))
        else:
            await query.edit_message_text(prompt, reply_markup=build_assessment_chat_keyboard(assessment_id))
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

    user_id = update.effective_user.id if update.effective_user is not None else None
    message = getattr(query, "message", None)
    if user_id is None or message is None:
        await query.edit_message_text("Unable to launch assessment scan.")
        return

    if tool == "tshark":
        from app.bot.handlers.upload import build_tshark_mode_keyboard, build_tshark_mode_text, clear_upload_state
        from app.bot.handlers.scan import PENDING_NMAP_REQUEST_KEY

        context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
        context.user_data.pop(ASSESSMENT_SCAN_CONTEXT_KEY, None)
        clear_upload_state(user_id)
        await message.reply_text(
            build_tshark_mode_text(),
            reply_markup=build_tshark_mode_keyboard(assessment_id),
        )
        return

    if not targets:
        await query.edit_message_text("Assessment has no target configured.")
        return

    target = targets[0]
    target_address = str(target["address"]).strip()
    if tool == "gitleaks" and not Path(target_address).is_dir():
        skip_message = (
            "Gitleaks is not applicable to this assessment target. "
            "Gitleaks requires a valid local directory; run it standalone with a local path."
        )
        await _send_assessment_skip_dashboard(
            query,
            f"{skip_message}\n\n"
            + build_assessment_dashboard_text(assessment, targets, list_assessment_scans(assessment_id)),
            assessment_id,
        )
        return
    if tool == "prowler" and target_address.lower() not in {"aws", "azure", "gcp"}:
        skip_message = (
            "Prowler is not applicable to this assessment target. "
            "Prowler requires the assessment target to be exactly aws, azure, or gcp for this workflow."
        )
        await _send_assessment_skip_dashboard(
            query,
            f"{skip_message}\n\n"
            + build_assessment_dashboard_text(assessment, targets, list_assessment_scans(assessment_id)),
            assessment_id,
        )
        return

    await query.edit_message_text(
        f"Launching {tool.upper()} for assessment target:\n{target_address}",
        reply_markup=build_assessment_dashboard_keyboard(assessment_id),
    )
    from app.bot.handlers.scan import PENDING_NMAP_REQUEST_KEY, scan_target_handler
    from app.services.scan_manager import create_scan_request, mark_scan_request_awaiting_target

    context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
    context.user_data.pop(ASSESSMENT_SCAN_CONTEXT_KEY, None)
    scan_request = create_scan_request(user_id=user_id, scan_type=tool)
    mark_scan_request_awaiting_target(user_id=user_id, scan_request_id=scan_request.id)
    context.user_data[PENDING_NMAP_REQUEST_KEY] = scan_request.id
    context.user_data[ASSESSMENT_SCAN_CONTEXT_KEY] = {
        "assessment_id": assessment_id,
        "target_id": target["id"],
        "cloud_context": target.get("name") or f"assessment-{str(target['address']).strip().lower()}",
        "primary_target": target_address,
        "tool": tool,
    }
    if tool == "metasploit":
        from app.bot.handlers.scan import build_metasploit_mode_keyboard, build_metasploit_mode_text, build_metasploit_readiness_failure_text
        from app.tools.metasploit_runner import check_metasploit_readiness

        readiness = check_metasploit_readiness(run_version_check=False)
        if readiness.get("ready") is not True:
            context.user_data.pop(PENDING_NMAP_REQUEST_KEY, None)
            context.user_data.pop(ASSESSMENT_SCAN_CONTEXT_KEY, None)
            await message.reply_text(build_metasploit_readiness_failure_text(readiness))
            return

        assessment_context = build_assessment_context(assessment_id=assessment_id, user_id=user_id)
        known_assets = {target_address}
        for finding in assessment_context.get("findings") or []:
            candidate = str(finding.get("target") or "").strip()
            if candidate:
                known_assets.add(candidate)
            for key in ("httpx_services", "katana_observations", "ffuf_results"):
                for item in finding.get(key) or []:
                    for value_key in ("url", "host"):
                        candidate = str(item.get(value_key) or "").strip()
                        if candidate:
                            known_assets.add(candidate)
            observation = finding.get("playwright_observation") or {}
            for value_key in ("requested_url", "final_url"):
                candidate = str(observation.get(value_key) or "").strip()
                if candidate:
                    known_assets.add(candidate)
        context.user_data[ASSESSMENT_SCAN_CONTEXT_KEY]["known_assets"] = sorted(known_assets)
        await message.reply_text(
            build_metasploit_mode_text(),
            reply_markup=build_metasploit_mode_keyboard(scan_request.id),
        )
        return
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
    statuses = {"nmap": "Not run", "bbot": "Not run", "nuclei": "Not run", "httpx": "Not run", "katana": "Not run", "playwright": "Not run", "ffuf": "Not run", "testssl": "Not run", "gitleaks": "Not run", "prowler": "Not run", "metasploit": "Not run", "tshark": "Not run"}
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
