import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from telegram import CallbackQuery, Chat, Message, Update, User
from telegram.ext import CallbackQueryHandler

from app.bot.bot import build_application
from app.bot.handlers.scan import _send_specialist_ai_assessment, tool_mode_callback_handler
from app.bot.keyboards.tool_mode_actions import TOOL_MODE_TOOLS, build_tool_mode_post_scan_keyboard
from app.core.config import Settings


EXPECTED_TOOLS = (
    "nmap", "bbot", "nuclei", "httpx", "playwright", "katana", "ffuf", "testssl",
    "gitleaks", "prowler", "metasploit", "tshark",
)


@pytest.mark.parametrize("tool", EXPECTED_TOOLS)
def test_all_twelve_tools_share_the_same_terminal_action_keyboard(tool: str) -> None:
    keyboard = build_tool_mode_post_scan_keyboard(tool)
    buttons = [(row[0].text, row[0].callback_data) for row in keyboard.inline_keyboard]

    assert buttons == [
        ("🔄 Run Again", f"toolmode:run:{tool}"),
        ("✦ Ask Mongrel", "toolmode:ask"),
        ("⬅️ Back to Tools", "toolmode:back"),
    ]
    assert TOOL_MODE_TOOLS == EXPECTED_TOOLS


@pytest.mark.parametrize("outcome", ("success", "fallback", "error"))
@pytest.mark.parametrize("tool", EXPECTED_TOOLS)
def test_terminal_ai_delivery_attaches_actions_for_success_fallback_and_error(tool: str, outcome: str) -> None:
    fallback = ["AI unavailable."]
    if outcome == "success":
        generator = Mock(return_value=["Executive Summary", "Bounded result."])
    elif outcome == "fallback":
        generator = Mock(return_value=fallback)
    else:
        generator = Mock(side_effect=RuntimeError("model unavailable"))
    message = SimpleNamespace(reply_text=AsyncMock())

    async def run_inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    with patch("app.bot.handlers.scan.safe_edit_text", new_callable=AsyncMock), patch(
        "app.bot.handlers.scan.asyncio.to_thread", side_effect=run_inline
    ):
        asyncio.run(_send_specialist_ai_assessment(
            message, {}, tool=tool, label=tool, generator=generator,
            fallback_lines=fallback, tool_mode=True,
        ))

    final = message.reply_text.call_args_list[-1]
    assert final.kwargs["reply_markup"] == build_tool_mode_post_scan_keyboard(tool)


def test_assessment_mode_specialist_delivery_has_no_tool_mode_keyboard() -> None:
    message = SimpleNamespace(reply_text=AsyncMock())
    async def run_inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    with patch("app.bot.handlers.scan.safe_edit_text", new_callable=AsyncMock), patch(
        "app.bot.handlers.scan.asyncio.to_thread", side_effect=run_inline
    ):
        asyncio.run(_send_specialist_ai_assessment(
            message, {}, tool="nmap", label="Nmap", generator=Mock(return_value=["Complete."]),
            fallback_lines=["Unavailable."], tool_mode=False,
        ))

    assert "reply_markup" not in message.reply_text.call_args_list[-1].kwargs


@pytest.mark.parametrize("action", ("ask", "back"))
def test_tool_mode_navigation_callbacks_are_acknowledged_and_do_not_execute_scanners(action: str) -> None:
    query = SimpleNamespace(data=f"toolmode:{action}", answer=AsyncMock(), edit_message_text=AsyncMock())
    update = SimpleNamespace(callback_query=query, effective_user=SimpleNamespace(id=8800))
    context = SimpleNamespace(user_data={})

    with patch("app.bot.handlers.scan.run_nmap_scan") as runner:
        asyncio.run(tool_mode_callback_handler(update, context))

    query.answer.assert_awaited_once()
    runner.assert_not_called()
    rendered = query.edit_message_text.call_args.args[0]
    if action == "ask":
        assert "Ask Mongrel" in rendered
    else:
        assert query.edit_message_text.call_args.kwargs["reply_markup"] is not None


def test_metasploit_run_again_only_reopens_existing_guided_flow() -> None:
    keyboard = build_tool_mode_post_scan_keyboard("metasploit")
    run_again = keyboard.inline_keyboard[0][0]

    assert run_again.callback_data == "toolmode:run:metasploit"
    assert "approve" not in run_again.callback_data
    assert "execute" not in run_again.callback_data


def _registered_callback(application, data: str):
    message = Message(message_id=1, date=datetime.now(UTC), chat=Chat(id=8800, type="private"), text="result")
    query = CallbackQuery(
        id=f"query-{data}", from_user=User(id=8800, first_name="Tester", is_bot=False),
        chat_instance="tool-mode", message=message, data=data,
    )
    update = Update(update_id=1, callback_query=query)
    update.set_bot(application.bot)
    query.set_bot(application.bot)
    message.set_bot(application.bot)
    matched = [
        handler for handler in application.handlers[0]
        if isinstance(handler, CallbackQueryHandler) and handler.check_update(update)
    ]
    return update, matched


@pytest.mark.parametrize("tool", EXPECTED_TOOLS)
def test_application_dispatcher_registers_all_tool_mode_run_callbacks(tool: str) -> None:
    application = build_application(Settings(_env_file=None, telegram_bot_token="123456:TEST"))
    update, matched = _registered_callback(application, f"toolmode:run:{tool}")
    context = SimpleNamespace(user_data={})

    assert matched
    assert matched[0].callback is tool_mode_callback_handler
    with (
        patch.object(type(application.bot), "answer_callback_query", new_callable=AsyncMock) as answer,
        patch("app.bot.handlers.scan.scan_callback_handler", new_callable=AsyncMock) as scan_route,
    ):
        asyncio.run(matched[0].callback(update, context))

    answer.assert_awaited_once()
    routed_update = scan_route.await_args.args[0]
    assert routed_update.callback_query.data == f"scan:{tool}"
    assert scan_route.await_args.kwargs == {"acknowledge": False}


@pytest.mark.parametrize("data", ("toolmode:ask", "toolmode:back", "toolmode:run:unknown"))
def test_application_dispatcher_executes_shared_route_and_acknowledges(data: str) -> None:
    application = build_application(Settings(_env_file=None, telegram_bot_token="123456:TEST"))
    update, matched = _registered_callback(application, data)
    context = SimpleNamespace(user_data={})

    with (
        patch.object(type(application.bot), "answer_callback_query", new_callable=AsyncMock) as answer,
        patch.object(type(application.bot), "edit_message_text", new_callable=AsyncMock) as edit,
        patch("app.bot.handlers.scan.run_nmap_scan") as scanner,
    ):
        asyncio.run(matched[0].callback(update, context))

    answer.assert_awaited_once()
    edit.assert_awaited_once()
    scanner.assert_not_called()
    if data.endswith("unknown"):
        assert "Unsupported Tool Mode action" in edit.call_args.kwargs["text"]


def test_application_dispatcher_run_again_opens_input_without_execution() -> None:
    application = build_application(Settings(_env_file=None, telegram_bot_token="123456:TEST"))
    update, matched = _registered_callback(application, "toolmode:run:nmap")
    context = SimpleNamespace(user_data={})

    with (
        patch.object(type(application.bot), "answer_callback_query", new_callable=AsyncMock) as answer,
        patch.object(type(application.bot), "edit_message_text", new_callable=AsyncMock) as edit,
        patch("app.bot.handlers.scan.run_nmap_scan") as scanner,
    ):
        asyncio.run(matched[0].callback(update, context))

    answer.assert_awaited_once()
    assert "target" in edit.call_args.kwargs["text"].lower()
    scanner.assert_not_called()
