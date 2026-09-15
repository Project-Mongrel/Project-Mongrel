import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.bot.handlers.scan import _send_specialist_ai_assessment, scan_callback_handler
from app.bot.keyboards.tool_mode_actions import TOOL_MODE_TOOLS, build_tool_mode_post_scan_keyboard


EXPECTED_TOOLS = (
    "nmap", "bbot", "nuclei", "httpx", "playwright", "katana", "ffuf", "testssl",
    "gitleaks", "prowler", "metasploit", "tshark",
)


@pytest.mark.parametrize("tool", EXPECTED_TOOLS)
def test_all_twelve_tools_share_the_same_terminal_action_keyboard(tool: str) -> None:
    keyboard = build_tool_mode_post_scan_keyboard(tool)
    buttons = [(row[0].text, row[0].callback_data) for row in keyboard.inline_keyboard]

    assert buttons == [
        ("🔄 Run Again", f"scan:{tool}"),
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
        asyncio.run(scan_callback_handler(update, context))

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

    assert run_again.callback_data == "scan:metasploit"
    assert "approve" not in run_again.callback_data
    assert "execute" not in run_again.callback_data
