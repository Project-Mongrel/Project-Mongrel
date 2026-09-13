import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.bot.handlers.ask import ask_handler
from app.bot.handlers.scan import scan_target_handler
from app.services.chat_state import append_ai_conversation_exchange, clear_ai_waiting, get_ai_conversation_history
from app.services.mongrel_self_knowledge import get_mongrel_tool_names
from app.services.standalone_ask import answer_standalone_product_question


FORBIDDEN_EXTERNAL_TOOLS = (
    "nikto",
    "nessus",
    "openvas",
    "wireshark",
    "snort",
    "openssl",
    "certbot",
)


def _answer(question: str, history: tuple[tuple[str, str], ...] = ()) -> str:
    answer = answer_standalone_product_question(question, history)
    assert answer is not None
    return answer


def test_standalone_ask_enumerates_exact_competition_tools() -> None:
    answer = _answer("What tools do you have?")

    for tool in get_mongrel_tool_names():
        assert tool in answer
    assert len(get_mongrel_tool_names()) == 12
    assert not any(tool in answer.lower() for tool in FORBIDDEN_EXTERNAL_TOOLS)


def test_standalone_ask_describes_ffuf_as_web_fuzzing() -> None:
    answer = _answer("What does ffuf do?").lower()

    assert "fuzz" in answer
    assert "fuzz" in answer or "path" in answer
    assert "path" in answer and "parameter" in answer and "hostname" in answer
    assert "open port" not in answer
    assert "service version" not in answer


def test_standalone_ask_selects_testssl_for_tls() -> None:
    answer = _answer("Which Mongrel tool checks TLS?")

    assert "testssl.sh" in answer
    assert "OpenSSL" not in answer


def test_standalone_ask_tls_followup_retains_referent() -> None:
    history = (("user", "Which Mongrel tool checks TLS?"), ("assistant", "Use testssl.sh."))

    answer = _answer("But which tool do I use?", history)

    assert "testssl.sh" in answer


def test_standalone_ask_tls_tools_distinguish_tshark() -> None:
    answer = _answer("Which Mongrel tools should I use for TLS?")

    assert "testssl.sh" in answer
    assert "TShark" in answer
    assert "does not replace" in answer
    assert not any(tool in answer.lower() for tool in FORBIDDEN_EXTERNAL_TOOLS)


def test_standalone_ask_gives_mongrel_aware_web_assessment_order() -> None:
    answer = _answer("What order would you assess a web target?")

    assert answer.index("Nmap") < answer.index("httpx")
    assert "Katana" in answer
    assert "ffuf" in answer
    assert "Nuclei" in answer
    assert "testssl.sh" in answer
    assert "explicit" in answer.lower() and "approval" in answer.lower()
    assert "not every" in answer.lower()


def test_standalone_ask_investigation_uses_only_relevant_mongrel_tools() -> None:
    history = (("user", "Mongrel found exposed services. What should I inspect?"),)

    answer = _answer("Which tools could help investigate this?", history)

    for tool in ("Nmap", "httpx", "Nuclei", "Katana", "ffuf", "testssl.sh", "TShark", "Metasploit"):
        assert tool in answer
    assert not any(tool in answer.lower() for tool in FORBIDDEN_EXTERNAL_TOOLS)


def test_standalone_ask_leaves_general_ssrf_question_to_general_ai() -> None:
    assert answer_standalone_product_question("How does SSRF work?", ()) is None


def test_standalone_ask_history_is_bounded_and_cleared_with_session() -> None:
    user_id = 81200
    clear_ai_waiting(user_id)
    for index in range(6):
        append_ai_conversation_exchange(user_id, f"question {index}", f"answer {index}")

    history = get_ai_conversation_history(user_id)
    assert len(history) == 8
    assert history[0] == ("user", "question 2")

    clear_ai_waiting(user_id)
    assert get_ai_conversation_history(user_id) == ()


def test_standalone_ask_telegram_session_retains_tls_followup() -> None:
    user_id = 81201
    clear_ai_waiting(user_id)
    context = SimpleNamespace(user_data={})
    asyncio.run(
        ask_handler(
            SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()), effective_user=SimpleNamespace(id=user_id)),
            context,
        )
    )

    first = SimpleNamespace(text="Which Mongrel tool checks TLS?", reply_text=AsyncMock())
    followup = SimpleNamespace(text="But which tool do I use?", reply_text=AsyncMock())
    with patch("app.bot.handlers.scan.ask_ai") as ask_ai:
        asyncio.run(scan_target_handler(SimpleNamespace(message=first, effective_user=SimpleNamespace(id=user_id)), context))
        asyncio.run(scan_target_handler(SimpleNamespace(message=followup, effective_user=SimpleNamespace(id=user_id)), context))

    ask_ai.assert_not_called()
    assert "testssl.sh" in first.reply_text.call_args_list[-1].args[0]
    assert "testssl.sh" in followup.reply_text.call_args_list[-1].args[0]
    clear_ai_waiting(user_id)


def test_standalone_ask_telegram_keeps_general_security_knowledge_path() -> None:
    user_id = 81202
    clear_ai_waiting(user_id)
    context = SimpleNamespace(user_data={})
    asyncio.run(
        ask_handler(
            SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()), effective_user=SimpleNamespace(id=user_id)),
            context,
        )
    )
    message = SimpleNamespace(text="How does SSRF work?", reply_text=AsyncMock())

    async def run_inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    with (
        patch("app.bot.handlers.scan.ask_ai", return_value="Grounded SSRF explanation") as ask_ai,
        patch("app.bot.handlers.scan.asyncio.to_thread", side_effect=run_inline),
    ):
        asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=user_id)), context))

    ask_ai.assert_called_once_with("How does SSRF work?", path="generic_ask")
    assert message.reply_text.call_args_list[-1].args[0] == "Grounded SSRF explanation"
    clear_ai_waiting(user_id)
