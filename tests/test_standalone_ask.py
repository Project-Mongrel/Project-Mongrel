import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.bot.handlers.ask import ask_handler
from app.bot.handlers.scan import scan_target_handler
from app.services.chat_state import append_ai_conversation_exchange, clear_ai_waiting, get_ai_conversation_history
from app.services.mongrel_self_knowledge import get_mongrel_tool_names
from app.services.conversation_understanding import extract_technical_tokens, normalize_conversational_text, understand_conversation
from app.services.standalone_ask import answer_standalone_product_question, build_standalone_ask_prompt


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


def test_standalone_ask_first_step_questions_stay_within_mongrel_capabilities() -> None:
    for question in ("what should we do first?", "what tool should we use first?", "what tool first?", "where should I start?"):
        answer = _answer(question).lower()
        assert "nmap" in answer and "httpx" in answer
        assert not any(tool in answer for tool in ("openvas", "qualys", "rapid7"))


def test_standalone_ask_followup_first_step_question_uses_bounded_context() -> None:
    history = (("user", "what should we do first?"), ("assistant", _answer("what should we do first?")))
    answer = _answer("elaborate. what tool first?", history).lower()

    assert answer.startswith("start with bbot")
    assert "nmap" in answer and "httpx" in answer
    assert "openvas" not in answer and "qualys" not in answer and "rapid7" not in answer


@pytest.mark.parametrize(
    ("question", "marker"),
    (
        ("which one first?", "Start with BBOT"),
        ("why that one?", "BBOT is the referenced step"),
        ("what does that do?", "BBOT is the referenced step"),
        ("what about the second one?", "Nmap is the referenced step"),
        ("and after that?", "Nmap is the referenced step"),
    ),
)
def test_standalone_followups_answer_the_narrow_reference(question: str, marker: str) -> None:
    history = (("user", "what should we do first?"), ("assistant", _answer("what should we do first?")))

    answer = _answer(question, history)

    assert marker in answer
    assert answer != history[-1][1]


def test_standalone_multi_turn_followups_advance_the_selected_tool() -> None:
    history = [("user", "what should we do first"), ("assistant", _answer("what should we do first"))]

    first = _answer("elobarate. what tool first?", history)
    history.extend([("user", "elobarate. what tool first?"), ("assistant", first)])
    why = _answer("why that one?", history)
    assert why.startswith("BBOT is the referenced step")

    history.extend([("user", "why that one?"), ("assistant", why)])
    second = _answer("what about the secind one?", history)
    assert second.startswith("Nmap is the referenced step")

    history.extend([("user", "what about the secind one?"), ("assistant", second)])
    after = _answer("and after that one?", history)
    assert after.startswith("httpx is the referenced step")


def test_standalone_normalization_handles_casual_noise_without_rewriting_technical_tokens() -> None:
    assert normalize_conversational_text("what the fuck should we do nxt?") == "what should we do next?"
    understanding = understand_conversation("can Mongrel run openVPS?", ())
    assert understanding.original_text == "can Mongrel run openVPS?"
    assert "openvps" in understanding.normalized_text


def test_standalone_unknown_technical_capability_is_not_silently_substituted() -> None:
    answer = _answer("can Mongrel run openVPS?")

    assert "openVPS" in answer
    assert "OpenVZ" not in answer
    assert "do not recognize" in answer


@pytest.mark.parametrize(
    ("question", "value"),
    (
        ("Can Mongrel run /etc/mongrel/config?", "/etc/mongrel/config"),
        ("Can Mongrel run port 8443?", "port 8443"),
        ("Can Mongrel run 192.0.2.10?", "192.0.2.10"),
        ("Can Mongrel run https://example.invalid/a?x=1?", "https://example.invalid/a?x=1"),
        ("Can Mongrel run CVE-2026-12345?", "CVE-2026-12345"),
    ),
)
def test_standalone_capability_preserves_opaque_technical_values(question: str, value: str) -> None:
    assert value in extract_technical_tokens(question)
    answer = _answer(question)
    assert value in answer
    assert "exactly 12 competition tools" not in answer


def test_standalone_capability_followup_preserves_unknown_product_uncertainty() -> None:
    history = [("user", "Can Mongrel run OpenVZ?"), ("assistant", _answer("Can Mongrel run OpenVZ?"))]
    answer = _answer("So OpenVZ is supported, right?", history)

    assert "OpenVZ" in answer
    assert "do not recognize" in answer
    assert "supported capabilities" in answer


def test_standalone_generic_prompt_is_bounded_and_has_no_assessment_context() -> None:
    prompt = build_standalone_ask_prompt(
        "How does SSRF work?",
        (("user", "What did the assessment find?"), ("assistant", "No assessment evidence is available here.")),
    )

    assert len(prompt) <= 9000
    assert "Standalone Ask Mongrel context:" in prompt
    assert "What did the assessment find?" in prompt
    assert "no assessment findings" in prompt.lower()
    assert "assessment_map" not in prompt.lower()
    assert "finding_id" not in prompt.lower()


def test_standalone_comparison_prompt_preserves_bounded_tool_truthfulness() -> None:
    prompt = build_standalone_ask_prompt("Actually compare Nmap and BBOT")

    prompt_lower = prompt.lower()
    assert "never call reconnaissance comprehensive or complete" in prompt_lower
    assert "does not establish ownership, reachability, vulnerability, or complete attack-surface coverage" in prompt_lower
    assert "does not establish application behavior, vulnerability" in prompt_lower


def test_standalone_external_tool_question_remains_general_knowledge_fallback() -> None:
    assert answer_standalone_product_question("How does OpenVAS work?", ()) is None


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
        asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=user_id), effective_chat=SimpleNamespace(id=user_id)), context))

    ask_ai.assert_called_once()
    assert ask_ai.call_args.kwargs == {"path": "generic_ask"}
    assert "How does SSRF work?" in ask_ai.call_args.args[0]
    assert "general cybersecurity and educational questions" in ask_ai.call_args.args[0]
    assert message.reply_text.call_args_list[-1].args[0] == "Grounded SSRF explanation"
    clear_ai_waiting(user_id)


def test_standalone_ask_external_tool_question_reaches_general_ai_without_claiming_support() -> None:
    user_id = 81203
    clear_ai_waiting(user_id)
    context = SimpleNamespace(user_data={})
    asyncio.run(
        ask_handler(
            SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()), effective_user=SimpleNamespace(id=user_id)),
            context,
        )
    )
    message = SimpleNamespace(text="How does OpenVAS work?", reply_text=AsyncMock())

    async def run_inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    with (
        patch("app.bot.handlers.scan.ask_ai", return_value="General OpenVAS explanation") as ask_ai,
        patch("app.bot.handlers.scan.asyncio.to_thread", side_effect=run_inline),
    ):
        asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=user_id), effective_chat=SimpleNamespace(id=user_id)), context))

    ask_ai.assert_called_once()
    prompt = ask_ai.call_args.args[0]
    assert "How does OpenVAS work?" in prompt
    assert "do not claim Mongrel supports it" in prompt
    assert message.reply_text.call_args_list[-1].args[0] == "General OpenVAS explanation"
    clear_ai_waiting(user_id)


def test_standalone_ask_typing_failure_does_not_block_persistence_or_delivery() -> None:
    user_id = 81204
    clear_ai_waiting(user_id)
    context = SimpleNamespace(user_data={}, bot=SimpleNamespace(send_chat_action=AsyncMock(side_effect=RuntimeError("unavailable"))))
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
        patch("app.bot.handlers.scan.ask_ai", return_value="Stored general answer"),
        patch("app.bot.handlers.scan.asyncio.to_thread", side_effect=run_inline),
    ):
        asyncio.run(scan_target_handler(SimpleNamespace(message=message, effective_user=SimpleNamespace(id=user_id)), context))

    assert message.reply_text.call_args_list[-1].args[0] == "Stored general answer"
    assert get_ai_conversation_history(user_id)[-2:] == (("user", "How does SSRF work?"), ("assistant", "Stored general answer"))
    clear_ai_waiting(user_id)
