import logging
from types import SimpleNamespace
from unittest.mock import patch

import httpx

from app.core.config import Settings
from app.services.ai_client import (
    ask_ai,
    ask_ollama,
    build_mongrel_prompt,
    build_ollama_messages,
    parse_ollama_latency,
)


def test_parse_ollama_latency_uses_native_nanosecond_telemetry() -> None:
    telemetry = parse_ollama_latency(
        {
            "model": "qwen2.5:3b",
            "total_duration": 12_000_000_000,
            "load_duration": 2_000_000_000,
            "prompt_eval_count": 300,
            "prompt_eval_duration": 3_000_000_000,
            "eval_count": 70,
            "eval_duration": 7_000_000_000,
        },
        path="assessment_ask",
        model="fallback-model",
        ollama_ms=12_250.5,
    )

    assert telemetry == {
        "path": "assessment_ask", "model": "qwen2.5:3b", "status": "ok",
        "ollama_ms": 12250.5, "total_ms": 12000.0, "load_ms": 2000.0,
        "prompt_eval_ms": 3000.0, "eval_ms": 7000.0, "prompt_tokens": 300,
        "output_tokens": 70, "tokens_per_second": 10.0,
    }


def test_parse_ollama_latency_tolerates_missing_telemetry() -> None:
    telemetry = parse_ollama_latency({}, path="generic_ask", model="qwen2.5:3b", ollama_ms=4.25)

    assert telemetry["ollama_ms"] == 4.25
    assert telemetry["load_ms"] is None
    assert telemetry["prompt_tokens"] is None
    assert telemetry["tokens_per_second"] is None


def test_ai_disabled_returns_fallback() -> None:
    with patch("app.services.ai_client.get_settings", return_value=Settings(ai_enabled=False)):
        assert ask_ai("What should I check?") == "AI integration is not configured yet."


def test_unsupported_provider_handled() -> None:
    settings = Settings(ai_enabled=True, ai_provider="openai", ollama_base_url="https://ollama.example")

    with patch("app.services.ai_client.get_settings", return_value=settings):
        assert ask_ai("What should I check?") == "Unsupported AI provider."


def test_missing_ollama_base_url_handled() -> None:
    settings = Settings(ai_enabled=True, ai_provider="ollama", ollama_base_url="")

    with patch("app.services.ai_client.get_settings", return_value=settings):
        assert ask_ai("What should I check?") == "Ollama base URL is not configured."


def test_ai_enabled_uses_ollama_client() -> None:
    settings = Settings(ai_enabled=True, ai_provider="ollama", ollama_base_url="https://ollama.example")

    with (
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.ask_ollama", return_value="Review SSH exposure.") as ask_ollama,
    ):
        assert ask_ai("What should I check?") == "Review SSH exposure."

    ask_ollama.assert_called_once_with("What should I check?")


def test_ollama_messages_include_system_and_user_content() -> None:
    messages = build_ollama_messages("What is Linux?")

    assert messages[0]["role"] == "system"
    assert (
        "Project Mongrel is a Telegram-first AI security assistant that helps analyze findings, "
        "prioritize risks, and support authorized defensive security operations."
    ) in messages[0]["content"]
    assert "Do not claim to be the Ruby Mongrel web server." in messages[0]["content"]
    assert "Do not use hidden reasoning." in messages[0]["content"]
    assert "Do not output thinking." in messages[0]["content"]
    assert "Reply directly with the final answer only." in messages[0]["content"]
    assert messages[1] == {
        "role": "user",
        "content": "Reply with final answer only. Do not think silently. Question:\nWhat is Linux?",
    }


def test_mongrel_prompt_includes_identity() -> None:
    prompt = build_mongrel_prompt("Explain Project Mongrel in one sentence.")

    assert "You are Project Mongrel." in prompt
    assert (
        "Project Mongrel is a Telegram-first AI security assistant that helps analyze findings, "
        "prioritize risks, and support authorized defensive security operations."
    ) in prompt
    assert "Vulnerability analysis" in prompt
    assert "Risk prioritization" in prompt


def test_mongrel_prompt_says_not_ruby_web_server() -> None:
    prompt = build_mongrel_prompt("Explain Project Mongrel in one sentence.")

    assert "Do not claim to be the Ruby Mongrel web server." in prompt


def test_mongrel_prompt_allows_general_technical_questions() -> None:
    prompt = build_mongrel_prompt("What is Linux?")

    assert "You may also answer general technical and educational questions when helpful." in prompt
    assert "Only assist with authorized" not in prompt
    assert "User question:\nWhat is Linux?" in prompt


def test_mongrel_prompt_sets_professional_no_emoji_style() -> None:
    prompt = build_mongrel_prompt("How do I prioritize Nmap findings?")

    assert "Be concise, professional, and direct." in prompt
    assert "Do not present yourself as a generic AI assistant." in prompt
    assert "Do not use emojis unless explicitly requested." in prompt


def test_mongrel_prompt_says_always_provide_final_answer() -> None:
    prompt = build_mongrel_prompt("What is Linux?")

    assert "Always provide a final answer." in prompt
    assert "Do not stop after internal reasoning." in prompt
    assert "Put the user-facing answer in the final response." in prompt
    assert "Do not use hidden reasoning." in prompt
    assert "Do not output thinking." in prompt
    assert "Reply directly with the final answer only." in prompt
    assert "Keep it concise." in prompt


def test_mongrel_prompt_includes_user_question_after_identity() -> None:
    prompt = build_mongrel_prompt("Explain Project Mongrel in one sentence.")

    assert prompt.index("Do not claim to be the Ruby Mongrel web server.") < prompt.index("User question:")
    assert "User question:\nExplain Project Mongrel in one sentence.\n\nFinal answer:" in prompt


def test_mongrel_prompt_ends_with_final_answer_marker() -> None:
    prompt = build_mongrel_prompt("Explain Project Mongrel in one sentence.")

    assert prompt.endswith("Final answer:")


def test_ollama_timeout_handled() -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example")

    with (
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", side_effect=httpx.TimeoutException("timeout")),
    ):
        assert ask_ollama("What should I check?") == "AI request timed out."


def test_ollama_connection_error_handled() -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example")

    with (
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", side_effect=httpx.ConnectError("connection failed")),
    ):
        assert ask_ollama("What should I check?") == "Unable to connect to Ollama server."


def test_ollama_malformed_response_handled() -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example")
    response = SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"unexpected": "value"})

    with (
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", return_value=response),
    ):
        assert ask_ollama("What should I check?") == "Malformed Ollama response."


def test_ollama_empty_response_handled(caplog) -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example")
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {
            "model": "qwen3:4b",
            "done": True,
            "thinking": "Internal reasoning that must not be sent to Telegram.",
            "message": {"role": "assistant", "content": ""},
        },
    )

    with (
        caplog.at_level(logging.INFO, logger="app.services.ai_client"),
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", return_value=response),
    ):
        assert (
            ask_ollama("What should I check?")
            == "Mongrel generated internal reasoning but no final answer. Try rephrasing the question."
        )

    assert "message_content_len=0" in caplog.text
    assert "thinking_len=53" in caplog.text
    assert "thinking_exists=True" in caplog.text
    assert "message_keys=['content', 'role']" in caplog.text
    assert "done=True" in caplog.text
    assert "model=qwen3:4b" in caplog.text
    assert "Ollama returned thinking but empty response" in caplog.text
    assert "Internal reasoning" not in caplog.text


def test_ollama_whitespace_only_response_is_empty(caplog) -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example")
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {"message": {"role": "assistant", "content": "  "}, "thinking": ""},
    )

    with (
        caplog.at_level(logging.INFO, logger="app.services.ai_client"),
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", return_value=response),
    ):
        assert ask_ollama("What should I check?") == "Empty AI response."

    assert "message_content_len=2" in caplog.text
    assert "thinking_len=0" in caplog.text
    assert "thinking_exists=True" in caplog.text
    assert "Ollama returned thinking but empty response" not in caplog.text


def test_ollama_whitespace_response_with_thinking_uses_clear_fallback(caplog) -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example")
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {"message": {"role": "assistant", "content": "  "}, "thinking": "Internal reasoning only."},
    )

    with (
        caplog.at_level(logging.INFO, logger="app.services.ai_client"),
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", return_value=response),
    ):
        assert (
            ask_ollama("What should I check?")
            == "Mongrel generated internal reasoning but no final answer. Try rephrasing the question."
        )

    assert "message_content_len=2" in caplog.text
    assert "thinking_len=24" in caplog.text
    assert "thinking_exists=True" in caplog.text
    assert "Ollama returned thinking but empty response" in caplog.text
    assert "Internal reasoning only." not in caplog.text


def test_ollama_success_returns_response_text() -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example", ollama_model="qwen3:4b")
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {"message": {"role": "assistant", "content": "  Review SSH exposure.  "}},
    )

    with (
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", return_value=response) as post,
    ):
        assert ask_ollama("What should I check?") == "Review SSH exposure."

    assert post.call_count == 1
    call_args, call_kwargs = post.call_args
    assert call_args[0] == "https://ollama.example/api/chat"
    payload = call_kwargs["json"]
    assert payload["model"] == "qwen3:4b"
    assert payload["messages"] == build_ollama_messages("What should I check?")
    assert payload["stream"] is False
    assert payload["options"]["num_predict"] == 256
    assert payload["options"]["temperature"] == 0.2
    assert payload["options"]["think"] is False


def test_ollama_latency_log_is_metadata_only_and_response_is_unchanged(caplog) -> None:
    secret_prompt = "Evidence token=super-secret-value"
    answer = "Bounded response containing private assessment prose."
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example", ollama_model="qwen2.5:3b")
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {
            "model": "qwen2.5:3b", "done": True,
            "total_duration": 5_000_000_000, "load_duration": 500_000_000,
            "prompt_eval_count": 120, "prompt_eval_duration": 1_500_000_000,
            "eval_count": 30, "eval_duration": 3_000_000_000,
            "message": {"role": "assistant", "content": answer},
        },
    )
    captured = []

    with (
        caplog.at_level(logging.INFO, logger="app.services.ai_client"),
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", return_value=response),
    ):
        actual = ask_ollama(secret_prompt, path="assessment_ask", telemetry_sink=captured.append)

    assert actual == answer
    assert captured[0]["load_ms"] == 500.0
    assert captured[0]["tokens_per_second"] == 10.0
    assert "AI latency path=assessment_ask model=qwen2.5:3b" in caplog.text
    assert "super-secret-value" not in caplog.text
    assert "private assessment prose" not in caplog.text


def test_ollama_optional_num_predict_overrides_default() -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example", ollama_model="qwen3:4b")
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {"message": {"role": "assistant", "content": "Assessment answer."}},
    )

    with (
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", return_value=response) as post,
    ):
        assert ask_ollama("Summarize the assessment.", num_predict=768) == "Assessment answer."

    assert post.call_args.kwargs["json"]["options"]["num_predict"] == 768


def test_qwen_response_parsing_ignores_thinking() -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example")
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {
            "thinking": "Internal reasoning that must not be sent to Telegram.",
            "message": {"role": "assistant", "content": "Only this answer should be returned."},
        },
    )

    with (
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", return_value=response),
    ):
        assert ask_ollama("What should I check?") == "Only this answer should be returned."
