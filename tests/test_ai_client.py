from types import SimpleNamespace
from unittest.mock import patch

import httpx

from app.core.config import Settings
from app.services.ai_client import ask_ai, ask_ollama


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


def test_ollama_empty_response_handled() -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example")
    response = SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"response": "  "})

    with (
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", return_value=response),
    ):
        assert ask_ollama("What should I check?") == "Empty AI response."


def test_ollama_success_returns_response_text() -> None:
    settings = Settings(ai_enabled=True, ollama_base_url="https://ollama.example", ollama_model="qwen3:4b")
    response = SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"response": "  Review SSH exposure.  "})

    with (
        patch("app.services.ai_client.get_settings", return_value=settings),
        patch("app.services.ai_client.httpx.post", return_value=response) as post,
    ):
        assert ask_ollama("What should I check?") == "Review SSH exposure."

    post.assert_called_once_with(
        "https://ollama.example/api/generate",
        json={"model": "qwen3:4b", "prompt": "What should I check?", "stream": False},
        timeout=60,
    )
