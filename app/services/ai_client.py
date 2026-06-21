import logging

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

MONGREL_IDENTITY_PROMPT = (
    "You are Project Mongrel.\n\n"
    "Project Mongrel is a Telegram-first AI security assistant that helps analyze findings, prioritize risks, "
    "and support authorized defensive security operations.\n\n"
    "Your primary expertise includes:\n"
    "- Vulnerability analysis\n"
    "- Risk prioritization\n"
    "- Security findings review\n"
    "- Security reporting\n"
    "- Remediation planning\n"
    "- Security operations support\n\n"
    "You may also answer general technical and educational questions when helpful.\n\n"
    "When a question relates to cybersecurity, provide practical, accurate, and defensive guidance appropriate "
    "for authorized environments.\n\n"
    "Be concise, professional, and direct.\n\n"
    "Always provide a final answer.\n"
    "Do not stop after internal reasoning.\n"
    "Put the user-facing answer in the final response.\n"
    "Do not use hidden reasoning.\n"
    "Do not output thinking.\n"
    "Reply directly with the final answer only.\n"
    "Keep it concise.\n\n"
    "Do not present yourself as a generic AI assistant.\n"
    "Do not claim to be the Ruby Mongrel web server.\n"
    "Do not use emojis unless explicitly requested."
)


def ask_ai(prompt: str) -> str:
    settings = get_settings()
    if not settings.ai_enabled:
        return "AI integration is not configured yet."

    if settings.ai_provider.lower() != "ollama":
        return "Unsupported AI provider."

    if not settings.ollama_base_url:
        return "Ollama base URL is not configured."

    return ask_ollama(prompt)


def build_mongrel_prompt(user_question: str) -> str:
    return f"{MONGREL_IDENTITY_PROMPT}\n\nUser question:\n{user_question}\n\nFinal answer:"


def build_ollama_messages(user_question: str) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": MONGREL_IDENTITY_PROMPT,
        },
        {
            "role": "user",
            "content": f"Reply with final answer only. Do not think silently. Question:\n{user_question}",
        },
    ]


def ask_ollama(user_question: str) -> str:
    settings = get_settings()
    try:
        response = httpx.post(
            f"{settings.ollama_base_url.rstrip('/')}/api/chat",
            json={
                "model": settings.ollama_model,
                "messages": build_ollama_messages(user_question),
                "stream": False,
                "options": {
                    "num_predict": 256,
                    "temperature": 0.2,
                    "think": False,
                },
            },
            timeout=settings.ai_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return "AI request timed out."
    except httpx.ConnectError:
        return "Unable to connect to Ollama server."
    except httpx.HTTPError:
        return "AI request failed."
    except (ValueError, TypeError):
        return "Malformed Ollama response."

    if not isinstance(payload, dict):
        return "Malformed Ollama response."

    _log_ollama_response_metadata(payload)

    message = payload.get("message")
    if not isinstance(message, dict):
        return "Malformed Ollama response."

    answer = message.get("content")
    if not isinstance(answer, str):
        return "Malformed Ollama response."

    answer = answer.strip()
    if not answer:
        thinking = _get_ollama_thinking(payload)
        if isinstance(thinking, str) and thinking.strip():
            return "Mongrel generated internal reasoning but no final answer. Try rephrasing the question."

        return "Empty AI response."

    return answer


def _log_ollama_response_metadata(payload: dict) -> None:
    message = payload.get("message")
    message_content = message.get("content") if isinstance(message, dict) else None
    message_content_length = len(message_content) if isinstance(message_content, str) else 0
    message_keys = sorted(str(key) for key in message.keys()) if isinstance(message, dict) else []
    thinking_text = _get_ollama_thinking(payload)
    thinking_exists = isinstance(thinking_text, str)
    thinking_length = len(thinking_text) if isinstance(thinking_text, str) else 0

    logger.info(
        "Ollama response metadata: keys=%s message_keys=%s message_content_len=%s thinking_len=%s done=%s model=%s thinking_exists=%s",
        sorted(str(key) for key in payload.keys()),
        message_keys,
        message_content_length,
        thinking_length,
        payload.get("done"),
        payload.get("model"),
        thinking_exists,
    )
    response_is_empty = not message_content.strip() if isinstance(message_content, str) else True
    thinking_has_content = bool(thinking_text.strip()) if isinstance(thinking_text, str) else False
    if response_is_empty and thinking_has_content:
        logger.warning("Ollama returned thinking but empty response")


def _get_ollama_thinking(payload: dict) -> object:
    if "thinking" in payload:
        return payload.get("thinking")

    message = payload.get("message")
    if isinstance(message, dict):
        return message.get("thinking")

    return None
