import httpx

from app.core.config import get_settings


def ask_ai(prompt: str) -> str:
    settings = get_settings()
    if not settings.ai_enabled:
        return "AI integration is not configured yet."

    if settings.ai_provider.lower() != "ollama":
        return "Unsupported AI provider."

    if not settings.ollama_base_url:
        return "Ollama base URL is not configured."

    return ask_ollama(prompt)


def ask_ollama(prompt: str) -> str:
    settings = get_settings()
    try:
        response = httpx.post(
            f"{settings.ollama_base_url.rstrip('/')}/api/generate",
            json={
                "model": settings.ollama_model,
                "prompt": prompt,
                "stream": False,
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

    answer = payload.get("response")
    if not isinstance(answer, str):
        return "Malformed Ollama response."

    answer = answer.strip()
    if not answer:
        return "Empty AI response."

    return answer
