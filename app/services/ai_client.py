import logging
import inspect
from time import perf_counter
from typing import Callable

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


def ask_ai(
    prompt: str,
    num_predict: int | None = None,
    *,
    path: str | None = None,
    telemetry_sink: Callable[[dict], None] | None = None,
) -> str:
    settings = get_settings()
    if not settings.ai_enabled:
        return "AI integration is not configured yet."

    if settings.ai_provider.lower() != "ollama":
        return "Unsupported AI provider."

    if not settings.ollama_base_url:
        return "Ollama base URL is not configured."

    kwargs = {"path": path, "telemetry_sink": telemetry_sink} if path or telemetry_sink else {}
    if num_predict is None:
        return ask_ollama(prompt, **kwargs)
    return ask_ollama(prompt, num_predict=num_predict, **kwargs)


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


def ask_ollama(
    user_question: str,
    num_predict: int | None = None,
    *,
    path: str | None = None,
    telemetry_sink: Callable[[dict], None] | None = None,
) -> str:
    settings = get_settings()
    prediction_budget = int(num_predict) if num_predict is not None else 256
    latency_path = path or _infer_latency_path()
    request_started = perf_counter()
    try:
        response = httpx.post(
            f"{settings.ollama_base_url.rstrip('/')}/api/chat",
            json={
                "model": settings.ollama_model,
                "messages": build_ollama_messages(user_question),
                "stream": False,
                "options": {
                    "num_predict": prediction_budget,
                    "temperature": 0.2,
                    "think": False,
                },
            },
            timeout=settings.ai_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        _record_latency({}, latency_path, settings.ollama_model, request_started, "timeout", telemetry_sink)
        return "AI request timed out."
    except httpx.ConnectError:
        _record_latency({}, latency_path, settings.ollama_model, request_started, "connect_error", telemetry_sink)
        return "Unable to connect to Ollama server."
    except httpx.HTTPError:
        _record_latency({}, latency_path, settings.ollama_model, request_started, "http_error", telemetry_sink)
        return "AI request failed."
    except (ValueError, TypeError):
        _record_latency({}, latency_path, settings.ollama_model, request_started, "malformed_response", telemetry_sink)
        return "Malformed Ollama response."

    if not isinstance(payload, dict):
        _record_latency({}, latency_path, settings.ollama_model, request_started, "malformed_payload", telemetry_sink)
        return "Malformed Ollama response."

    _log_ollama_response_metadata(payload)
    _record_latency(payload, latency_path, settings.ollama_model, request_started, "ok", telemetry_sink)

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


def parse_ollama_latency(payload: dict, *, path: str, model: str, ollama_ms: float, status: str = "ok") -> dict:
    """Extract non-sensitive timing/token metadata from an Ollama response."""
    eval_count = _optional_int(payload.get("eval_count"))
    eval_duration_ns = _optional_int(payload.get("eval_duration"))
    tokens_per_second = None
    if eval_count is not None and eval_duration_ns and eval_duration_ns > 0:
        tokens_per_second = round(eval_count / (eval_duration_ns / 1_000_000_000), 3)
    return {
        "path": path,
        "model": str(payload.get("model") or model),
        "status": status,
        "ollama_ms": round(ollama_ms, 3),
        "total_ms": _ns_to_ms(payload.get("total_duration")),
        "load_ms": _ns_to_ms(payload.get("load_duration")),
        "prompt_eval_ms": _ns_to_ms(payload.get("prompt_eval_duration")),
        "eval_ms": _ns_to_ms(payload.get("eval_duration")),
        "prompt_tokens": _optional_int(payload.get("prompt_eval_count")),
        "output_tokens": eval_count,
        "tokens_per_second": tokens_per_second,
    }


def _record_latency(
    payload: dict,
    path: str,
    model: str,
    request_started: float,
    status: str,
    telemetry_sink: Callable[[dict], None] | None,
) -> None:
    telemetry = parse_ollama_latency(
        payload,
        path=path,
        model=model,
        ollama_ms=(perf_counter() - request_started) * 1000,
        status=status,
    )
    logger.info(
        "AI latency path=%s model=%s status=%s ollama_ms=%s total_ms=%s load_ms=%s "
        "prompt_eval_ms=%s eval_ms=%s prompt_tokens=%s output_tokens=%s tokens_per_second=%s",
        telemetry["path"], telemetry["model"], telemetry["status"], telemetry["ollama_ms"],
        telemetry["total_ms"], telemetry["load_ms"], telemetry["prompt_eval_ms"], telemetry["eval_ms"],
        telemetry["prompt_tokens"], telemetry["output_tokens"], telemetry["tokens_per_second"],
    )
    if telemetry_sink is not None:
        telemetry_sink(dict(telemetry))


def _infer_latency_path() -> str:
    for frame in inspect.stack()[2:10]:
        module = str(frame.frame.f_globals.get("__name__") or "")
        if module == __name__:
            continue
        short_module = module.removeprefix("app.").replace(".", "_")
        return f"{short_module}.{frame.function}" if short_module else frame.function
    return "unknown"


def _optional_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _ns_to_ms(value: object) -> float | None:
    nanoseconds = _optional_int(value)
    return round(nanoseconds / 1_000_000, 3) if nanoseconds is not None else None


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
