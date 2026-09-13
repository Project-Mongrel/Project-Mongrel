_ai_waiting_users: set[int] = set()
_ai_conversation_history: dict[int, list[tuple[str, str]]] = {}
_finding_analysis_contexts: dict[int, dict] = {}

_AI_HISTORY_MESSAGE_LIMIT = 8


def set_ai_waiting(user_id: int) -> None:
    _ai_waiting_users.add(user_id)


def is_ai_waiting(user_id: int) -> bool:
    return user_id in _ai_waiting_users


def clear_ai_waiting(user_id: int) -> None:
    _ai_waiting_users.discard(user_id)
    _ai_conversation_history.pop(user_id, None)


def get_ai_conversation_history(user_id: int) -> tuple[tuple[str, str], ...]:
    return tuple(_ai_conversation_history.get(user_id, ()))


def append_ai_conversation_exchange(user_id: int, question: str, answer: str) -> None:
    history = _ai_conversation_history.setdefault(user_id, [])
    history.extend((("user", question), ("assistant", answer)))
    del history[:-_AI_HISTORY_MESSAGE_LIMIT]


def set_finding_analysis_context(user_id: int, context: dict) -> None:
    _finding_analysis_contexts[user_id] = dict(context)


def get_finding_analysis_context(user_id: int) -> dict | None:
    return _finding_analysis_contexts.get(user_id)


def is_finding_analysis_active(user_id: int) -> bool:
    return user_id in _finding_analysis_contexts


def clear_finding_analysis_context(user_id: int) -> None:
    _finding_analysis_contexts.pop(user_id, None)
