_ai_waiting_users: set[int] = set()
_finding_analysis_contexts: dict[int, dict] = {}


def set_ai_waiting(user_id: int) -> None:
    _ai_waiting_users.add(user_id)


def is_ai_waiting(user_id: int) -> bool:
    return user_id in _ai_waiting_users


def clear_ai_waiting(user_id: int) -> None:
    _ai_waiting_users.discard(user_id)


def set_finding_analysis_context(user_id: int, context: dict) -> None:
    _finding_analysis_contexts[user_id] = dict(context)


def get_finding_analysis_context(user_id: int) -> dict | None:
    return _finding_analysis_contexts.get(user_id)


def is_finding_analysis_active(user_id: int) -> bool:
    return user_id in _finding_analysis_contexts


def clear_finding_analysis_context(user_id: int) -> None:
    _finding_analysis_contexts.pop(user_id, None)
