_ai_waiting_users: set[int] = set()


def set_ai_waiting(user_id: int) -> None:
    _ai_waiting_users.add(user_id)


def is_ai_waiting(user_id: int) -> bool:
    return user_id in _ai_waiting_users


def clear_ai_waiting(user_id: int) -> None:
    _ai_waiting_users.discard(user_id)
