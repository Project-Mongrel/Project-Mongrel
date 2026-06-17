from app.core.config import Settings


def is_admin(user_id: int | None, settings: Settings) -> bool:
    """Return whether the Telegram user is configured as the app admin."""

    return user_id is not None and settings.admin_user_id is not None and user_id == settings.admin_user_id
