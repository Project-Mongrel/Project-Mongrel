import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import AsyncContextManager

from fastapi import FastAPI

from app.core.config import Settings

logger = logging.getLogger(__name__)


def create_lifespan(settings: Settings) -> Callable[[FastAPI], AsyncContextManager[None]]:
    """Build the application lifespan handler with startup and shutdown hooks."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = settings
        logger.info(
            "Starting %s version %s in %s mode",
            settings.app_name,
            settings.app_version,
            settings.app_env,
        )
        logger.info("Telegram integration configured: %s", bool(settings.telegram_bot_token))

        yield

        logger.info("Shutting down %s", settings.app_name)

    return lifespan
