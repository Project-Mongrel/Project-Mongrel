from fastapi import FastAPI

from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.lifecycle import create_lifespan
from app.core.logging import configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.log_level)

    app = FastAPI(
        title=resolved_settings.app_name,
        description=resolved_settings.app_description,
        version=resolved_settings.app_version,
        lifespan=create_lifespan(resolved_settings),
    )
    app.include_router(api_router, prefix=resolved_settings.api_prefix)

    return app


app = create_app()
