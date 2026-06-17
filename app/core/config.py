from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env files."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Project Mongrel"
    app_description: str = "Telegram-first AI security analyst."
    app_version: str = "0.1.0"
    app_env: str = "development"
    api_prefix: str = "/api/v1"
    log_level: str = "INFO"

    telegram_bot_token: str | None = None
    admin_user_id: int | None = None

    database_path: Path = Path("data/mongrel.db")
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3"


@lru_cache
def get_settings() -> Settings:
    return Settings()
