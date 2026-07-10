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
    ai_enabled: bool = False
    ai_provider: str = "ollama"
    ollama_base_url: str = ""
    ollama_model: str = "qwen3:4b"
    ai_timeout_seconds: int = 60
    nuclei_path: str = "nuclei"
    nuclei_scan_timeout_seconds: int = 180
    nuclei_tags: str = "exposure,misconfig,tech,panel,headers"
    nuclei_rate_limit: int = 25
    nuclei_request_timeout: int = 5
    nuclei_retries: int = 1
    httpx_path: str = "httpx"
    httpx_scan_timeout_seconds: int = 120
    katana_path: str = "katana"
    katana_scan_timeout_seconds: int = 180
    katana_crawl_depth: int = 2
    playwright_scan_timeout_seconds: int = 45
    ffuf_path: str = "ffuf"
    ffuf_scan_timeout_seconds: int = 120
    ffuf_wordlist_path: Path = Path("app/resources/wordlists/ffuf_default.txt")
    ffuf_threads: int = 5
    ffuf_rate_limit: int = 25
    testssl_path: str = "testssl.sh"
    testssl_scan_timeout_seconds: int = 180
    gitleaks_path: str = "gitleaks"
    gitleaks_scan_timeout_seconds: int = 120
    evidence_vault_path: Path = Path("data/evidence_vault.db")
    evidence_vault_key: str | None = None
    evidence_reveal_ttl_seconds: int = 60
    prowler_enabled: bool = False
    prowler_binary: str = "prowler"
    prowler_timeout_seconds: int = 900
    # Set METASPLOIT_BINARY to the absolute msfconsole path on VPS installs when it is not on PATH.
    metasploit_binary: str = "msfconsole"
    metasploit_timeout_seconds: int = 300
    tshark_binary: str = "tshark"
    tshark_timeout_seconds: int = 120
    tshark_max_output_bytes: int = 2_000_000
    tshark_max_packets_normalized: int = 5000
    tshark_max_unique_endpoints: int = 500
    tshark_max_conversations: int = 1000
    tshark_max_dns_observations: int = 500
    tshark_max_http_observations: int = 500
    tshark_max_tls_observations: int = 500


@lru_cache
def get_settings() -> Settings:
    return Settings()
