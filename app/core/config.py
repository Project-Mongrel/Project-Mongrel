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
    bbot_binary: str = "bbot"
    bbot_scan_timeout_seconds: int = 600
    bbot_presets: str = "subdomain-enum"
    bbot_modules: str = ""
    bbot_require_flags: str = "passive"
    bbot_exclude_flags: str = ""
    bbot_scope_search_distance: int = 0
    bbot_scope_report_distance: int = 0
    bbot_dns_threads: int = 10
    bbot_dns_brute_threads: int = 100
    bbot_dns_timeout_seconds: int = 5
    bbot_dns_retries: int = 1
    bbot_web_http_timeout_seconds: int = 10
    bbot_web_http_retries: int = 1
    bbot_web_spider_distance: int = 0
    bbot_web_spider_depth: int = 1
    bbot_web_spider_links_per_page: int = 10
    bbot_max_output_bytes: int = 2_000_000
    bbot_max_json_files: int = 25
    nuclei_path: str = "nuclei"
    nuclei_scan_timeout_seconds: int = 600
    nuclei_tags: str = "exposure,misconfig,tech,panel,headers"
    nuclei_exclude_tags: str = "dos,fuzz,bruteforce,intrusive"
    nuclei_severities: str = "info,low,medium,high,critical"
    nuclei_exclude_severities: str = ""
    nuclei_protocol_types: str = "http,ssl,dns,tcp,whois"
    nuclei_template_paths: str = ""
    nuclei_template_profile: str = ""
    nuclei_template_ids: str = ""
    nuclei_exclude_template_ids: str = ""
    nuclei_rate_limit: int = 25
    nuclei_concurrency: int = 10
    nuclei_bulk_size: int = 10
    nuclei_request_timeout: int = 5
    nuclei_retries: int = 1
    nuclei_max_redirects: int = 3
    nuclei_response_size_read: int = 1_048_576
    nuclei_max_output_bytes: int = 2_000_000
    httpx_path: str = "httpx"
    httpx_scan_timeout_seconds: int = 120
    httpx_request_timeout_seconds: int = 10
    httpx_retries: int = 1
    httpx_threads: int = 25
    httpx_rate_limit: int = 100
    httpx_ports: str = "http:80,8080,8000,8888,https:443,8443"
    httpx_max_redirects: int = 3
    httpx_max_response_size_bytes: int = 1_000_000
    katana_path: str = "katana"
    katana_scan_timeout_seconds: int = 180
    katana_crawl_depth: int = 3
    katana_concurrency: int = 10
    katana_rate_limit: int = 50
    katana_crawl_duration_seconds: int = 120
    katana_max_response_size_bytes: int = 4_194_304
    katana_field_scope: str = "fqdn"
    katana_known_files: str = "robotstxt,sitemapxml"
    katana_js_crawl: bool = True
    katana_form_extraction: bool = True
    playwright_scan_timeout_seconds: int = 45
    playwright_max_links: int = 25
    playwright_max_forms: int = 10
    playwright_max_inputs: int = 25
    playwright_max_console_messages: int = 10
    playwright_max_network_events: int = 25
    playwright_max_response_size_bytes: int = 1_000_000
    playwright_capture_screenshot_metadata: bool = True
    ffuf_path: str = "ffuf"
    ffuf_scan_timeout_seconds: int = 120
    ffuf_wordlist_path: Path = Path("app/resources/wordlists/ffuf_default.txt")
    ffuf_threads: int = 5
    ffuf_rate_limit: int = 25
    ffuf_extensions: str = ""
    testssl_path: str = "testssl.sh"
    testssl_scan_timeout_seconds: int = 180
    testssl_connect_timeout_seconds: int = 10
    testssl_openssl_timeout_seconds: int = 5
    testssl_ip_mode: str = ""
    testssl_starttls_protocol: str = ""
    testssl_ids_friendly: bool = False
    testssl_max_output_bytes: int = 500_000
    testssl_max_json_bytes: int = 2_000_000
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
    tshark_live_interface_allowlist: str = ""
    tshark_live_max_duration_seconds: int = 30
    tshark_live_max_packet_count: int = 500
    tshark_live_max_file_size_kb: int = 4096


@lru_cache
def get_settings() -> Settings:
    return Settings()
