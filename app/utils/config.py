from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = Field(default="Automated WAF", alias="WAF_APP_NAME")
    environment: str = Field(default="development", alias="WAF_ENV")
    upstream_url: str = Field(default="http://127.0.0.1:8001", alias="WAF_UPSTREAM_URL")
    database_url: str = Field(default="sqlite:///./data/waf.db", alias="WAF_DATABASE_URL")
    log_level: str = Field(default="INFO", alias="WAF_LOG_LEVEL")
    block_threshold: int = Field(default=70, alias="WAF_BLOCK_THRESHOLD")
    temp_block_seconds: int = Field(default=900, alias="WAF_TEMP_BLOCK_SECONDS")
    offender_warning_threshold: int = Field(default=2, alias="WAF_OFFENDER_WARNING_THRESHOLD")
    offender_temp_block_threshold: int = Field(default=3, alias="WAF_OFFENDER_TEMP_BLOCK_THRESHOLD")
    offender_permanent_block_threshold: int = Field(default=5, alias="WAF_OFFENDER_PERMANENT_BLOCK_THRESHOLD")
    rate_limit_requests: int = Field(default=60, alias="WAF_RATE_LIMIT_REQUESTS")
    rate_limit_window_seconds: int = Field(default=60, alias="WAF_RATE_LIMIT_WINDOW_SECONDS")
    user_agent_blocklist: str = Field(default="sqlmap,nikto,acunetix,netsparker", alias="WAF_USER_AGENT_BLOCKLIST")
    max_body_bytes: int = Field(default=65536, alias="WAF_MAX_BODY_BYTES")
    protected_host: str = Field(default="protected.local", alias="WAF_PROTECTED_HOST")
    enable_iptables: bool = Field(default=False, alias="WAF_ENABLE_IPTABLES")
    enable_nftables: bool = Field(default=False, alias="WAF_ENABLE_NFTABLES")
    proxy_timeout_seconds: float = Field(default=30.0, alias="WAF_PROXY_TIMEOUT_SECONDS")
    bind_host: str = Field(default="0.0.0.0", alias="WAF_BIND_HOST")
    bind_port: int = Field(default=8080, alias="WAF_BIND_PORT")

    @field_validator("user_agent_blocklist", mode="before")
    @classmethod
    def normalize_blocklist(cls, value: str | list[str]) -> str:
        if isinstance(value, list):
            return ",".join(value)
        return value

    @property
    def blocklist_items(self) -> list[str]:
        return [item.strip().lower() for item in self.user_agent_blocklist.split(",") if item.strip()]

    @property
    def allowed_proxy_schemes(self) -> tuple[Literal["http"], Literal["https"]]:
        return ("http", "https")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
