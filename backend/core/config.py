"""Aithyrex application configuration loaded from environment variables."""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

    APP_ENV: str = "development"
    APP_SECRET_KEY: str = "change-me"
    LOG_LEVEL: str = "INFO"
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]
    ALLOWED_HOSTS: List[str] = ["*"]

    # Explicit opt-in only for isolated local development. Never enable in production.
    ALLOW_INSECURE_DEV_AUTH: bool = False

    THREATFADE_API_URL: str = "http://localhost:8000"
    THREATFADE_API_KEY: str = ""

    ANTHROPIC_API_KEY: str = ""
    GROK_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    DATABASE_URL: str = "postgresql+asyncpg://aishield:password@localhost:5432/aishield"
    REDIS_URL: str = "redis://localhost:6379/0"

    CLERK_SECRET_KEY: str = ""
    CLERK_JWT_KEY: str = ""
    CLERK_JWT_ISSUER: str = ""
    CLERK_JWT_AUDIENCE: str = ""
    CLERK_AUTHORIZED_PARTIES: List[str] = []
    CLERK_PUBLISHABLE_KEY: str = ""
    CLERK_WEBHOOK_SECRET: str = ""

    # Platform-signed agent/action assertions; this service emits signals only.
    PLATFORM_ACTION_JWT_PUBLIC_KEY: str = ""
    PLATFORM_ACTION_JWT_ISSUER: str = ""
    PLATFORM_ACTION_JWT_AUDIENCE: str = ""

    LEMONSQUEEZY_API_KEY: str = ""
    LEMONSQUEEZY_STORE_ID: str = ""
    LEMONSQUEEZY_WEBHOOK_SECRET: str = ""
    LEMONSQUEEZY_STARTER_VARIANT_ID: str = ""
    LEMONSQUEEZY_PRO_VARIANT_ID: str = ""

    KALEVIOAI_API_URL: str = ""
    KALEVIOAI_API_KEY: str = ""
    RECONOS_API_URL: str = ""
    RECONOS_API_KEY: str = ""

    SPLUNK_HEC_URL: str = ""
    SPLUNK_HEC_TOKEN: str = ""

    SLACK_WEBHOOK_URL: str = ""
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""

    PADDLE_API_KEY: str = ""
    PADDLE_WEBHOOK_SECRET: str = ""
    PADDLE_SELLER_ID: str = ""
    PADDLE_PRO_PRICE_ID: str = ""
    PADDLE_ENTERPRISE_PRICE_ID: str = ""

    OUTBOX_WORKER_ENABLED: bool = False

    RATE_LIMIT_PER_MINUTE: int = 60
    FREE_TIER_MONTHLY_LIMIT: int = 500
    STARTER_TIER_MONTHLY_LIMIT: int = 25_000
    PRO_TIER_MONTHLY_LIMIT: int = 150_000


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
