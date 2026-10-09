"""
AI Shield — Application Configuration
======================================
Pydantic settings loaded from environment variables.
Mirrors KalevioAI config pattern.
"""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Core ────────────────────────────────────────────────────────
    APP_ENV: str = "development"
    APP_SECRET_KEY: str = "change-me"
    LOG_LEVEL: str = "INFO"
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]
    ALLOWED_HOSTS: List[str] = ["*"]

    # ── ThreatFade Bridge ────────────────────────────────────────────
    THREATFADE_API_URL: str = "http://localhost:8000"
    THREATFADE_API_KEY: str = ""

    # ── LLM Providers ────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = ""
    GROK_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # ── Database ─────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://aishield:password@localhost:5432/aishield"
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── Auth ─────────────────────────────────────────────────────────
    CLERK_SECRET_KEY: str = ""
    CLERK_PUBLISHABLE_KEY: str = ""
    CLERK_WEBHOOK_SECRET: str = ""

    # ── Payments ─────────────────────────────────────────────────────
    LEMONSQUEEZY_API_KEY: str = ""
    LEMONSQUEEZY_STORE_ID: str = ""
    LEMONSQUEEZY_WEBHOOK_SECRET: str = ""
    LEMONSQUEEZY_STARTER_VARIANT_ID: str = ""
    LEMONSQUEEZY_PRO_VARIANT_ID: str = ""

    # ── Integrations ─────────────────────────────────────────────────
    KALEVIOAI_API_URL: str = ""
    KALEVIOAI_API_KEY: str = ""
    RECONOS_API_URL: str = ""
    RECONOS_API_KEY: str = ""

    # ── SIEM ─────────────────────────────────────────────────────────
    SPLUNK_HEC_URL: str = ""
    SPLUNK_HEC_TOKEN: str = ""

    # ── Alerts ───────────────────────────────────────────────────────
    SLACK_WEBHOOK_URL: str = ""
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""

    # ── Paddle (EU/Enterprise billing) ─────────────────────────────────────
    PADDLE_API_KEY: str = ""
    PADDLE_WEBHOOK_SECRET: str = ""
    PADDLE_SELLER_ID: str = ""
    PADDLE_PRO_PRICE_ID: str = ""
    PADDLE_ENTERPRISE_PRICE_ID: str = ""

    # ── Rate / Usage Limits ───────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60
    FREE_TIER_MONTHLY_LIMIT: int = 500
    STARTER_TIER_MONTHLY_LIMIT: int = 25_000
    PRO_TIER_MONTHLY_LIMIT: int = 150_000


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
