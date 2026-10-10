from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import FastAPI

from backend.main import lifespan


@pytest.mark.asyncio
async def test_production_rejects_http_threatfade_and_missing_api_key(monkeypatch):
    settings = __import__("backend.core.config", fromlist=["settings"]).settings
    values = {
        "APP_ENV": "production",
        "CLERK_JWT_KEY": "test-key",
        "CLERK_JWT_ISSUER": "https://clerk.example.com",
        "CLERK_AUTHORIZED_PARTIES": ["https://app.example.com"],
        "THREATFADE_API_URL": "http://threatfade.internal",
        "THREATFADE_API_KEY": "",
        "APP_SECRET_KEY": "x" * 40,
        "DATABASE_URL": "postgresql+asyncpg://user:strong-password@db.internal:5432/app?ssl=require",
        "REDIS_URL": "rediss://redis.internal:6379/0",
        "ALLOWED_HOSTS": ["api.example.com"],
        "ALLOWED_ORIGINS": ["https://app.example.com"],
    }
    for key, value in values.items():
        monkeypatch.setattr(settings, key, value)

    with pytest.raises(RuntimeError) as exc:
        async with lifespan(FastAPI()):
            pass
    assert "THREATFADE_API_URL" in str(exc.value)
    assert "THREATFADE_API_KEY" in str(exc.value)


@pytest.mark.asyncio
async def test_production_configuration_requires_trusted_hosts(monkeypatch):
    settings = __import__("backend.core.config", fromlist=["settings"]).settings
    values = {
        "APP_ENV": "prod",
        "CLERK_JWT_KEY": "test-key",
        "CLERK_JWT_ISSUER": "https://clerk.example.com",
        "CLERK_AUTHORIZED_PARTIES": ["https://app.example.com"],
        "THREATFADE_API_URL": "https://threatfade.internal",
        "THREATFADE_API_KEY": "test-key",
        "APP_SECRET_KEY": "x" * 40,
        "DATABASE_URL": "postgresql+asyncpg://user:strong-password@db.internal:5432/app?ssl=require",
        "REDIS_URL": "rediss://redis.internal:6379/0",
        "ALLOWED_HOSTS": ["*"],
        "ALLOWED_ORIGINS": ["https://app.example.com"],
    }
    for key, value in values.items():
        monkeypatch.setattr(settings, key, value)

    with pytest.raises(RuntimeError) as exc:
        async with lifespan(FastAPI()):
            pass
    assert "ALLOWED_HOSTS" in str(exc.value)
