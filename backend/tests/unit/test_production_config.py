from fastapi import FastAPI
import pytest

from backend.main import lifespan


TEST_RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsk0lt+quNzDp4+1eKPU3
J34J8H1czcXw3L5/v6h8Yfohhr7S4D4h3YalOK5hWug5/7M0DLSjrTtF6NI9zRn0
Qb75PxPN2sF7NMm0PDJzXXjjL6JUPVmvEpC10F3YlLPpQIghH6QuS7wjpincQrYa
kKo32mQOa6bfXqM3oFxOo56APo9YDj5M4fAGDsP4ZGWFp+hIE6tql70x/Kd/n3pG
qasmvHIUYKvEA4imfSrSE576jX8fVD6rYpPNTdEu8UlNgkd4stF0BaTG0R6BAg8n
VAVSOvoXuXLs9ESzC00H75HmMJq1KOjMX+HkNIAMQukViFk+ulnbrGrvBqHp5aLl
7wIDAQAB
-----END PUBLIC KEY-----"""


@pytest.mark.asyncio
async def test_production_rejects_http_threatfade_and_missing_api_key(monkeypatch):
    settings = __import__("backend.core.config", fromlist=["settings"]).settings
    values = {
        "APP_ENV": "production",
        "CLERK_JWT_KEY": TEST_RSA_PUBLIC_KEY,
        "CLERK_JWT_ISSUER": "https://clerk.example.com",
        "CLERK_AUTHORIZED_PARTIES": ["https://app.example.com"],
        "THREATFADE_API_URL": "http://threatfade.internal",
        "THREATFADE_API_KEY": "",
        "APP_SECRET_KEY": "x" * 40,
        "DATABASE_URL": "postgresql+asyncpg://user:secret123@db.internal:5432/app?ssl=require",
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
        "CLERK_JWT_KEY": TEST_RSA_PUBLIC_KEY,
        "CLERK_JWT_ISSUER": "https://clerk.example.com",
        "CLERK_AUTHORIZED_PARTIES": ["https://app.example.com"],
        "THREATFADE_API_URL": "https://threatfade.internal",
        "THREATFADE_API_KEY": "test-key",
        "APP_SECRET_KEY": "y" * 40,
        "DATABASE_URL": "postgresql+asyncpg://user:secret123@db.internal:5432/app?ssl=require",
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
    assert "OUTBOX_WORKER_ENABLED" in str(exc.value)
