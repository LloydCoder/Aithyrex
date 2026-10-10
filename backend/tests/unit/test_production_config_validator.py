from types import SimpleNamespace

from backend.core.production_config import production_configuration_errors


def valid_settings(**overrides):
    values = {
        "APP_SECRET_KEY": "s" * 48,
        "CLERK_JWT_KEY": "-----BEGIN PUBLIC KEY-----test",
        "CLERK_JWT_ISSUER": "https://clerk.example.com",
        "CLERK_AUTHORIZED_PARTIES": ["https://app.example.com"],
        "THREATFADE_API_URL": "https://threatfade.example.com",
        "THREATFADE_API_KEY": "threatfade-secret",
        "DATABASE_URL": "postgresql+asyncpg://app:strong-db-secret@db.example.com:5432/aithyrex?ssl=verify-full",
        "REDIS_URL": "rediss://:strong-redis-secret@redis.example.com:6379/0",
        "ALLOWED_HOSTS": ["api.example.com"],
        "ALLOWED_ORIGINS": ["https://app.example.com"],
        "OUTBOX_WORKER_ENABLED": True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_valid_production_configuration_has_no_errors():
    assert production_configuration_errors(valid_settings()) == []


def test_database_tls_marker_must_be_a_real_ssl_query_parameter():
    settings = valid_settings(
        DATABASE_URL="postgresql+asyncpg://app:strong-db-secret@db.example.com:5432/aithyrex?notes=ssl%3Drequire"
    )
    errors = production_configuration_errors(settings)
    assert any(error.startswith("DATABASE_URL") for error in errors)


def test_production_rejects_loopback_and_default_redis_credentials():
    settings = valid_settings(
        DATABASE_URL="postgresql+asyncpg://app:strong-db-secret@127.0.0.1:5432/aithyrex?ssl=require",
        REDIS_URL="rediss://:password@redis.example.com:6379/0",
    )
    errors = production_configuration_errors(settings)
    assert any(error.startswith("DATABASE_URL") for error in errors)
    assert any(error.startswith("REDIS_URL") for error in errors)


def test_production_rejects_wildcard_hosts_and_http_origins():
    settings = valid_settings(ALLOWED_HOSTS=["*"], ALLOWED_ORIGINS=["http://app.example.com"])
    errors = production_configuration_errors(settings)
    assert any(error.startswith("ALLOWED_HOSTS") for error in errors)
    assert any(error.startswith("ALLOWED_ORIGINS") for error in errors)


def test_production_rejects_duplicate_ssl_query_parameters():
    settings = valid_settings(
        DATABASE_URL="postgresql+asyncpg://app:strong-db-secret@db.example.com:5432/aithyrex?ssl=disable&ssl=verify-full"
    )
    errors = production_configuration_errors(settings)
    assert any(error.startswith("DATABASE_URL") for error in errors)


def test_production_rejects_loopback_threatfade_even_with_https():
    settings = valid_settings(THREATFADE_API_URL="https://localhost:8000")
    errors = production_configuration_errors(settings)
    assert any(error.startswith("THREATFADE_API_URL") for error in errors)
