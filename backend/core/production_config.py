"""Production-only configuration invariants for Aithyrex.

This module validates configuration without logging or returning secret values.
It deliberately does not attempt to prove that remote services are reachable.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


_DEFAULT_SECRETS = {"", "change-me", "password", "changeme", "secret", "aishield_dev", "dev-secret-change-in-production"}
_LOCAL_HOSTS = {"localhost", "localhost.localdomain", "host.docker.internal"}


def _is_local_host(host: str | None) -> bool:
    if not host:
        return True
    normalized = host.rstrip(".").lower()
    if normalized in _LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def production_configuration_errors(settings) -> list[str]:
    """Return safe, variable-name-only production configuration errors."""
    errors: list[str] = []

    app_secret = str(getattr(settings, "APP_SECRET_KEY", "") or "")
    if app_secret.lower() in _DEFAULT_SECRETS or len(app_secret) < 32:
        errors.append("APP_SECRET_KEY (must be a non-default secret of at least 32 characters)")

    clerk_key = str(getattr(settings, "CLERK_JWT_KEY", "") or "").strip()
    if not clerk_key:
        errors.append("CLERK_JWT_KEY")
    else:
        try:
            parsed_clerk_key = serialization.load_pem_public_key(clerk_key.encode("utf-8"))
            if not isinstance(parsed_clerk_key, rsa.RSAPublicKey):
                errors.append("CLERK_JWT_KEY (RSA public key PEM required)")
        except Exception:
            errors.append("CLERK_JWT_KEY (valid RSA public key PEM required)")
    issuer = urlparse(str(getattr(settings, "CLERK_JWT_ISSUER", "") or ""))
    if (
        issuer.scheme != "https"
        or not issuer.hostname
        or _is_local_host(issuer.hostname)
        or issuer.username
        or issuer.password
    ):
        errors.append("CLERK_JWT_ISSUER (remote HTTPS issuer URL required)")
    if not getattr(settings, "CLERK_AUTHORIZED_PARTIES", None):
        errors.append("CLERK_AUTHORIZED_PARTIES (explicit allow-list required)")

    threatfade = urlparse(str(getattr(settings, "THREATFADE_API_URL", "") or ""))
    if (
        threatfade.scheme != "https"
        or not threatfade.hostname
        or _is_local_host(threatfade.hostname)
        or threatfade.username
        or threatfade.password
    ):
        errors.append("THREATFADE_API_URL (HTTPS endpoint without embedded credentials required)")
    if not str(getattr(settings, "THREATFADE_API_KEY", "") or "").strip():
        errors.append("THREATFADE_API_KEY")

    database = urlparse(str(getattr(settings, "DATABASE_URL", "") or ""))
    database_query = parse_qs(database.query, keep_blank_values=True)
    ssl_values = [value.lower() for value in database_query.get("ssl", [])]
    database_password = database.password or ""
    if (
        database.scheme != "postgresql+asyncpg"
        or _is_local_host(database.hostname)
        or not database.username
        or len(database_password) < 16
        or database_password.lower() in _DEFAULT_SECRETS
        or len(ssl_values) != 1
        or ssl_values[0] not in {"require", "verify-full"}
    ):
        errors.append("DATABASE_URL (remote PostgreSQL+asyncpg, non-default credentials and ssl=require|verify-full required)")

    redis = urlparse(str(getattr(settings, "REDIS_URL", "") or ""))
    redis_password = redis.password or ""
    if (
        redis.scheme != "rediss"
        or _is_local_host(redis.hostname)
        or len(redis_password) < 16
        or redis_password.lower() in _DEFAULT_SECRETS
    ):
        errors.append("REDIS_URL (remote TLS Redis endpoint with non-default authentication required)")

    hosts = list(getattr(settings, "ALLOWED_HOSTS", []) or [])
    if not hosts or any(not str(host).strip() or "*" in str(host) for host in hosts):
        errors.append("ALLOWED_HOSTS (explicit host allow-list required)")

    origins = list(getattr(settings, "ALLOWED_ORIGINS", []) or [])
    if not origins or any(
        urlparse(str(origin)).scheme != "https"
        or not urlparse(str(origin)).hostname
        or urlparse(str(origin)).username
        or urlparse(str(origin)).password
        or "*" in (urlparse(str(origin)).hostname or "")
        for origin in origins
    ):
        errors.append("ALLOWED_ORIGINS (explicit HTTPS origin allow-list required)")

    pool_size = getattr(settings, "DB_POOL_SIZE", 10)
    max_overflow = getattr(settings, "DB_MAX_OVERFLOW", 20)
    pool_timeout = getattr(settings, "DB_POOL_TIMEOUT_SECONDS", 30)
    pool_recycle = getattr(settings, "DB_POOL_RECYCLE_SECONDS", 1800)
    if isinstance(pool_size, bool) or not isinstance(pool_size, int) or not 1 <= pool_size <= 100:
        errors.append("DB_POOL_SIZE (integer from 1 to 100 required)")
    if isinstance(max_overflow, bool) or not isinstance(max_overflow, int) or not 0 <= max_overflow <= 200:
        errors.append("DB_MAX_OVERFLOW (integer from 0 to 200 required)")
    if isinstance(pool_timeout, bool) or not isinstance(pool_timeout, int) or not 1 <= pool_timeout <= 120:
        errors.append("DB_POOL_TIMEOUT_SECONDS (integer from 1 to 120 required)")
    if isinstance(pool_recycle, bool) or not isinstance(pool_recycle, int) or not 60 <= pool_recycle <= 86400:
        errors.append("DB_POOL_RECYCLE_SECONDS (integer from 60 to 86400 required)")

    if not getattr(settings, "OUTBOX_WORKER_ENABLED", False):
        errors.append("OUTBOX_WORKER_ENABLED=true (durable delivery worker required)")

    return errors
