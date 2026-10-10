"""Bounded liveness and dependency-readiness endpoints for Aithyrex."""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

import structlog
from fastapi import APIRouter
from fastapi.responses import JSONResponse

logger = structlog.get_logger(__name__)
router = APIRouter()

HEALTH_CHECK_TIMEOUT_SECONDS = 2.0
APP_VERSION = "0.1.0"


async def _check_threatfade() -> dict[str, Any]:
    from backend.core.threatfade_client import threatfade

    start = time.monotonic()
    try:
        alive = await threatfade.health()
        return {
            "status": "ok" if alive else "unreachable",
            "latency_ms": round((time.monotonic() - start) * 1000, 1),
        }
    except Exception as exc:
        return {"status": "error", "error_type": type(exc).__name__}


async def _check_postgres() -> dict[str, Any]:
    start = time.monotonic()
    try:
        from sqlalchemy import text

        from backend.models.database import engine

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {
            "status": "ok",
            "latency_ms": round((time.monotonic() - start) * 1000, 1),
        }
    except Exception as exc:
        return {"status": "unreachable", "error_type": type(exc).__name__}


async def _check_redis() -> dict[str, Any]:
    start = time.monotonic()
    try:
        from backend.core.usage_counter import usage_counter

        redis = await usage_counter._get_redis()
        if redis:
            await redis.ping()
            return {
                "status": "ok",
                "latency_ms": round((time.monotonic() - start) * 1000, 1),
            }
        return {"status": "unreachable"}
    except Exception as exc:
        # Never return exception text, URLs, hostnames, or credential-bearing details.
        return {"status": "unreachable", "error_type": type(exc).__name__}


async def _bounded_check(
    check: Callable[[], Awaitable[dict[str, Any]]],
    timeout_seconds: float = HEALTH_CHECK_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(check(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        return {"status": "timeout"}
    except Exception as exc:
        return {"status": "error", "error_type": type(exc).__name__}


async def _dependency_health() -> dict[str, Any]:
    threatfade, postgres, redis = await asyncio.gather(
        _bounded_check(_check_threatfade),
        _bounded_check(_check_postgres),
        _bounded_check(_check_redis),
    )
    dependencies = {
        "threatfade": threatfade,
        "postgres": postgres,
        "redis": redis,
    }
    all_ok = all(item.get("status") == "ok" for item in dependencies.values())
    result = {
        "status": "ok" if all_ok else "degraded",
        "version": APP_VERSION,
        "dependencies": dependencies,
    }
    logger.info("health_check", status=result["status"])
    return result


@router.get("/health/live")
async def liveness() -> dict[str, str]:
    """Process liveness only; deliberately independent of remote dependencies."""
    return {"status": "ok"}


@router.get("/health/ready")
async def readiness() -> JSONResponse:
    """Readiness for traffic that requires the critical dependencies to be healthy."""
    result = await _dependency_health()
    return JSONResponse(
        status_code=200 if result["status"] == "ok" else 503,
        content=result,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/health")
async def health() -> dict[str, Any]:
    """Backward-compatible dependency diagnostic; degraded state remains HTTP 200.

    New load balancer/orchestrator probes should use /health/live or /health/ready.
    """
    return await _dependency_health()
