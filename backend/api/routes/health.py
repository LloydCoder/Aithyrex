"""
AI Shield — Health Route
=========================
GET /health — comprehensive liveness check.
Pings ThreatFade, PostgreSQL, and Redis.
Returns degraded status if any dependency is down.
"""

from __future__ import annotations

import asyncio
import time

import structlog
from fastapi import APIRouter

logger = structlog.get_logger(__name__)
router = APIRouter()


async def _check_threatfade() -> dict:
    from backend.core.threatfade_client import threatfade
    start = time.monotonic()
    try:
        alive = await threatfade.health()
        return {
            "status": "ok" if alive else "unreachable",
            "latency_ms": round((time.monotonic() - start) * 1000, 1),
        }
    except Exception as e:
        return {"status": "error", "error_type": type(e).__name__}


async def _check_postgres() -> dict:
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
    except Exception as e:
        return {"status": "unreachable", "error_type": type(e).__name__}


async def _check_redis() -> dict:
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
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:80]}


@router.get("/health")
async def health():
    """
    Comprehensive health check.
    Returns 200 even if dependencies are degraded (for load balancer compatibility).
    Use `status` field to determine actual health.
    """
    tf, pg, redis = await asyncio.gather(
        _check_threatfade(),
        _check_postgres(),
        _check_redis(),
    )

    all_ok = all(
        d.get("status") == "ok"
        for d in [tf, pg, redis]
    )

    result = {
        "status": "ok" if all_ok else "degraded",
        "version": "0.1.0",
        "dependencies": {
            "threatfade": tf,
            "postgres": pg,
            "redis": redis,
        },
    }

    logger.info("health_check", status=result["status"])
    return result
