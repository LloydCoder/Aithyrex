"""Tenant-scoped Redis rate limiting for authenticated API requests."""

from __future__ import annotations

import time

import structlog
from fastapi import HTTPException

from backend.core.config import settings

logger = structlog.get_logger(__name__)


class RateLimiter:
    """Atomic fixed-window limiter. Redis failure is surfaced, never treated as unlimited."""

    def __init__(self) -> None:
        self._redis = None

    async def _get_redis(self):
        if self._redis is None:
            try:
                import redis.asyncio as aioredis

                self._redis = await aioredis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                )
            except Exception as exc:
                logger.error("rate_limit_redis_unavailable", error_type=type(exc).__name__)
                raise RuntimeError("rate limiter unavailable") from exc
        return self._redis

    async def enforce(self, tenant_id: str) -> tuple[int, int]:
        """Return (observed count, limit), or raise 429/RuntimeError."""
        redis = await self._get_redis()
        now_window = int(time.time() // 60)
        key = f"aithyrex:rate:{tenant_id}:{now_window}"
        limit = max(1, int(settings.RATE_LIMIT_PER_MINUTE))
        script = """
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then
            redis.call('EXPIRE', KEYS[1], 65)
        end
        if count > tonumber(ARGV[1]) then
            return {0, count}
        end
        return {1, count}
        """
        try:
            result = await redis.eval(script, 1, key, limit)
            allowed, count = (int(value) for value in result)
        except Exception as exc:
            logger.error("rate_limit_state_unavailable", error_type=type(exc).__name__)
            raise RuntimeError("rate limiter state unavailable") from exc
        if not allowed:
            logger.warning("tenant_rate_limit_exceeded", tenant_id=tenant_id, count=count, limit=limit)
            raise HTTPException(
                status_code=429,
                detail="Tenant request rate limit exceeded",
                headers={"Retry-After": "60"},
            )
        return count, limit


rate_limiter = RateLimiter()
