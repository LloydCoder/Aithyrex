"""
Aithyrex — Usage Counter (Redis)
===================================
Per-tenant monthly inference counter.
Enforces tier limits in real time via Redis.
PostgreSQL sync happens on overage billing cron.

Tier limits:
  free:       500  inferences/month  → hard cutoff
  starter:  25,000 inferences/month  → +$0.002 overage
  pro:     150,000 inferences/month  → +$0.001 overage
  enterprise: custom (no Redis limit)
"""

from __future__ import annotations

from datetime import datetime, timezone

import structlog

from backend.core.config import settings

logger = structlog.get_logger(__name__)

TIER_LIMITS: dict[str, int] = {
    "free": settings.FREE_TIER_MONTHLY_LIMIT,
    "starter": settings.STARTER_TIER_MONTHLY_LIMIT,
    "pro": settings.PRO_TIER_MONTHLY_LIMIT,
    "enterprise": 999_999_999,
}


class UsageCounterService:
    """
    Redis-backed usage counter.

    Key format: shield:usage:{tenant_id}:{YYYY}:{MM}
    TTL: through the next UTC month boundary plus one day
    """

    def __init__(self) -> None:
        self._redis = None   # lazy-init — avoids import errors when Redis not available

    async def _get_redis(self):
        if self._redis is None:
            try:
                import redis.asyncio as aioredis

                from backend.core.config import settings
                self._redis = aioredis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                )
            except Exception as e:
                logger.error("redis_unavailable", error_type=type(e).__name__)
                raise RuntimeError("usage counter unavailable") from e
        return self._redis

    async def close(self) -> None:
        """Close the Redis connection pool during application shutdown."""
        redis = self._redis
        self._redis = None
        if redis is None:
            return
        close = getattr(redis, "aclose", None) or getattr(redis, "close", None)
        if close is not None:
            result = close()
            if hasattr(result, "__await__"):
                await result

    def _key(self, tenant_id: str) -> str:
        now = datetime.now(timezone.utc)
        return f"shield:usage:{tenant_id}:{now.year}:{now.month:02d}"

    @staticmethod
    def _ttl_to_month_end() -> int:
        now = datetime.now(timezone.utc)
        if now.month == 12:
            next_month = datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            next_month = datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)
        return max(60, int((next_month - now).total_seconds()) + 86400)

    async def increment(self, tenant_id: str) -> int:
        """Increment inference count. Returns new total."""
        redis = await self._get_redis()
        if redis is None:
            raise RuntimeError("usage counter unavailable")

        key = self._key(tenant_id)
        count = await redis.incr(key)

        # Retain the current calendar-month counter through the next boundary.
        if count == 1:
            await redis.expire(key, self._ttl_to_month_end())

        return count

    async def get_count(self, tenant_id: str) -> int:
        """Get current month inference count."""
        redis = await self._get_redis()
        if redis is None:
            raise RuntimeError("usage counter unavailable")

        val = await redis.get(self._key(tenant_id))
        return int(val) if val else 0

    async def reserve_inference(self, tenant_id: str, plan: str) -> tuple[bool, int, int]:
        """Atomically enforce Free cutoff and account an inference in Redis."""
        redis = await self._get_redis()
        if redis is None:
            raise RuntimeError("usage counter unavailable")

        limit = TIER_LIMITS.get(plan, TIER_LIMITS["free"])
        key = self._key(tenant_id)
        script = """
        local current = tonumber(redis.call('GET', KEYS[1]) or '0')
        local limit = tonumber(ARGV[1])
        local plan = ARGV[2]
        if plan == 'free' and current >= limit then
            return {0, current, limit}
        end
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then
            redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
        end
        return {1, count, limit}
        """
        result = await redis.eval(script, 1, key, limit, plan, self._ttl_to_month_end())
        allowed, count, effective_limit = (int(value) for value in result)
        return bool(allowed), count, effective_limit

    async def check_limit(self, tenant_id: str, plan: str) -> tuple[bool, int, int]:
        """
        Check if tenant is within their plan limit.

        Returns:
            (within_limit, current_count, limit)
        """
        limit = TIER_LIMITS.get(plan, 500)
        count = await self.get_count(tenant_id)

        within = count < limit
        if not within:
            logger.warning(
                "usage_limit_exceeded",
                tenant_id=tenant_id,
                plan=plan,
                count=count,
                limit=limit,
            )

        return within, count, limit

    async def get_overage(self, tenant_id: str, plan: str) -> int:
        """Calculate overage inferences for billing."""
        limit = TIER_LIMITS.get(plan, 500)
        count = await self.get_count(tenant_id)
        return max(0, count - limit)


# Module-level singleton
usage_counter = UsageCounterService()
