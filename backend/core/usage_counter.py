"""
AI Shield — Usage Counter (Redis)
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

import calendar
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger(__name__)

TIER_LIMITS: dict[str, int] = {
    "free":       500,
    "starter":    25_000,
    "pro":        150_000,
    "enterprise": 999_999_999,   # effectively unlimited
}


class UsageCounterService:
    """
    Redis-backed usage counter.

    Key format: shield:usage:{tenant_id}:{YYYY}:{MM}
    TTL: 35 days (covers the full month + billing window)
    """

    def __init__(self) -> None:
        self._redis = None   # lazy-init — avoids import errors when Redis not available

    async def _get_redis(self):
        if self._redis is None:
            try:
                import redis.asyncio as aioredis
                from backend.core.config import settings
                self._redis = await aioredis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                )
            except Exception as e:
                logger.warning("redis_unavailable", error=str(e))
                return None
        return self._redis

    def _key(self, tenant_id: str) -> str:
        now = datetime.now(timezone.utc)
        return f"shield:usage:{tenant_id}:{now.year}:{now.month:02d}"

    async def increment(self, tenant_id: str) -> int:
        """Increment inference count. Returns new total."""
        redis = await self._get_redis()
        if redis is None:
            return 0

        key = self._key(tenant_id)
        count = await redis.incr(key)

        # Set TTL on first increment — expire 35 days from now
        if count == 1:
            ttl = 35 * 24 * 3600
            await redis.expire(key, ttl)

        return count

    async def get_count(self, tenant_id: str) -> int:
        """Get current month inference count."""
        redis = await self._get_redis()
        if redis is None:
            return 0

        val = await redis.get(self._key(tenant_id))
        return int(val) if val else 0

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
