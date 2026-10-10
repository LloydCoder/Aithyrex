"""
AI Shield — Block Mode Enforcement
=====================================
Redis-backed per-model and per-agent blocking. Pro tier only.

When a model or agent is blocked:
  - All subsequent calls from that model return BLOCK immediately
  - ShieldEngine checks block list BEFORE running detectors
  - Block list entries expire after configurable TTL (default: 24h)

Keys:
  shield:block:model:{tenant_id}:{model_id}   → "1" (blocked)
  shield:block:agent:{tenant_id}:{agent_id}   → "1" (blocked)
  shield:allow:{tenant_id}:{model_id}         → "1" (allowlisted)
"""

from __future__ import annotations

import structlog

logger = structlog.get_logger(__name__)

DEFAULT_BLOCK_TTL = 86_400   # 24 hours
ALLOW_TTL = 7 * 86_400       # 7 days


class BlockModeService:
    """
    Redis-backed block/allow list for models and agents.
    Pro tier and above only — enforced at route level.
    """

    def __init__(self) -> None:
        self._redis = None

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
                logger.warning("block_mode_redis_unavailable", error=str(e))
                return None
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

    # ── Block operations ──────────────────────────────────────────────────────
    async def block_model(
        self,
        tenant_id: str,
        model_id: str,
        reason: str = "",
        ttl: int = DEFAULT_BLOCK_TTL,
    ) -> bool:
        redis = await self._get_redis()
        if not redis:
            return False
        key = f"shield:block:model:{tenant_id}:{model_id}"
        try:
            await redis.setex(key, ttl, reason or "1")
        except Exception as exc:
            logger.error("model_block_write_failed", tenant_id=tenant_id, error_type=type(exc).__name__)
            return False
        logger.warning("model_blocked", tenant_id=tenant_id, model_id=model_id, ttl=ttl)
        return True

    async def block_agent(
        self,
        tenant_id: str,
        agent_id: str,
        reason: str = "",
        ttl: int = DEFAULT_BLOCK_TTL,
    ) -> bool:
        redis = await self._get_redis()
        if not redis:
            return False
        key = f"shield:block:agent:{tenant_id}:{agent_id}"
        try:
            await redis.setex(key, ttl, reason or "1")
        except Exception as exc:
            logger.error("agent_block_write_failed", tenant_id=tenant_id, error_type=type(exc).__name__)
            return False
        logger.warning("agent_blocked", tenant_id=tenant_id, agent_id=agent_id, ttl=ttl)
        return True

    async def unblock_model(self, tenant_id: str, model_id: str) -> bool:
        redis = await self._get_redis()
        if not redis:
            return False
        key = f"shield:block:model:{tenant_id}:{model_id}"
        try:
            await redis.delete(key)
        except Exception as exc:
            logger.error("model_unblock_failed", tenant_id=tenant_id, error_type=type(exc).__name__)
            return False
        logger.info("model_unblocked", tenant_id=tenant_id, model_id=model_id)
        return True

    async def unblock_agent(self, tenant_id: str, agent_id: str) -> bool:
        redis = await self._get_redis()
        if not redis:
            return False
        key = f"shield:block:agent:{tenant_id}:{agent_id}"
        try:
            await redis.delete(key)
        except Exception as exc:
            logger.error("agent_unblock_failed", tenant_id=tenant_id, error_type=type(exc).__name__)
            return False
        return True

    # ── Allow operations ──────────────────────────────────────────────────────
    async def allowlist_model(
        self,
        tenant_id: str,
        model_id: str,
        ttl: int = ALLOW_TTL,
    ) -> bool:
        redis = await self._get_redis()
        if not redis:
            return False
        key = f"shield:allow:{tenant_id}:{model_id}"
        await redis.setex(key, ttl, "1")
        logger.info("model_allowlisted", tenant_id=tenant_id, model_id=model_id)
        return True

    # ── Check operations ──────────────────────────────────────────────────────
    async def is_blocked(
        self,
        tenant_id: str,
        model_id: str | None = None,
        agent_id: str | None = None,
    ) -> tuple[bool, str]:
        """
        Check if a model or agent is blocked.

        Returns (is_blocked, reason).
        """
        redis = await self._get_redis()
        if not redis:
            logger.error("block_state_unavailable_fail_closed", tenant_id=tenant_id)
            return True, "block_state_unavailable"

        try:
            if model_id:
                key = f"shield:block:model:{tenant_id}:{model_id}"
                val = await redis.get(key)
                if val:
                    return True, val if val != "1" else "blocked by admin"

            if agent_id:
                key = f"shield:block:agent:{tenant_id}:{agent_id}"
                val = await redis.get(key)
                if val:
                    return True, val if val != "1" else "blocked by admin"

            return False, ""
        except Exception as exc:
            logger.error("block_state_read_failed_fail_closed", error_type=type(exc).__name__)
            return True, "block_state_unavailable"

    async def is_allowlisted(
        self,
        tenant_id: str,
        model_id: str,
    ) -> bool:
        """Legacy storage lookup only; enforcement must never use it to bypass detection."""
        redis = await self._get_redis()
        if not redis:
            return False
        key = f"shield:allow:{tenant_id}:{model_id}"
        try:
            return bool(await redis.get(key))
        except Exception as exc:
            logger.error("legacy_allowlist_read_failed", tenant_id=tenant_id, error_type=type(exc).__name__)
            return False

    async def list_blocked(self, tenant_id: str) -> list[dict]:
        """List all blocked models and agents for a tenant."""
        redis = await self._get_redis()
        if not redis:
            raise RuntimeError("Block-state storage unavailable; cannot confirm blocklist")

        blocked = []
        # Parse exact tenant-scoped prefixes so valid IDs containing ':' are preserved.
        model_prefix = f"shield:block:model:{tenant_id}:"
        agent_prefix = f"shield:block:agent:{tenant_id}:"
        # Models
        async for key in redis.scan_iter(f"{model_prefix}*"):
            model_id = key[len(model_prefix):]
            reason = await redis.get(key)
            ttl = await redis.ttl(key)
            blocked.append({
                "type": "model",
                "id": model_id,
                "reason": reason,
                "expires_in_seconds": ttl,
            })

        # Agents
        async for key in redis.scan_iter(f"{agent_prefix}*"):
            agent_id = key[len(agent_prefix):]
            reason = await redis.get(key)
            ttl = await redis.ttl(key)
            blocked.append({
                "type": "agent",
                "id": agent_id,
                "reason": reason,
                "expires_in_seconds": ttl,
            })

        return blocked


# Module-level singleton
block_mode = BlockModeService()
