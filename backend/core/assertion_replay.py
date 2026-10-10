"""Atomic replay protection for short-lived Platform-signed assertions.

Aithyrex accepts signed assertions only as advisory inspection inputs. The guard
prevents one assertion identifier from producing duplicate work/signals and fails
closed when its Redis state cannot be trusted.
"""
from __future__ import annotations

import hashlib
import time
from typing import Literal

from fastapi import HTTPException
import structlog

from backend.core.config import settings

logger = structlog.get_logger(__name__)
AssertionContract = Literal["agent-action", "context", "sequence"]


class AssertionReplayGuard:
    """Consume an assertion JTI once using Redis SET NX with an expiry bounded by JWT exp."""

    def __init__(self) -> None:
        self._redis = None

    async def _get_redis(self):
        if self._redis is None:
            try:
                import redis.asyncio as aioredis

                # redis.asyncio.from_url is a synchronous factory returning an async client.
                self._redis = aioredis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                )
            except Exception as exc:
                logger.error(
                    "assertion_replay_redis_unavailable",
                    error_type=type(exc).__name__,
                )
                raise RuntimeError("assertion replay state unavailable") from exc
        return self._redis

    async def consume(
        self,
        contract: AssertionContract,
        tenant_id: str,
        jti: str,
        expires_at: int,
    ) -> None:
        """Atomically reserve a signed assertion ID, rejecting replay and Redis failure."""
        now = int(time.time())
        ttl = min(300, int(expires_at) - now)
        if ttl <= 0:
            raise HTTPException(
                status_code=401,
                detail={
                    "error_code": "platform_assertion_expired",
                    "message": "Platform assertion is expired.",
                },
            )
        if not tenant_id or not jti or len(jti) > 128:
            raise HTTPException(
                status_code=401,
                detail={
                    "error_code": "invalid_platform_assertion_claims",
                    "message": "Platform assertion claims are malformed.",
                },
            )

        jti_digest = hashlib.sha256(jti.encode("utf-8")).hexdigest()
        key = f"aithyrex:assertion-replay:v1:{contract}:{tenant_id}:{jti_digest}"
        try:
            redis = await self._get_redis()
            created = await redis.set(key, "1", nx=True, ex=ttl)
        except Exception as exc:
            logger.error(
                "assertion_replay_state_unavailable",
                contract=contract,
                error_type=type(exc).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "error_code": "assertion_replay_state_unavailable",
                    "message": "Platform assertion replay state is unavailable.",
                },
            ) from exc

        if not created:
            raise HTTPException(
                status_code=409,
                detail={
                    "error_code": "platform_assertion_replayed",
                    "message": "Platform assertion has already been consumed.",
                },
            )

    async def close(self) -> None:
        """Close the lazily-created Redis connection pool during application shutdown."""
        if self._redis is None:
            return
        redis = self._redis
        self._redis = None
        close = getattr(redis, "aclose", None) or getattr(redis, "close", None)
        if close is not None:
            result = close()
            if hasattr(result, "__await__"):
                await result


assertion_replay_guard = AssertionReplayGuard()
