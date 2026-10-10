import hashlib
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from backend.core.assertion_replay import AssertionReplayGuard


class FakeReplayRedis:
    def __init__(self, result="OK"):
        self.result = result
        self.calls = []

    async def set(self, key, value, *, nx, ex):
        self.calls.append((key, value, nx, ex))
        return self.result


@pytest.mark.asyncio
async def test_assertion_is_consumed_atomically_with_bounded_expiry():
    guard = AssertionReplayGuard()
    redis = FakeReplayRedis()
    guard._get_redis = AsyncMock(return_value=redis)
    expires_at = int(time.time()) + 120

    await guard.consume("agent-action", "tenant-1", "private-jti", expires_at)

    key, value, nx, ttl = redis.calls[0]
    assert key.startswith("aithyrex:assertion-replay:v1:agent-action:tenant-1:")
    assert hashlib.sha256(b"private-jti").hexdigest() in key
    assert "private-jti" not in key
    assert (value, nx) == ("1", True)
    assert 1 <= ttl <= 120


@pytest.mark.asyncio
async def test_replayed_assertion_returns_conflict():
    guard = AssertionReplayGuard()
    guard._get_redis = AsyncMock(return_value=FakeReplayRedis(result=None))

    with pytest.raises(HTTPException) as error:
        await guard.consume("context", "tenant-1", "already-used", int(time.time()) + 60)

    assert error.value.status_code == 409
    assert error.value.detail["error_code"] == "platform_assertion_replayed"


@pytest.mark.asyncio
async def test_replay_state_outage_fails_closed():
    guard = AssertionReplayGuard()
    guard._get_redis = AsyncMock(side_effect=RuntimeError("redis unavailable"))

    with pytest.raises(HTTPException) as error:
        await guard.consume("sequence", "tenant-1", "event-1", int(time.time()) + 60)

    assert error.value.status_code == 503
    assert error.value.detail["error_code"] == "assertion_replay_state_unavailable"


@pytest.mark.asyncio
async def test_expired_assertion_is_rejected_before_redis_access():
    guard = AssertionReplayGuard()
    guard._get_redis = AsyncMock()

    with pytest.raises(HTTPException) as error:
        await guard.consume("agent-action", "tenant-1", "event-1", int(time.time()) - 1)

    assert error.value.status_code == 401
    guard._get_redis.assert_not_awaited()


@pytest.mark.asyncio
async def test_assertion_contracts_have_separate_replay_namespaces():
    guard = AssertionReplayGuard()
    redis = FakeReplayRedis()
    guard._get_redis = AsyncMock(return_value=redis)
    expires_at = int(time.time()) + 60

    await guard.consume("agent-action", "tenant-1", "same-jti", expires_at)
    await guard.consume("context", "tenant-1", "same-jti", expires_at)

    assert redis.calls[0][0] != redis.calls[1][0]


@pytest.mark.asyncio
async def test_close_releases_redis_pool():
    guard = AssertionReplayGuard()
    redis = MagicMock()
    redis.aclose = AsyncMock()
    guard._redis = redis

    await guard.close()

    redis.aclose.assert_awaited_once()
    assert guard._redis is None
