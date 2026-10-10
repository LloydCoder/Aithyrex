from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from backend.core.rate_limiter import RateLimiter


class FakeRedis:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def eval(self, script, numkeys, key, limit):
        self.calls.append((numkeys, key, limit))
        return self.result


@pytest.mark.asyncio
async def test_redis_async_from_url_factory_is_not_awaited(monkeypatch):
    limiter = RateLimiter()
    fake_redis = FakeRedis([1, 1])
    factory = MagicMock(return_value=fake_redis)
    monkeypatch.setattr("redis.asyncio.from_url", factory)
    monkeypatch.setattr("backend.core.rate_limiter.settings.REDIS_URL", "redis://test:6379/0")

    assert await limiter._get_redis() is fake_redis
    factory.assert_called_once_with(
        "redis://test:6379/0", encoding="utf-8", decode_responses=True
    )


@pytest.mark.asyncio
async def test_rate_limiter_allows_request_under_limit(monkeypatch):
    limiter = RateLimiter()
    redis = FakeRedis([1, 3])
    limiter._get_redis = AsyncMock(return_value=redis)
    monkeypatch.setattr("backend.core.rate_limiter.settings.RATE_LIMIT_PER_MINUTE", 60)
    count, limit = await limiter.enforce("tenant-1")
    assert (count, limit) == (3, 60)
    assert redis.calls[0][0] == 1
    assert "tenant-1" in redis.calls[0][1]


@pytest.mark.asyncio
async def test_rate_limiter_rejects_over_limit(monkeypatch):
    limiter = RateLimiter()
    limiter._get_redis = AsyncMock(return_value=FakeRedis([0, 61]))
    monkeypatch.setattr("backend.core.rate_limiter.settings.RATE_LIMIT_PER_MINUTE", 60)
    with pytest.raises(HTTPException) as exc:
        await limiter.enforce("tenant-1")
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "60"


@pytest.mark.asyncio
async def test_rate_limiter_fails_closed_when_redis_unavailable():
    limiter = RateLimiter()
    limiter._get_redis = AsyncMock(side_effect=RuntimeError("redis unavailable"))
    with pytest.raises(RuntimeError, match="redis unavailable"):
        await limiter.enforce("tenant-1")


@pytest.mark.asyncio
async def test_rate_limiter_is_tenant_scoped():
    limiter = RateLimiter()
    redis = FakeRedis([1, 1])
    limiter._get_redis = AsyncMock(return_value=redis)
    await limiter.enforce("tenant-A")
    await limiter.enforce("tenant-B")
    assert redis.calls[0][1] != redis.calls[1][1]
