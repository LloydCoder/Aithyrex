from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.core.usage_counter import UsageCounterService


@pytest.mark.asyncio
async def test_usage_counter_uses_sync_redis_client_factory(monkeypatch):
    service = UsageCounterService()
    fake_redis = AsyncMock()
    factory = MagicMock(return_value=fake_redis)
    monkeypatch.setattr("redis.asyncio.from_url", factory)
    monkeypatch.setattr("backend.core.usage_counter.settings.REDIS_URL", "redis://test:6379/0")

    assert await service._get_redis() is fake_redis
    factory.assert_called_once_with(
        "redis://test:6379/0", encoding="utf-8", decode_responses=True
    )


def test_usage_key_is_scoped_to_current_utc_calendar_month():
    service = UsageCounterService()
    now = datetime.now(timezone.utc)
    assert service._key("tenant-1") == f"shield:usage:tenant-1:{now.year}:{now.month:02d}"


def test_month_ttl_expires_after_next_month_boundary():
    ttl = UsageCounterService._ttl_to_month_end()
    assert 24 * 60 * 60 <= ttl <= 33 * 24 * 60 * 60


@pytest.mark.asyncio
async def test_reservation_is_atomic_and_records_monthly_ttl():
    service = UsageCounterService()
    service._redis = AsyncMock()
    service._redis.eval = AsyncMock(return_value=[1, 1, 500])

    allowed, count, limit = await service.reserve_inference("tenant-1", "free")

    assert (allowed, count, limit) == (True, 1, 500)
    args = service._redis.eval.await_args.args
    assert args[0].count("INCR") == 1
    assert "current >= limit" in args[0]
    assert args[2] == service._key("tenant-1")
    assert args[-1] == service._ttl_to_month_end()


@pytest.mark.asyncio
async def test_free_reservation_at_limit_is_denied_without_increment():
    service = UsageCounterService()
    service._redis = AsyncMock()
    service._redis.eval = AsyncMock(return_value=[0, 500, 500])

    allowed, count, limit = await service.reserve_inference("tenant-1", "free")

    assert (allowed, count, limit) == (False, 500, 500)


@pytest.mark.asyncio
async def test_redis_unavailable_raises_instead_of_returning_zero():
    service = UsageCounterService()
    service._get_redis = AsyncMock(side_effect=RuntimeError("unavailable"))
    with pytest.raises(RuntimeError, match="unavailable"):
        await service.reserve_inference("tenant-1", "free")


@pytest.mark.asyncio
async def test_close_releases_redis_pool():
    service = UsageCounterService()
    redis = MagicMock()
    redis.aclose = AsyncMock()
    service._redis = redis

    await service.close()

    redis.aclose.assert_awaited_once()
    assert service._redis is None
