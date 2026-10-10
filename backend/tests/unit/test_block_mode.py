"""
AI Shield — Unit Tests: Block Mode
=====================================
Tests Redis-backed block/allow list enforcement.
Redis is mocked — no live Redis needed.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.core.block_mode import BlockModeService


@pytest.fixture
def service():
    return BlockModeService()


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    redis = MagicMock()
    redis.setex = AsyncMock(return_value=True)
    redis.get = AsyncMock(return_value=None)
    redis.delete = AsyncMock(return_value=1)
    redis.ttl = AsyncMock(return_value=86400)
    redis.ping = AsyncMock(return_value=True)

    async def mock_scan(*args, **kwargs):
        return
        yield   # empty async generator

    redis.scan_iter = mock_scan
    return redis


@pytest.fixture(autouse=True)
def patch_redis(service, mock_redis):
    service._redis = mock_redis
    yield


# ── Block operations ──────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_block_model_sets_redis_key(service, mock_redis):
    result = await service.block_model("tenant-1", "gpt-4o", "C2 behaviour detected")
    assert result is True
    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args
    assert "shield:block:model:tenant-1:gpt-4o" in str(call_args)


@pytest.mark.asyncio
async def test_block_agent_sets_redis_key(service, mock_redis):
    result = await service.block_agent("tenant-1", "agent-001", "injection attempt")
    assert result is True
    mock_redis.setex.assert_called_once()


@pytest.mark.asyncio
async def test_is_blocked_returns_true_when_key_exists(service, mock_redis):
    mock_redis.get = AsyncMock(return_value="C2 behaviour detected")
    blocked, reason = await service.is_blocked("tenant-1", model_id="gpt-4o")
    assert blocked is True
    assert "C2" in reason


@pytest.mark.asyncio
async def test_is_blocked_returns_false_when_no_key(service, mock_redis):
    mock_redis.get = AsyncMock(return_value=None)
    blocked, reason = await service.is_blocked("tenant-1", model_id="gpt-4o")
    assert blocked is False
    assert reason == ""


@pytest.mark.asyncio
async def test_unblock_deletes_redis_key(service, mock_redis):
    result = await service.unblock_model("tenant-1", "gpt-4o")
    assert result is True
    mock_redis.delete.assert_called_once()


# ── Allow operations ──────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_allowlist_model_sets_key(service, mock_redis):
    result = await service.allowlist_model("tenant-1", "claude-haiku")
    assert result is True
    mock_redis.setex.assert_called_once()


@pytest.mark.asyncio
async def test_is_allowlisted_returns_true(service, mock_redis):
    mock_redis.get = AsyncMock(return_value="1")
    result = await service.is_allowlisted("tenant-1", "claude-haiku")
    assert result is True


@pytest.mark.asyncio
async def test_is_allowlisted_returns_false_when_absent(service, mock_redis):
    mock_redis.get = AsyncMock(return_value=None)
    result = await service.is_allowlisted("tenant-1", "claude-haiku")
    assert result is False


# ── TTL enforcement ───────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_block_model_default_ttl_is_24h(service, mock_redis):
    await service.block_model("tenant-1", "gpt-4o")
    call_args = mock_redis.setex.call_args
    ttl = call_args.args[1] if call_args.args else call_args[0][1]
    assert ttl == 86_400   # 24 hours


@pytest.mark.asyncio
async def test_block_model_custom_ttl(service, mock_redis):
    await service.block_model("tenant-1", "gpt-4o", ttl=3600)
    call_args = mock_redis.setex.call_args
    ttl = call_args.args[1] if call_args.args else call_args[0][1]
    assert ttl == 3600

@pytest.mark.asyncio
async def test_list_blocked_preserves_colons_in_model_and_agent_ids(service, mock_redis):
    async def scan_iter(pattern):
        if "shield:block:model:" in pattern:
            yield "shield:block:model:tenant-1:provider:model:alpha"
        elif "shield:block:agent:" in pattern:
            yield "shield:block:agent:tenant-1:agent:worker-1"

    mock_redis.scan_iter = scan_iter
    mock_redis.get = AsyncMock(return_value="test reason")
    items = await service.list_blocked("tenant-1")

    assert {item["id"] for item in items} == {"provider:model:alpha", "agent:worker-1"}
