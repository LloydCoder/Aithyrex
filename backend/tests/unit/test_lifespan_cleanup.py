from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI

from backend.core.config import settings
from backend.main import lifespan


@pytest.mark.asyncio
async def test_shutdown_closes_redis_services_and_disposes_database_engine(monkeypatch):
    from backend.core.assertion_replay import assertion_replay_guard
    from backend.core.block_mode import block_mode
    from backend.core.rate_limiter import rate_limiter
    from backend.core.usage_counter import usage_counter
    from backend.models.database import engine

    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "OUTBOX_WORKER_ENABLED", False)

    close_mocks = []
    for service in (assertion_replay_guard, block_mode, rate_limiter, usage_counter):
        close_mock = AsyncMock()
        monkeypatch.setattr(service, "close", close_mock)
        close_mocks.append(close_mock)
    dispose_mock = AsyncMock()
    monkeypatch.setattr(type(engine), "dispose", dispose_mock)

    async with lifespan(FastAPI()):
        pass

    for close_mock in close_mocks:
        close_mock.assert_awaited_once()
    dispose_mock.assert_awaited_once()
