import asyncio

import pytest
from fastapi.responses import JSONResponse

from backend.api.routes import health


@pytest.mark.asyncio
async def test_liveness_does_not_probe_dependencies():
    assert await health.liveness() == {"status": "ok"}


@pytest.mark.asyncio
async def test_readiness_returns_503_when_dependencies_are_degraded(monkeypatch):
    async def degraded():
        return {
            "status": "degraded",
            "version": health.APP_VERSION,
            "dependencies": {
                "threatfade": {"status": "timeout"},
                "postgres": {"status": "ok"},
                "redis": {"status": "ok"},
            },
        }

    monkeypatch.setattr(health, "_dependency_health", degraded)
    response = await health.readiness()
    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_dependency_checks_are_bounded(monkeypatch):
    async def slow_check():
        await asyncio.sleep(0.05)
        return {"status": "ok"}

    result = await health._bounded_check(slow_check, timeout_seconds=0.001)
    assert result == {"status": "timeout"}


@pytest.mark.asyncio
async def test_redis_health_does_not_expose_exception_text(monkeypatch):
    class FailingRedis:
        async def ping(self):
            raise RuntimeError("redis://user:secret@private-host")

    class Usage:
        async def _get_redis(self):
            return FailingRedis()

    monkeypatch.setattr("backend.core.usage_counter.usage_counter", Usage())
    result = await health._check_redis()
    assert result == {"status": "unreachable", "error_type": "RuntimeError"}
    assert "secret" not in str(result)
    assert "private-host" not in str(result)


@pytest.mark.asyncio
async def test_legacy_health_preserves_degraded_status_contract(monkeypatch):
    async def degraded():
        return {
            "status": "degraded",
            "version": health.APP_VERSION,
            "dependencies": {"postgres": {"status": "timeout"}},
        }

    monkeypatch.setattr(health, "_dependency_health", degraded)
    response = await health.health()
    assert response["status"] == "degraded"
