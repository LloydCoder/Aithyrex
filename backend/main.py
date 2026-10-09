"""
AI Shield — FastAPI Application Entry Point
============================================
Runtime security for LLM and agentic AI systems.

Built by Tinlance Limited (RC: 7962164)
https://github.com/Tinlance/ai-shield
"""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from backend.core.config import settings
from backend.api.routes import detect, enforce, health, monitor, reports, webhooks

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info(
        "ai_shield_starting",
        version="0.1.0",
        environment=settings.APP_ENV,
    )
    yield
    logger.info("ai_shield_shutdown")


app = FastAPI(
    title="AI Shield",
    description="Runtime Security for LLM and Agentic AI Systems",
    version="0.1.0",
    docs_url="/docs" if settings.APP_ENV == "development" else None,
    redoc_url="/redoc" if settings.APP_ENV == "development" else None,
    lifespan=lifespan,
)

# ── Security Middleware ───────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

if settings.APP_ENV == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS,
    )

# ── Routes ────────────────────────────────────────────────────────────
app.include_router(health.router, tags=["Health"])
app.include_router(detect.router, prefix="/detect", tags=["Detection"])
app.include_router(monitor.router, prefix="/monitor", tags=["Monitor"])
app.include_router(enforce.router, prefix="/enforce", tags=["Enforcement"])
app.include_router(reports.router, prefix="/reports", tags=["Reports"])
app.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
