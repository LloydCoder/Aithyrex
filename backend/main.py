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

from backend.api.routes import detect, enforce, health, monitor, reports, webhooks
from backend.core.config import settings

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    if settings.APP_ENV.lower() == "production":
        missing = []
        if not settings.CLERK_JWT_KEY:
            missing.append("CLERK_JWT_KEY")
        if not settings.CLERK_JWT_ISSUER:
            missing.append("CLERK_JWT_ISSUER")
        if not settings.CLERK_AUTHORIZED_PARTIES:
            missing.append("CLERK_AUTHORIZED_PARTIES")
        if settings.APP_SECRET_KEY == "change-me" or len(settings.APP_SECRET_KEY) < 32:
            missing.append("APP_SECRET_KEY (must be at least 32 characters and non-default)")
        if not settings.ALLOWED_HOSTS or "*" in settings.ALLOWED_HOSTS:
            missing.append("ALLOWED_HOSTS (explicit production hosts required)")
        if (
            not settings.ALLOWED_ORIGINS
            or "*" in settings.ALLOWED_ORIGINS
            or any(not origin.startswith("https://") for origin in settings.ALLOWED_ORIGINS)
        ):
            missing.append("ALLOWED_ORIGINS (explicit HTTPS origins required)")
        if missing:
            raise RuntimeError("Unsafe production configuration; configure: " + ", ".join(missing))
    logger.info(
        "aithyrex_starting",
        version="0.1.0",
        environment=settings.APP_ENV,
    )
    yield
    logger.info("aithyrex_shutdown")


app = FastAPI(
    title="Aithyrex",
    description="Agentic AI Runtime Security",
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
