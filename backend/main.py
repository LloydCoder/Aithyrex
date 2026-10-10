"""
Aithyrex — FastAPI Application Entry Point
============================================
Runtime security for LLM and agentic AI systems.

Built by Tinlance Limited (RC: 7962164)
https://github.com/LloydCoder/Aithyrex
"""

from contextlib import asynccontextmanager
from urllib.parse import urlparse
from uuid import UUID, uuid4

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from structlog.contextvars import bound_contextvars

from backend.api.routes import detect, enforce, health, monitor, reports, webhooks
from backend.core.config import settings
from backend.core.contracts import APIErrorV1

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    if settings.APP_ENV.lower() in {"prod", "production"}:
        missing = []
        if not settings.CLERK_JWT_KEY:
            missing.append("CLERK_JWT_KEY")
        if not settings.CLERK_JWT_ISSUER:
            missing.append("CLERK_JWT_ISSUER")
        if not settings.CLERK_AUTHORIZED_PARTIES:
            missing.append("CLERK_AUTHORIZED_PARTIES")
        threatfade_url = urlparse(settings.THREATFADE_API_URL)
        if threatfade_url.scheme != "https" or not threatfade_url.hostname:
            missing.append("THREATFADE_API_URL (HTTPS endpoint required in production)")
        if not settings.THREATFADE_API_KEY:
            missing.append("THREATFADE_API_KEY")
        if settings.APP_SECRET_KEY == "change-me" or len(settings.APP_SECRET_KEY) < 32:
            missing.append("APP_SECRET_KEY (must be at least 32 characters and non-default)")
        database_url = settings.DATABASE_URL.lower()
        if (
            "localhost" in database_url
            or "127.0.0.1" in database_url
            or "password@" in database_url
            or not any(marker in database_url for marker in ("ssl=require", "ssl=verify-full"))
        ):
            missing.append("DATABASE_URL (remote database with TLS and non-default credentials required)")
        if not settings.REDIS_URL.startswith("rediss://"):
            missing.append("REDIS_URL (TLS-protected Redis URL required)")
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


def _trace_id(request: Request) -> str:
    value = getattr(request.state, "trace_id", None)
    return value if isinstance(value, str) else str(uuid4())


@app.exception_handler(HTTPException)
async def http_error_contract(request: Request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        error_code = str(detail.get("error_code") or detail.get("error") or f"http_{exc.status_code}")
        message = str(detail.get("message") or "Request rejected")
    else:
        error_code = f"http_{exc.status_code}"
        message = detail if isinstance(detail, str) else "Request rejected"
    body = APIErrorV1(
        error_code=error_code,
        message=message,
        trace_id=_trace_id(request),
        retryable=exc.status_code == 429 or exc.status_code >= 500,
        detail=detail,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=body.model_dump(mode="json", exclude_none=True),
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_error_contract(request: Request, exc: RequestValidationError):
    # Do not echo rejected request values: prompts and completions can contain secrets/PII.
    safe_errors = [
        {
            "loc": [str(part) for part in item.get("loc", [])],
            "msg": str(item.get("msg", "Invalid input")),
            "type": str(item.get("type", "value_error")),
        }
        for item in exc.errors()
    ]
    body = APIErrorV1(
        error_code="validation_error",
        message="Request validation failed",
        trace_id=_trace_id(request),
        retryable=False,
        detail={"errors": safe_errors},
    )
    return JSONResponse(
        status_code=422,
        content=body.model_dump(mode="json", exclude_none=True),
    )

# ── Security Middleware ───────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

if settings.APP_ENV.lower() in {"prod", "production"}:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS,
    )


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """Attach a validated UUID trace ID to logs and every HTTP response."""
    incoming = request.headers.get("X-Request-ID", "")
    try:
        trace_id = str(UUID(incoming))
    except (ValueError, TypeError, AttributeError):
        trace_id = str(uuid4())
    request.state.trace_id = trace_id
    logger.info(
        "http_request_started",
        trace_id=trace_id,
        method=request.method,
        path=request.url.path,
    )
    try:
        with bound_contextvars(trace_id=trace_id):
            response = await call_next(request)
    except Exception as exc:
        logger.error(
            "unhandled_http_request",
            trace_id=trace_id,
            error_type=type(exc).__name__,
        )
        body = APIErrorV1(
            error_code="internal_error",
            message="Internal server error",
            trace_id=UUID(trace_id),
            retryable=True,
        )
        response = JSONResponse(status_code=500, content=body.model_dump(mode="json"))
    response.headers["X-Request-ID"] = trace_id
    logger.info(
        "http_request_completed",
        trace_id=trace_id,
        status_code=response.status_code,
    )
    return response


# ── Routes ────────────────────────────────────────────────────────────
app.include_router(health.router, tags=["Health"])
app.include_router(detect.router, prefix="/api/v1/detect", tags=["Detection"])
app.include_router(monitor.router, prefix="/api/v1/monitor", tags=["Monitor"])
app.include_router(enforce.router, prefix="/api/v1/enforce", tags=["Enforcement"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
