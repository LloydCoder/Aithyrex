"""
AI Shield — Clerk Auth Middleware
===================================
JWT verification via Clerk.
Extracts tenant_id and plan from the token.
Protects all routes except /health.

Pattern reused from KalevioAI auth implementation.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Annotated

import httpx
import structlog
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = structlog.get_logger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)


# ── Token payload ─────────────────────────────────────────────────────────────
class TokenPayload:
    """Decoded Clerk JWT payload."""

    def __init__(
        self,
        tenant_id: str,
        user_id: str,
        plan: str = "free",
        org_id: str | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.plan = plan
        self.org_id = org_id

    def __repr__(self) -> str:
        return f"<TokenPayload tenant={self.tenant_id} plan={self.plan}>"


# ── Clerk JWKS cache ──────────────────────────────────────────────────────────
@lru_cache(maxsize=1)
def _get_clerk_secret() -> str:
    from backend.core.config import settings
    return settings.CLERK_SECRET_KEY


async def _verify_clerk_token(token: str) -> dict:
    """
    Verify a Clerk session token.
    Uses Clerk's /oauth/token/info endpoint for validation.

    In production: use PyJWT with Clerk JWKS endpoint.
    For MVP: forward to Clerk's verify endpoint.
    """
    clerk_secret = _get_clerk_secret()

    if not clerk_secret or clerk_secret == "":
        # Dev mode — accept any token, extract basic claims
        logger.warning("clerk_dev_mode", token_prefix=token[:10])
        return {
            "sub": "dev_user",
            "org_id": "dev_org",
            "metadata": {"plan": "pro"},
        }

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.get(
                "https://api.clerk.com/v1/sessions/verify",
                headers={
                    "Authorization": f"Bearer {clerk_secret}",
                    "Content-Type": "application/json",
                },
                params={"token": token},
            )
            if response.status_code == 200:
                return response.json()
            logger.warning("clerk_verify_failed", status=response.status_code)
            return {}
        except httpx.TimeoutException:
            logger.error("clerk_timeout")
            return {}


async def get_current_tenant(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(bearer_scheme),
    ] = None,
) -> TokenPayload:
    """
    FastAPI dependency — returns authenticated tenant.
    Raises 401 if token missing or invalid.

    Usage:
        @router.post("/detect/llm")
        async def detect(tenant: TokenPayload = Depends(get_current_tenant)):
            ...
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims = await _verify_clerk_token(credentials.credentials)

    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract org_id as tenant identifier (Clerk org = AI Shield tenant)
    org_id = claims.get("org_id") or claims.get("sub", "unknown")
    user_id = claims.get("sub", "unknown")

    # Plan stored in Clerk public metadata
    metadata = claims.get("public_metadata", claims.get("metadata", {}))
    plan = metadata.get("plan", "free") if isinstance(metadata, dict) else "free"

    return TokenPayload(
        tenant_id=org_id,
        user_id=user_id,
        plan=plan,
        org_id=org_id,
    )


# Optional auth — returns None if no token (for public endpoints)
async def get_optional_tenant(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(bearer_scheme),
    ] = None,
) -> TokenPayload | None:
    """Returns None if no token present — for public/partially-public routes."""
    if credentials is None:
        return None
    try:
        return await get_current_tenant(credentials)
    except HTTPException:
        return None
