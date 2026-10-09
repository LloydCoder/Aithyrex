"""Clerk authentication for Aithyrex API routes."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

import httpx
import structlog
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = structlog.get_logger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)


class TokenPayload:
    """Verified identity and tenant claims extracted from a Clerk session."""

    def __init__(self, tenant_id: str, user_id: str, plan: str = "free", org_id: str | None = None) -> None:
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.plan = plan
        self.org_id = org_id

    def __repr__(self) -> str:
        return f"<TokenPayload tenant={self.tenant_id} plan={self.plan}>"


@lru_cache(maxsize=1)
def _get_clerk_secret() -> str:
    from backend.core.config import settings
    return settings.CLERK_SECRET_KEY


async def _verify_clerk_token(token: str) -> dict:
    """Verify a session token with Clerk; never accept arbitrary tokens by default."""
    from backend.core.config import settings

    clerk_secret = _get_clerk_secret()
    if not clerk_secret:
        if settings.APP_ENV.lower() == "development" and settings.ALLOW_INSECURE_DEV_AUTH:
            logger.warning("explicit_insecure_development_auth_enabled")
            return {"sub": "dev_user", "org_id": "dev_org", "public_metadata": {"plan": "free"}}
        logger.error("clerk_auth_not_configured")
        return {}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                "https://api.clerk.com/v1/sessions/verify",
                headers={
                    "Authorization": f"Bearer {clerk_secret}",
                    "Content-Type": "application/json",
                },
                json={"token": token},
            )
            if response.status_code != 200:
                logger.warning("clerk_verify_failed", status=response.status_code)
                return {}
            claims = response.json()
            if not isinstance(claims, dict) or not claims.get("sub"):
                logger.warning("clerk_verify_missing_subject")
                return {}
            return claims
    except (httpx.TimeoutException, httpx.HTTPError) as exc:
        logger.error("clerk_verification_unavailable", error_type=type(exc).__name__)
        return {}


async def get_current_tenant(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)] = None,
) -> TokenPayload:
    """FastAPI dependency that rejects missing, invalid, or unverifiable credentials."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authorization token", headers={"WWW-Authenticate": "Bearer"})
    claims = await _verify_clerk_token(credentials.credentials)
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid, expired, or unverifiable token", headers={"WWW-Authenticate": "Bearer"})
    org_id = claims.get("org_id")
    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token subject")
    tenant_id = org_id or user_id
    metadata = claims.get("public_metadata", {})
    plan = metadata.get("plan", "free") if isinstance(metadata, dict) else "free"
    if plan not in {"free", "starter", "pro", "enterprise"}:
        logger.warning("unknown_plan_claim_fallback", plan=plan)
        plan = "free"
    return TokenPayload(tenant_id=tenant_id, user_id=user_id, plan=plan, org_id=org_id)


async def get_optional_tenant(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)] = None,
) -> TokenPayload | None:
    """Optional authentication for endpoints explicitly designed to be public."""
    if credentials is None:
        return None
    try:
        return await get_current_tenant(credentials)
    except HTTPException:
        return None
