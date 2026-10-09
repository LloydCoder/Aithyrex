"""Clerk JWT authentication for Aithyrex API routes."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

import jwt
import structlog
from fastapi import HTTPException, Security
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
def _get_settings():
    from backend.core.config import settings
    return settings


async def _verify_clerk_token(token: str) -> dict:
    """Verify Clerk JWT signature and standard claims locally; fail closed on config/errors."""
    settings = _get_settings()
    if not settings.CLERK_JWT_KEY or not settings.CLERK_JWT_ISSUER:
        logger.error("clerk_jwt_verification_not_configured")
        return {}
    try:
        options = {"verify_aud": bool(settings.CLERK_JWT_AUDIENCE)}
        claims = jwt.decode(
            token,
            settings.CLERK_JWT_KEY,
            algorithms=["RS256"],
            issuer=settings.CLERK_JWT_ISSUER,
            audience=settings.CLERK_JWT_AUDIENCE or None,
            options=options,
        )
        if not isinstance(claims, dict) or not claims.get("sub"):
            logger.warning("clerk_jwt_missing_subject")
            return {}
        authorized_parties = settings.CLERK_AUTHORIZED_PARTIES
        if authorized_parties and claims.get("azp") not in authorized_parties:
            logger.warning("clerk_jwt_unauthorized_party")
            return {}
        return claims
    except jwt.InvalidTokenError as exc:
        logger.warning("clerk_jwt_invalid", error_type=type(exc).__name__)
        return {}
    except Exception as exc:
        logger.error("clerk_jwt_verification_error", error_type=type(exc).__name__)
        return {}


async def get_current_tenant(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)] = None,
) -> TokenPayload:
    """FastAPI dependency rejecting missing, invalid, expired, or unverifiable credentials."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authorization token", headers={"WWW-Authenticate": "Bearer"})
    claims = await _verify_clerk_token(credentials.credentials)
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid, expired, or unverifiable token", headers={"WWW-Authenticate": "Bearer"})
    user_id = claims["sub"]
    org_id = claims.get("org_id")
    if not org_id:
        raise HTTPException(status_code=403, detail="An active Clerk organization is required")

    try:
        from sqlalchemy import select

        from backend.models.database import AsyncSessionFactory
        from backend.models.models import Tenant

        async with AsyncSessionFactory() as session:
            result = await session.execute(
                select(Tenant).where(
                    Tenant.clerk_org_id == org_id,
                    Tenant.is_active.is_(True),
                )
            )
            tenant = result.scalar_one_or_none()
        if tenant is None:
            raise HTTPException(status_code=403, detail="Organization is not provisioned for Aithyrex")
        if tenant.plan not in {"free", "starter", "pro", "enterprise"}:
            logger.error("invalid_server_side_tenant_plan", tenant_id=str(tenant.id))
            raise HTTPException(status_code=503, detail="Tenant entitlement state is invalid")
        return TokenPayload(
            tenant_id=str(tenant.id),
            user_id=user_id,
            plan=tenant.plan,
            org_id=org_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("tenant_resolution_failed", error_type=type(exc).__name__)
        raise HTTPException(status_code=503, detail="Tenant authorization state unavailable") from exc


async def get_optional_tenant(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)] = None,
) -> TokenPayload | None:
    """Optional authentication for endpoints explicitly designed to be public."""
    if credentials is None:
        return None
    return await get_current_tenant(credentials)
