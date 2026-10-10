"""Verify Platform-signed context bundle assertions for advisory inspection only."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

import jwt
from fastapi import HTTPException

from backend.core.config import settings

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ASSERTION_TTL_SECONDS = 300
_REQUIRED_CLAIMS = [
    "exp", "iat", "iss", "aud", "sub", "jti", "tenant_id",
    "context_id", "context_bundle_sha256",
]


def canonical_context_bundle_bytes(
    agent_id: str, context_id: str, items: Sequence[Mapping[str, Any]]
) -> bytes:
    """Serialize content and source metadata deterministically for signed binding."""
    normalized = {
        "agent_id": agent_id,
        "context_id": context_id,
        "items": [
            {
                "source_type": item["source_type"],
                "source_id": item["source_id"],
                "content": item["content"],
            }
            for item in items
        ],
    }
    return json.dumps(
        normalized, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def context_bundle_sha256(
    agent_id: str, context_id: str, items: Sequence[Mapping[str, Any]]
) -> str:
    """Hash the complete canonical bundle, including content and provenance labels."""
    return hashlib.sha256(
        canonical_context_bundle_bytes(agent_id, context_id, items)
    ).hexdigest()


def decode_platform_context_assertion(token: str) -> dict[str, Any]:
    """Verify the Platform assertion. A valid signature is provenance, not authorization."""
    key = settings.PLATFORM_ACTION_JWT_PUBLIC_KEY.replace("\\n", "\n").strip()
    issuer = settings.PLATFORM_ACTION_JWT_ISSUER.strip()
    audience = settings.PLATFORM_ACTION_JWT_AUDIENCE.strip()
    if not key or not issuer or not audience:
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "platform_context_auth_not_configured",
                "message": "Platform context assertion verification is not configured.",
            },
        )
    try:
        claims = jwt.decode(
            token, key, algorithms=["RS256"], issuer=issuer, audience=audience,
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "invalid_platform_context_assertion",
                "message": "Platform context assertion is invalid or expired.",
            },
        ) from exc
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "platform_context_auth_misconfigured",
                "message": "Platform context assertion verification is misconfigured.",
            },
        ) from exc

    if not isinstance(claims, dict):
        raise HTTPException(status_code=401, detail="Invalid Platform context assertion")
    issued_at, expires_at = claims.get("iat"), claims.get("exp")
    if (
        isinstance(issued_at, bool) or not isinstance(issued_at, int)
        or isinstance(expires_at, bool) or not isinstance(expires_at, int)
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_ASSERTION_TTL_SECONDS
    ):
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "invalid_platform_context_lifetime",
                "message": "Platform context assertion lifetime is invalid.",
            },
        )
    for name, maximum in (
        ("sub", 255), ("jti", 128), ("context_id", 255),
        ("context_bundle_sha256", 64),
    ):
        value = claims.get(name)
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise HTTPException(
                status_code=401,
                detail={
                    "error_code": "invalid_platform_context_claims",
                    "message": "Platform context assertion claims are malformed.",
                },
            )
    if not _SHA256_RE.fullmatch(claims["context_bundle_sha256"]):
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "invalid_platform_context_claims",
                "message": "Platform context assertion claims are malformed.",
            },
        )
    try:
        UUID(str(claims.get("tenant_id", "")))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "invalid_platform_context_claims",
                "message": "Platform context assertion claims are malformed.",
            },
        ) from exc
    return claims
