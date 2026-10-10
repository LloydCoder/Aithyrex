"""Verify Platform-signed agent-action assertions for advisory inspection only."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from uuid import UUID

import jwt
from fastapi import HTTPException

from backend.core.config import settings

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_CLAIMS = [
    "exp",
    "iat",
    "iss",
    "aud",
    "sub",
    "jti",
    "tenant_id",
    "action_id",
    "tool_name",
    "action_payload_sha256",
]


def decode_platform_action_assertion(token: str) -> dict[str, Any]:
    """Verify a short-lived RS256 assertion and validate its action-binding claims.

    This authenticates an assertion only. It does not authorize or execute an action.
    """
    key = settings.PLATFORM_ACTION_JWT_PUBLIC_KEY.replace("\\n", "\n").strip()
    issuer = settings.PLATFORM_ACTION_JWT_ISSUER.strip()
    audience = settings.PLATFORM_ACTION_JWT_AUDIENCE.strip()
    if not key or not issuer or not audience:
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "platform_action_auth_not_configured",
                "message": "Platform action assertion verification is not configured.",
            },
        )

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.InvalidTokenError as exc:
        # Never log or echo the assertion token or rejected claims.
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "invalid_platform_action_assertion",
                "message": "Platform action assertion is invalid or expired.",
            },
        ) from exc

    if not isinstance(claims, dict):
        raise HTTPException(status_code=401, detail="Invalid Platform action assertion")

    string_claims = ("sub", "jti", "tenant_id", "action_id", "tool_name", "action_payload_sha256")
    if any(not isinstance(claims.get(name), str) or not claims[name].strip() for name in string_claims):
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "invalid_platform_action_claims",
                "message": "Platform action assertion claims are malformed.",
            },
        )

    if (
        len(claims["sub"]) > 255
        or len(claims["jti"]) > 128
        or len(claims["action_id"]) > 255
        or len(claims["tool_name"]) > 256
        or not _SHA256_RE.fullmatch(claims["action_payload_sha256"])
    ):
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "invalid_platform_action_claims",
                "message": "Platform action assertion claims are malformed.",
            },
        )

    try:
        UUID(claims["tenant_id"])
    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "invalid_platform_action_claims",
                "message": "Platform action assertion claims are malformed.",
            },
        ) from exc

    return claims


def action_payload_sha256(tool_name: str, arguments: dict[str, Any], context: str | None) -> str:
    """Hash the canonical action payload so the signed assertion binds exact inspected content."""
    canonical = json.dumps(
        {"tool_name": tool_name, "arguments": arguments, "context": context or ""},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
