"""Verify Platform-signed behavioral sequence assertions."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import jwt
from fastapi import HTTPException

from backend.core.config import settings

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_CLAIMS = [
    "exp", "iat", "iss", "aud", "sub", "jti", "tenant_id",
    "sequence_id", "sequence_sha256",
]
MAX_ASSERTION_TTL_SECONDS = 300


def _canonical_timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("Event timestamp must be a datetime or ISO-8601 string")
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Event timestamp must include a timezone")
    return timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds")


def canonical_sequence_bytes(
    agent_id: str, sequence_id: str, events: Sequence[Mapping[str, Any]]
) -> bytes:
    """Serialize ordered event metadata for exact signed binding."""
    normalized_events = []
    for event in events:
        normalized_events.append({
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "occurred_at": _canonical_timestamp(event["occurred_at"]),
            "tool_name": event.get("tool_name"),
            "finding_id": event.get("finding_id"),
            "signals": event.get("signals", []),
        })
    return json.dumps(
        {"agent_id": agent_id, "sequence_id": sequence_id, "events": normalized_events},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def sequence_sha256(
    agent_id: str, sequence_id: str, events: Sequence[Mapping[str, Any]]
) -> str:
    return hashlib.sha256(canonical_sequence_bytes(agent_id, sequence_id, events)).hexdigest()


def decode_platform_sequence_assertion(token: str) -> dict[str, Any]:
    """Verify issuer, audience, signature, claim shape, and bounded token lifetime."""
    key = settings.PLATFORM_ACTION_JWT_PUBLIC_KEY.replace("\\n", "\n").strip()
    issuer = settings.PLATFORM_ACTION_JWT_ISSUER.strip()
    audience = settings.PLATFORM_ACTION_JWT_AUDIENCE.strip()
    if not key or not issuer or not audience:
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "platform_sequence_auth_not_configured",
                "message": "Platform sequence assertion verification is not configured.",
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
                "error_code": "invalid_platform_sequence_assertion",
                "message": "Platform sequence assertion is invalid or expired.",
            },
        ) from exc
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "platform_sequence_auth_misconfigured",
                "message": "Platform sequence assertion verification is misconfigured.",
            },
        ) from exc
    if not isinstance(claims, dict):
        raise HTTPException(status_code=401, detail="Invalid Platform sequence assertion")

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
                "error_code": "invalid_platform_sequence_lifetime",
                "message": "Platform sequence assertion lifetime is invalid.",
            },
        )
    for name, maximum in (
        ("sub", 255), ("jti", 128), ("sequence_id", 255), ("sequence_sha256", 64),
    ):
        value = claims.get(name)
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise HTTPException(
                status_code=401,
                detail={
                    "error_code": "invalid_platform_sequence_claims",
                    "message": "Platform sequence assertion claims are malformed.",
                },
            )
    if not _SHA256_RE.fullmatch(claims["sequence_sha256"]):
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "invalid_platform_sequence_claims",
                "message": "Platform sequence assertion claims are malformed.",
            },
        )
    try:
        UUID(str(claims.get("tenant_id", "")))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "invalid_platform_sequence_claims",
                "message": "Platform sequence assertion claims are malformed.",
            },
        ) from exc
    return claims
