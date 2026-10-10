"""Signed, provenance-aware context inspection. Findings remain advisory only."""
from __future__ import annotations

import hashlib
from typing import Annotated, Literal
from uuid import UUID

import structlog
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.api.routes.detect import _resolve_platform_tenant
from backend.core.contracts import DetectorEvidenceV1, FindingV1
from backend.core.platform_context_auth import (
    canonical_context_bundle_bytes,
    context_bundle_sha256,
    decode_platform_context_assertion,
)
from backend.core.rate_limiter import rate_limiter
from backend.core.shield_engine import ShieldEngine, ShieldVerdict
from backend.core.usage_counter import usage_counter

router = APIRouter()
logger = structlog.get_logger(__name__)
engine = ShieldEngine()

MAX_CONTEXT_ITEMS = 32
MAX_CONTEXT_ITEM_CHARS = 20_000
MAX_CONTEXT_TOTAL_CHARS = 200_000
MAX_CONTEXT_BUNDLE_BYTES = 250_000
SourceType = Literal["retrieved_document", "tool_output", "memory", "user_input", "model_output"]


class ContextItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_type: SourceType
    source_id: str = Field(min_length=1, max_length=255)
    content: str = Field(max_length=MAX_CONTEXT_ITEM_CHARS)


class ContextInspectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=255)
    context_id: str = Field(min_length=1, max_length=255)
    items: list[ContextItem] = Field(min_length=1, max_length=MAX_CONTEXT_ITEMS)

    @model_validator(mode="after")
    def enforce_context_bounds(self) -> "ContextInspectionRequest":
        if sum(len(item.content) for item in self.items) > MAX_CONTEXT_TOTAL_CHARS:
            raise ValueError("Context bundle exceeds the aggregate inspection limit")
        try:
            payload = canonical_context_bundle_bytes(
                self.agent_id, self.context_id, [item.model_dump() for item in self.items]
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("Context bundle is not canonical JSON") from exc
        if len(payload) > MAX_CONTEXT_BUNDLE_BYTES:
            raise ValueError("Context bundle exceeds the UTF-8 byte limit")
        return self


class ContextSourceEvidence(BaseModel):
    source_type: SourceType
    source_id: str
    content_sha256: str
    trust_boundary: Literal["untrusted"] = "untrusted"


class ContextSignalResponse(BaseModel):
    schema_version: Literal["aithyrex.context-inspection.v1"] = "aithyrex.context-inspection.v1"
    trace_id: str
    finding_id: str
    tenant_id: str
    agent_id: str
    context_id: str
    assertion_jti: str
    detected: bool
    severity: str
    degraded: bool
    advisory_only: Literal[True] = True
    authorization_performed: Literal[False] = False
    execution_performed: Literal[False] = False
    sources: list[ContextSourceEvidence]
    finding: FindingV1


@router.post("/context", response_model=ContextSignalResponse)
async def inspect_context(
    req: ContextInspectionRequest,
    request: Request,
    platform_assertion: Annotated[str | None, Header(alias="X-Platform-Context-Assertion")] = None,
):
    """Inspect a signed context bundle; never treat provenance as trust or permission."""
    if not platform_assertion:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "missing_platform_context_assertion",
                "message": "A signed Platform context assertion is required.",
            },
        )
    claims = decode_platform_context_assertion(platform_assertion)
    items = [item.model_dump() for item in req.items]
    bundle_hash = context_bundle_sha256(req.agent_id, req.context_id, items)
    if (
        claims["sub"] != req.agent_id
        or claims["context_id"] != req.context_id
        or claims["context_bundle_sha256"] != bundle_hash
    ):
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "platform_context_binding_mismatch",
                "message": "Context bundle does not match the signed Platform assertion.",
            },
        )

    tenant = await _resolve_platform_tenant(claims["tenant_id"])
    tenant_id = str(tenant.id)
    try:
        await rate_limiter.enforce(tenant_id)
        usage_allowed, _count, _limit = await usage_counter.reserve_inference(
            tenant_id, tenant.plan
        )
    except HTTPException:
        raise
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "context_inspection_capacity_unavailable",
                "message": "Context inspection capacity state is unavailable.",
            },
        ) from exc
    if not usage_allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error_code": "context_inspection_usage_limit_reached",
                "message": "Context inspection usage limit reached.",
            },
        )

    # Scan content only; metadata is retained as signed provenance, not inserted
    # into model-facing text. Source labels do not make content trusted.
    content = "\n\n".join(item.content for item in req.items)
    verdict: ShieldVerdict = await engine.inspect(
        prompt=content, completion=None, tenant_id=None, plan="enterprise"
    )
    evidence = [
        DetectorEvidenceV1(
            detector=result.detector,
            detected=result.detected,
            severity=result.severity.value if hasattr(result.severity, "value") else str(result.severity),
            confidence=result.confidence,
            mitre_atlas=result.mitre_atlas,
            details=result.details,
        )
        for result in verdict.results
    ]
    degraded = any(bool(result.details.get("degraded")) for result in verdict.results)
    detected = any(result.detected or result.details.get("degraded") for result in verdict.results)
    severity = verdict.severity.value if hasattr(verdict.severity, "value") else str(verdict.severity)
    trace_id = UUID(request.state.trace_id)
    sources = [
        ContextSourceEvidence(
            source_type=item.source_type,
            source_id=item.source_id,
            content_sha256=hashlib.sha256(item.content.encode("utf-8")).hexdigest(),
            trust_boundary="untrusted",
        )
        for item in req.items
    ]
    finding = FindingV1(
        trace_id=trace_id,
        tenant_id=tenant_id,
        action="log",
        severity=severity,
        blocked=False,
        degraded=degraded,
        evidence=evidence,
        provenance={
            "component": "aithyrex-context-signal",
            "context_id": req.context_id,
            "agent_id": req.agent_id,
            "assertion_jti": claims["jti"],
            "context_bundle_sha256": bundle_hash,
            "source_count": len(sources),
            "source_types": sorted({item.source_type for item in req.items}),
            "source_evidence": [source.model_dump() for source in sources],
            "trust_boundary": "untrusted",
            "advisory_only": True,
            "authorization_performed": False,
            "execution_performed": False,
        },
    )
    logger.info(
        "context_inspection_completed",
        trace_id=str(trace_id),
        tenant_id=tenant_id,
        context_id=req.context_id,
        source_count=len(sources),
        detected=detected,
        degraded=degraded,
    )
    return ContextSignalResponse(
        trace_id=str(trace_id),
        finding_id=str(finding.finding_id),
        tenant_id=tenant_id,
        agent_id=req.agent_id,
        context_id=req.context_id,
        assertion_jti=claims["jti"],
        detected=detected,
        severity=severity,
        degraded=degraded,
        sources=sources,
        finding=finding,
    )
