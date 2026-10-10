"""
Aithyrex — Detection Routes
==============================
POST /detect/llm      — analyse a prompt + completion pair
POST /detect/prompt   — pre-flight prompt-only check (before sending to LLM)
POST /detect/agent    — analyse agentic AI communication stream

All routes require verified Clerk auth and server-side tenant entitlements.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator
import structlog

from backend.core.auth import TokenPayload, get_current_tenant
from backend.core.contracts import APIErrorV1, DetectorEvidenceV1, FindingV1
from backend.core.platform_action_auth import (
    action_payload_sha256,
    canonical_action_payload_bytes,
    decode_platform_action_assertion,
)
from backend.core.shield_engine import Action, Severity, ShieldEngine, ShieldVerdict

router = APIRouter()
engine = ShieldEngine()
logger = structlog.get_logger(__name__)


# ── Request / Response schemas ────────────────────────────────────────────────
class LLMInspectRequest(BaseModel):
    prompt: str = Field(max_length=100_000)
    completion: str | None = Field(default=None, max_length=100_000)
    model: str | None = Field(default=None, max_length=256)


MAX_AGENT_MESSAGE_COUNT = 100
MAX_AGENT_MESSAGE_CHARS = 20_000
MAX_AGENT_TOTAL_CHARS = 200_000


class AgentMessage(BaseModel):
    role: str | None = Field(default=None, max_length=64)
    source: str | None = Field(default=None, max_length=64)
    content: str = Field(default="", max_length=MAX_AGENT_MESSAGE_CHARS)


class AgentInspectRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=255)
    messages: list[AgentMessage] = Field(max_length=MAX_AGENT_MESSAGE_COUNT)

    @model_validator(mode="after")
    def enforce_total_content_limit(self) -> "AgentInspectRequest":
        total_chars = sum(len(message.content) for message in self.messages)
        if total_chars > MAX_AGENT_TOTAL_CHARS:
            raise ValueError("Total agent message content exceeds the inspection limit")
        return self


class DetectionResponse(BaseModel):
    schema_version: Literal["aithyrex.detection-response.v1"] = "aithyrex.detection-response.v1"
    trace_id: str
    finding_id: str
    degraded: bool = False
    finding: FindingV1
    action: str
    severity: str
    blocked: bool
    detections: list[dict]
    tenant_id: str
    inferences_used: int = 0


class PromptDetectionResponse(BaseModel):
    schema_version: Literal["aithyrex.detection-response.v1"] = "aithyrex.detection-response.v1"
    trace_id: str
    finding_id: str
    degraded: bool = False
    finding: FindingV1
    action: str
    blocked: bool
    severity: str
    tenant_id: str


class AgentDetectionResponse(PromptDetectionResponse):
    agent_id: str
    turns_analysed: int
    detections: list[dict]


MAX_ACTION_PAYLOAD_BYTES = 100_000


class AgentActionInspectionRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=255)
    action_id: str = Field(min_length=1, max_length=255)
    tool_name: str = Field(min_length=1, max_length=256)
    arguments: dict[str, Any] = Field(default_factory=dict)
    context: str | None = Field(default=None, max_length=20_000)

    @model_validator(mode="after")
    def enforce_action_payload_limit(self) -> "AgentActionInspectionRequest":
        try:
            payload = canonical_action_payload_bytes(self.tool_name, self.arguments, self.context)
        except (TypeError, ValueError) as exc:
            raise ValueError("Action payload must be valid canonical JSON") from exc
        if len(payload) > MAX_ACTION_PAYLOAD_BYTES:
            raise ValueError("Action payload exceeds the inspection limit")
        return self


class AgentActionSignalResponse(BaseModel):
    schema_version: Literal["aithyrex.agent-action-signal.v1"] = "aithyrex.agent-action-signal.v1"
    trace_id: str
    finding_id: str
    tenant_id: str
    agent_id: str
    action_id: str
    tool_name: str
    assertion_jti: str
    detected: bool
    severity: str
    degraded: bool
    advisory_only: Literal[True] = True
    authorization_performed: Literal[False] = False
    execution_performed: Literal[False] = False
    finding: FindingV1


def _build_finding(verdict: ShieldVerdict, tenant_id: str, trace_id: str) -> FindingV1:
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
    return FindingV1(
        trace_id=trace_id,
        tenant_id=tenant_id,
        action=verdict.action.value if hasattr(verdict.action, "value") else str(verdict.action),
        severity=verdict.severity.value if hasattr(verdict.severity, "value") else str(verdict.severity),
        blocked=verdict.blocked,
        degraded=degraded,
        evidence=evidence,
        provenance={"component": "aithyrex-api"},
    )


# ── Routes ────────────────────────────────────────────────────────────────────
@router.post(
    "/llm",
    response_model=DetectionResponse,
    responses={
        422: {"model": APIErrorV1, "description": "Invalid request"},
        429: {"model": APIErrorV1, "description": "Tenant rate limit exceeded"},
        503: {"model": APIErrorV1, "description": "Required dependency unavailable"},
    },
)
async def detect_llm(
    req: LLMInspectRequest,
    request: Request,
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
):
    """
    Inspect a prompt/completion pair for threats.
    Returns ShieldVerdict — action, severity, per-detector results.
    """
    verdict: ShieldVerdict = await engine.inspect(
        prompt=req.prompt,
        completion=req.completion,
        tenant_id=tenant.tenant_id,
        model=req.model,
        plan=tenant.plan,
    )

    finding = _build_finding(verdict, tenant.tenant_id, request.state.trace_id)
    return DetectionResponse(
        trace_id=request.state.trace_id,
        finding_id=str(finding.finding_id),
        degraded=finding.degraded,
        finding=finding,
        action=verdict.action,
        severity=verdict.severity,
        blocked=verdict.blocked,
        tenant_id=tenant.tenant_id,
        detections=[
            {
                "detector": r.detector,
                "detected": r.detected,
                "severity": r.severity,
                "confidence": r.confidence,
                "mitre_atlas": r.mitre_atlas,
                "details": r.details,
            }
            for r in verdict.results
            if r.detected
        ],
    )


@router.post(
    "/prompt",
    response_model=PromptDetectionResponse,
    responses={
        403: {"model": APIErrorV1, "description": "Prompt blocked by detection policy"},
        422: {"model": APIErrorV1, "description": "Invalid request"},
        503: {"model": APIErrorV1, "description": "Required dependency unavailable"},
    },
)
async def detect_prompt(
    req: LLMInspectRequest,
    request: Request,
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
):
    """
    Pre-flight prompt check — run BEFORE sending to LLM.
    Returns 403 if blocked, 200 with {blocked: false} if clean.
    """
    verdict: ShieldVerdict = await engine.inspect(
        prompt=req.prompt,
        completion=None,
        tenant_id=tenant.tenant_id,
        plan=tenant.plan,
    )

    finding = _build_finding(verdict, tenant.tenant_id, request.state.trace_id)

    # Pre-flight: block on any detection (ALERT or BLOCK).
    # This is stricter than /detect/llm, which preserves the detector action.
    should_block = (
        verdict.blocked or
        verdict.action == Action.ALERT or
        verdict.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM)
    )

    actionable_detections = [
        result for result in verdict.results
        if result.detected and not result.details.get("advisory_only", False)
    ]
    if verdict.blocked or (should_block and actionable_detections):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "blocked": True,
                "reason": verdict.severity,
                "action": verdict.action,
                "detectors_fired": [
                    r.detector for r in verdict.results if r.detected
                ],
                "error_code": "detection_blocked",
                "message": "Aithyrex blocked this prompt.",
                "trace_id": request.state.trace_id,
                "finding_id": str(finding.finding_id),
                "finding": finding.model_dump(mode="json"),
            },
        )

    finding = _build_finding(verdict, tenant.tenant_id, request.state.trace_id)
    return {
        "schema_version": "aithyrex.detection-response.v1",
        "trace_id": request.state.trace_id,
        "finding_id": str(finding.finding_id),
        "finding": finding.model_dump(mode="json"),
        "degraded": finding.degraded,
        "action": verdict.action,
        "blocked": False,
        "severity": verdict.severity,
        "tenant_id": tenant.tenant_id,
    }


@router.post(
    "/agent",
    response_model=AgentDetectionResponse,
    responses={
        422: {"model": APIErrorV1, "description": "Invalid request"},
        503: {"model": APIErrorV1, "description": "Required dependency unavailable"},
    },
)
async def detect_agent(
    req: AgentInspectRequest,
    request: Request,
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
):
    """
    Analyze supported string content from an agent message list.
    This does not mediate tool calls, MCP operations, or per-turn side effects.
    """
    # Sprint 1 — inspect the concatenated conversation
    # Role/source metadata is accepted for caller compatibility but is not trusted
    # as provenance. Phase 9 introduces authenticated context lineage.
    full_text = " ".join(message.content for message in req.messages if message.content)

    verdict: ShieldVerdict = await engine.inspect(
        prompt=full_text,
        tenant_id=tenant.tenant_id,
        plan=tenant.plan,
    )

    finding = _build_finding(verdict, tenant.tenant_id, request.state.trace_id)
    return {
        "schema_version": "aithyrex.detection-response.v1",
        "trace_id": request.state.trace_id,
        "finding_id": str(finding.finding_id),
        "finding": finding.model_dump(mode="json"),
        "degraded": finding.degraded,
        "agent_id": req.agent_id,
        "tenant_id": tenant.tenant_id,
        "action": verdict.action,
        "severity": verdict.severity,
        "blocked": verdict.blocked,
        "turns_analysed": len(req.messages),
        "detections": [
            {"detector": r.detector, "severity": r.severity}
            for r in verdict.results if r.detected
        ],
    }



async def _resolve_platform_tenant(tenant_id: str):
    """Resolve only active, server-side tenant state for a verified Platform assertion."""
    try:
        tenant_uuid = UUID(tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail={
            "error_code": "invalid_platform_tenant",
            "message": "Platform action assertion tenant is invalid.",
        }) from exc

    try:
        from sqlalchemy import select

        from backend.models.database import AsyncSessionFactory
        from backend.models.models import Tenant

        async with AsyncSessionFactory() as session:
            result = await session.execute(
                select(Tenant).where(
                    Tenant.id == tenant_uuid,
                    Tenant.is_active.is_(True),
                )
            )
            tenant = result.scalar_one_or_none()
    except Exception as exc:
        logger.error(
            "platform_action_tenant_resolution_failed",
            error_type=type(exc).__name__,
        )
        raise HTTPException(status_code=503, detail={
            "error_code": "tenant_authorization_state_unavailable",
            "message": "Tenant authorization state is unavailable.",
        }) from exc

    if tenant is None:
        raise HTTPException(status_code=403, detail={
            "error_code": "platform_tenant_not_provisioned",
            "message": "Tenant is not active or provisioned for Aithyrex.",
        })
    if tenant.plan not in {"free", "starter", "pro", "enterprise"}:
        raise HTTPException(status_code=503, detail={
            "error_code": "invalid_tenant_entitlement_state",
            "message": "Tenant entitlement state is invalid.",
        })
    return tenant


@router.post(
    "/action",
    response_model=AgentActionSignalResponse,
    responses={
        401: {"model": APIErrorV1, "description": "Missing or invalid Platform assertion"},
        403: {"model": APIErrorV1, "description": "Action payload does not match signed assertion"},
        422: {"model": APIErrorV1, "description": "Invalid action inspection request"},
        503: {"model": APIErrorV1, "description": "Platform assertion or tenant state unavailable"},
    },
)
async def detect_agent_action(
    req: AgentActionInspectionRequest,
    request: Request,
    platform_assertion: Annotated[str | None, Header(alias="X-Platform-Action-Assertion")] = None,
):
    """Inspect a Platform-bound tool/action payload and emit a signal only.

    This endpoint neither authorizes nor executes the action. The Platform remains
    the sole authority for action binding, approvals, policy and governed execution.
    """
    if not platform_assertion:
        raise HTTPException(status_code=401, detail={
            "error_code": "missing_platform_action_assertion",
            "message": "A signed Platform action assertion is required.",
        })

    claims = decode_platform_action_assertion(platform_assertion)
    payload_hash = action_payload_sha256(req.tool_name, req.arguments, req.context)
    if (
        claims["sub"] != req.agent_id
        or claims["action_id"] != req.action_id
        or claims["tool_name"] != req.tool_name
        or claims["action_payload_sha256"] != payload_hash
    ):
        raise HTTPException(status_code=403, detail={
            "error_code": "platform_action_binding_mismatch",
            "message": "Action fields do not match the signed Platform assertion.",
        })

    tenant = await _resolve_platform_tenant(claims["tenant_id"])
    tenant_id = str(tenant.id)
    payload_text = canonical_action_payload_bytes(req.tool_name, req.arguments, req.context).decode("utf-8")

    # Run detection without applying tenant usage limits or exposing an allow/block
    # decision. A finding is evidence for the Platform; it is not an execution grant.
    verdict: ShieldVerdict = await engine.inspect(
        prompt=payload_text,
        completion=None,
        tenant_id=None,
        plan="enterprise",
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
    finding = FindingV1(
        trace_id=trace_id,
        tenant_id=tenant_id,
        action="log",
        severity=severity,
        blocked=False,
        degraded=degraded,
        evidence=evidence,
        provenance={
            "component": "aithyrex-platform-action-signal",
            "advisory_only": True,
            "authorization_performed": False,
            "execution_performed": False,
            "agent_id": req.agent_id,
            "action_id": req.action_id,
            "tool_name": req.tool_name,
            "platform_assertion_jti": claims["jti"],
            "action_payload_sha256": payload_hash,
        },
    )
    return AgentActionSignalResponse(
        trace_id=str(trace_id),
        finding_id=str(finding.finding_id),
        tenant_id=tenant_id,
        agent_id=req.agent_id,
        action_id=req.action_id,
        tool_name=req.tool_name,
        assertion_jti=claims["jti"],
        detected=detected,
        severity=severity,
        degraded=degraded,
        finding=finding,
    )
