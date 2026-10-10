"""
Aithyrex — Detection Routes
==============================
POST /detect/llm      — analyse a prompt + completion pair
POST /detect/prompt   — pre-flight prompt-only check (before sending to LLM)
POST /detect/agent    — analyse agentic AI communication stream

All routes require verified Clerk auth and server-side tenant entitlements.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator

from backend.core.auth import TokenPayload, get_current_tenant
from backend.core.contracts import APIErrorV1, DetectorEvidenceV1, FindingV1
from backend.core.shield_engine import Action, Severity, ShieldEngine, ShieldVerdict

router = APIRouter()
engine = ShieldEngine()


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
