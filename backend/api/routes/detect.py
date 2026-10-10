"""
Aithyrex — Detection Routes
==============================
POST /detect/llm      — analyse a prompt + completion pair
POST /detect/prompt   — pre-flight prompt-only check (before sending to LLM)
POST /detect/agent    — analyse agentic AI communication stream

All routes require Clerk auth. Plan extracted from JWT for tier enforcement.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from backend.core.auth import TokenPayload, get_current_tenant
from backend.core.contracts import DetectorEvidenceV1, FindingV1
from backend.core.shield_engine import Action, ShieldEngine, ShieldVerdict

router = APIRouter()
engine = ShieldEngine()


# ── Request / Response schemas ────────────────────────────────────────────────
class LLMInspectRequest(BaseModel):
    prompt: str = Field(max_length=100_000)
    completion: str | None = Field(default=None, max_length=100_000)
    model: str | None = Field(default=None, max_length=256)


class AgentInspectRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=255)
    messages: list[dict] = Field(max_length=1_000)


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
@router.post("/llm", response_model=DetectionResponse)
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


@router.post("/prompt")
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

    # Pre-flight: block on any detection (ALERT or BLOCK)
    # This is stricter than /detect/llm which only hard-blocks on CRITICAL
    from backend.core.shield_engine import Severity
    should_block = (
        verdict.blocked or
        verdict.action == Action.ALERT or
        verdict.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM)
    )

    if verdict.blocked or (should_block and any(r.detected for r in verdict.results)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "blocked": True,
                "reason": verdict.severity,
                "action": verdict.action,
                "detectors_fired": [
                    r.detector for r in verdict.results if r.detected
                ],
                "message": "Aithyrex blocked this prompt.",
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


@router.post("/agent")
async def detect_agent(
    req: AgentInspectRequest,
    request: Request,
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
):
    """
    Analyse a full agentic AI message stream.
    Inspects each turn for injection and C2 indicators.
    Sprint 2: full per-turn inspection.
    """
    # Sprint 1 — inspect the concatenated conversation
    full_text = " ".join(
        m.get("content", "") for m in req.messages
        if isinstance(m.get("content"), str)
    )

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
        "action": verdict.action,
        "severity": verdict.severity,
        "blocked": verdict.blocked,
        "turns_analysed": len(req.messages),
        "detections": [
            {"detector": r.detector, "severity": r.severity}
            for r in verdict.results if r.detected
        ],
    }
