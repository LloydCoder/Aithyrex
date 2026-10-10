"""Signed behavioral-sequence analysis; deterministic and advisory-only."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

import structlog
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.api.routes.detect import _resolve_platform_tenant
from backend.core.behavioral_correlation import BehaviorEvent, correlate_events
from backend.core.contracts import DetectorEvidenceV1, FindingV1
from backend.core.platform_sequence_auth import (
    sequence_sha256,
    decode_platform_sequence_assertion,
)
from backend.core.rate_limiter import rate_limiter
from backend.core.usage_counter import usage_counter

router = APIRouter()
logger = structlog.get_logger(__name__)

MAX_SEQUENCE_EVENTS = 100
MAX_SEQUENCE_WINDOW_SECONDS = 3600
MAX_FUTURE_CLOCK_SKEW_SECONDS = 30
EventType = Literal[
    "prompt_injection_detected",
    "credential_exposure_detected",
    "sensitive_data_accessed",
    "external_transfer_requested",
    "tool_action_proposed",
    "tool_action_executed",
    "policy_denied",
    "approval_recorded",
]


class BehaviorEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=1, max_length=128)
    event_type: EventType
    occurred_at: datetime
    tool_name: str | None = Field(default=None, max_length=128)
    finding_id: UUID | None = None
    signals: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def validate_event(self) -> "BehaviorEventRequest":
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("Event timestamp must include a timezone")
        if any(not value or len(value) > 128 for value in self.signals):
            raise ValueError("Signal identifiers must be non-empty and bounded")
        return self


class SequenceInspectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=255)
    sequence_id: str = Field(min_length=1, max_length=255)
    events: list[BehaviorEventRequest] = Field(min_length=2, max_length=MAX_SEQUENCE_EVENTS)

    @model_validator(mode="after")
    def validate_sequence(self) -> "SequenceInspectionRequest":
        ids = [event.event_id for event in self.events]
        if len(ids) != len(set(ids)):
            raise ValueError("Event identifiers must be unique within a sequence")
        timestamps = [event.occurred_at for event in self.events]
        if timestamps != sorted(timestamps):
            raise ValueError("Events must be ordered by occurrence time")
        if (timestamps[-1] - timestamps[0]).total_seconds() > MAX_SEQUENCE_WINDOW_SECONDS:
            raise ValueError("Sequence exceeds the one-hour analysis window")
        now = datetime.now(timezone.utc)
        if any(event.occurred_at.astimezone(timezone.utc).timestamp() > now.timestamp() + MAX_FUTURE_CLOCK_SKEW_SECONDS for event in self.events):
            raise ValueError("Event timestamp is too far in the future")
        return self


class CorrelationFindingResponse(BaseModel):
    rule_id: str
    severity: Literal["medium", "high", "critical"]
    first_event_id: str
    second_event_id: str
    window_seconds: int
    description: str
    confidence_calibrated: Literal[False] = False


class SequenceSignalResponse(BaseModel):
    schema_version: Literal["aithyrex.behavioral-correlation.v1"] = "aithyrex.behavioral-correlation.v1"
    trace_id: str
    finding_id: str
    tenant_id: str
    agent_id: str
    sequence_id: str
    sequence_sha256: str
    events_analyzed: int
    detected: bool
    severity: str
    findings: list[CorrelationFindingResponse]
    advisory_only: Literal[True] = True
    authorization_performed: Literal[False] = False
    execution_performed: Literal[False] = False
    finding: FindingV1


@router.post("/sequence", response_model=SequenceSignalResponse)
async def inspect_sequence(
    req: SequenceInspectionRequest,
    request: Request,
    platform_assertion: Annotated[str | None, Header(alias="X-Platform-Sequence-Assertion")] = None,
):
    """Correlate an ordered, signed sequence of event metadata without taking action."""
    if not platform_assertion:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "missing_platform_sequence_assertion",
                "message": "A signed Platform sequence assertion is required.",
            },
        )
    claims = decode_platform_sequence_assertion(platform_assertion)
    events_payload = [event.model_dump(mode="json") for event in req.events]
    digest = sequence_sha256(req.agent_id, req.sequence_id, events_payload)
    if (
        claims["sub"] != req.agent_id
        or claims["sequence_id"] != req.sequence_id
        or claims["sequence_sha256"] != digest
    ):
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "platform_sequence_binding_mismatch",
                "message": "Event sequence does not match the signed Platform assertion.",
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
                "error_code": "sequence_analysis_capacity_unavailable",
                "message": "Sequence analysis capacity state is unavailable.",
            },
        ) from exc
    if not usage_allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error_code": "sequence_analysis_usage_limit_reached",
                "message": "Sequence analysis usage limit reached.",
            },
        )

    events = [
        BehaviorEvent(
            event_id=event.event_id,
            event_type=event.event_type,
            occurred_at=event.occurred_at,
            tool_name=event.tool_name,
        )
        for event in req.events
    ]
    correlated = correlate_events(events)
    severity_order = {"clean": 0, "medium": 1, "high": 2, "critical": 3}
    severity = max((item.severity for item in correlated), key=lambda value: severity_order[value], default="clean")
    detected = bool(correlated)
    trace_id = UUID(request.state.trace_id)
    correlation_responses = [
        CorrelationFindingResponse(
            rule_id=item.rule_id,
            severity=item.severity,
            first_event_id=item.first_event_id,
            second_event_id=item.second_event_id,
            window_seconds=item.window_seconds,
            description=item.description,
            confidence_calibrated=False,
        )
        for item in correlated
    ]
    evidence = [
        DetectorEvidenceV1(
            detector="behavioral_correlation",
            detected=detected,
            severity=severity,
            confidence=0.0,
            mitre_atlas=[],
            details={
                "rule_ids": [item.rule_id for item in correlated],
                "event_ids": sorted({event_id for item in correlated for event_id in (item.first_event_id, item.second_event_id)}),
                "confidence_calibrated": False,
                "correlation_window_seconds": MAX_SEQUENCE_WINDOW_SECONDS,
            },
        )
    ]
    finding = FindingV1(
        trace_id=trace_id,
        tenant_id=tenant_id,
        action="log",
        severity=severity,
        blocked=False,
        evidence=evidence,
        provenance={
            "component": "aithyrex-behavioral-correlation",
            "agent_id": req.agent_id,
            "sequence_id": req.sequence_id,
            "sequence_sha256": digest,
            "assertion_jti": claims["jti"],
            "events_analyzed": len(events),
            "event_ids": [event.event_id for event in events],
            "advisory_only": True,
            "authorization_performed": False,
            "execution_performed": False,
        },
    )
    logger.info(
        "behavioral_sequence_analysis_completed",
        trace_id=str(trace_id),
        tenant_id=tenant_id,
        sequence_id=req.sequence_id,
        events_analyzed=len(events),
        correlation_count=len(correlated),
    )
    return SequenceSignalResponse(
        trace_id=str(trace_id),
        finding_id=str(finding.finding_id),
        tenant_id=tenant_id,
        agent_id=req.agent_id,
        sequence_id=req.sequence_id,
        sequence_sha256=digest,
        events_analyzed=len(events),
        detected=detected,
        severity=severity,
        findings=correlation_responses,
        finding=finding,
    )
