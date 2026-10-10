"""Versioned, evidence-bearing API contracts for Aithyrex."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class DetectorEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["aithyrex.detector-evidence.v1"] = "aithyrex.detector-evidence.v1"
    detector: str = Field(min_length=1, max_length=128)
    detected: bool
    severity: Literal["clean", "info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_atlas: list[str] = Field(default_factory=list, max_length=64)
    details: dict[str, Any] = Field(default_factory=dict)


class FindingV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["aithyrex.finding.v1"] = "aithyrex.finding.v1"
    finding_id: UUID = Field(default_factory=uuid4)
    trace_id: UUID
    tenant_id: str = Field(min_length=1, max_length=255)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action: Literal["pass", "log", "alert", "block"]
    severity: Literal["clean", "info", "low", "medium", "high", "critical"]
    blocked: bool
    degraded: bool = False
    source: Literal["api", "sdk", "gateway"] = "api"
    evidence: list[DetectorEvidenceV1] = Field(default_factory=list, max_length=64)
    provenance: dict[str, Any] = Field(default_factory=dict)


class APIErrorV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["aithyrex.error.v1"] = "aithyrex.error.v1"
    error_code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=500)
    trace_id: UUID
    retryable: bool
    detail: Any | None = None
