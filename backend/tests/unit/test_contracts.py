from uuid import UUID

import pytest
from pydantic import ValidationError

from backend.core.contracts import APIErrorV1, DetectorEvidenceV1, FindingV1


def test_finding_v1_generates_stable_identifiers_and_provenance():
    trace_id = UUID("12345678-1234-4234-8234-123456789abc")
    finding = FindingV1(
        trace_id=trace_id,
        tenant_id="tenant-1",
        action="block",
        severity="critical",
        blocked=True,
        degraded=False,
        evidence=[
            DetectorEvidenceV1(
                detector="credential_leak",
                detected=True,
                severity="critical",
                confidence=1.0,
                mitre_atlas=["AML.T0051"],
                details={"source": "completion"},
            )
        ],
        provenance={"component": "aithyrex-api"},
    )
    assert finding.schema_version == "aithyrex.finding.v1"
    assert finding.trace_id == trace_id
    assert finding.finding_id
    assert finding.evidence[0].schema_version == "aithyrex.detector-evidence.v1"
    assert finding.model_dump(mode="json")["action"] == "block"


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_detector_evidence_rejects_invalid_confidence(confidence):
    with pytest.raises(ValidationError):
        DetectorEvidenceV1(
            detector="prompt_injection",
            detected=True,
            severity="high",
            confidence=confidence,
        )


def test_error_contract_is_versioned_and_safe():
    error = APIErrorV1(
        error_code="validation_error",
        message="Request validation failed",
        trace_id=UUID("12345678-1234-4234-8234-123456789abc"),
        retryable=False,
        detail={"errors": [{"loc": ["body", "prompt"], "msg": "too long", "type": "string_too_long"}]},
    )
    assert error.schema_version == "aithyrex.error.v1"
    assert "input" not in str(error.model_dump(mode="json"))
