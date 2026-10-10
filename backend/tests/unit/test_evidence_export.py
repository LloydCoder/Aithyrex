from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

from backend.compliance.evidence_export import (
    _csv_safe,
    build_export_envelope,
    render_csv,
    render_json,
    render_markdown,
)


def sample_event(**overrides):
    values = {
        "id": UUID("00000000-0000-4000-8000-000000000001"),
        "created_at": datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc),
        "model": "gpt-4o",
        "prompt_len": 120,
        "completion_len": 45,
        "action": "block",
        "severity": "critical",
        "blocked": True,
        "results": [
            {
                "detector": "credential_leak",
                "detected": True,
                "severity": "critical",
                "confidence": 0.99,
                "mitre_atlas": ["T1552", "AML.T0048"],
                "details": {"raw_match": "must never be exported"},
            },
            {
                "detector": "prompt_injection",
                "detected": False,
                "severity": "clean",
                "confidence": 0.0,
                "mitre_atlas": [],
            },
        ],
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_evidence_digest_is_stable_across_export_instances():
    event = sample_event()
    first = build_export_envelope(
        event,
        tenant_id="00000000-0000-4000-8000-000000000002",
        report_id="report-one",
        generated_at=datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc),
    )
    second = build_export_envelope(
        event,
        tenant_id="00000000-0000-4000-8000-000000000002",
        report_id="report-two",
        generated_at=datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc),
    )
    assert first["evidence_digest"] == second["evidence_digest"]
    assert len(first["evidence_digest"]) == 64
    assert first["report_id"] != second["report_id"]


def test_export_excludes_raw_detector_details_and_unflagged_results():
    envelope = build_export_envelope(sample_event(), tenant_id="tenant-safe")
    serialized = render_json(envelope)
    assert "must never be exported" not in serialized
    assert "raw_match" not in serialized
    assert len(envelope["evidence"]["findings"]) == 1
    assert envelope["evidence"]["findings"][0]["detector"] == "credential_leak"
    assert envelope["evidence"]["findings"][0]["confidence_calibrated"] is False


def test_export_explicitly_disclaims_submission_and_assessment():
    envelope = build_export_envelope(sample_event(), tenant_id="tenant-safe")
    assert envelope["submission"] == {
        "status": "not_submitted",
        "legal_submission_performed": False,
        "regulatory_assessment": "not_performed",
    }
    assert "NOT SUBMITTED" in render_markdown(envelope)
    assert "not legal advice" in render_markdown(envelope)


def test_csv_export_neutralizes_formula_prefixes():
    event = sample_event(model='=HYPERLINK("https://attacker.invalid")')
    envelope = build_export_envelope(event, tenant_id="tenant-safe")
    csv_text = render_csv(envelope)
    assert "HYPERLINK" not in csv_text
    assert _csv_safe('=HYPERLINK("https://attacker.invalid")').startswith("'=HYPERLINK")
    assert _csv_safe("   =1+1").startswith("'   =1+1")
    assert _csv_safe("\t@SUM(1,1)").startswith("'\t@SUM(1,1)")
    assert envelope["evidence"]["model"] is None


def test_invalid_confidence_and_identifiers_are_safely_normalized():
    event = sample_event(results=[{
        "detector": "raw detector name with spaces",
        "detected": True,
        "severity": "unexpected",
        "confidence": float("nan"),
        "mitre_atlas": ["T1552", "bad technique id"],
        "details": {"secret": "never exported"},
    }])
    envelope = build_export_envelope(event, tenant_id="tenant safe")
    finding = envelope["evidence"]["findings"][0]
    assert finding["detector"] == "unknown"
    assert finding["severity"] == "unknown"
    assert finding["confidence"] is None
    assert finding["mitre_atlas"] == ["T1552"]
    assert envelope["evidence"]["tenant_id"] == "unknown"
