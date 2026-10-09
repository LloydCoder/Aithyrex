"""
AI Shield — Unit Tests: SIEM Exporter
=======================================
Tests all 5 export formats.
"""

import json
import pytest
from unittest.mock import AsyncMock, patch

from backend.core.shield_engine import (
    Action, DetectionResult, Severity, ShieldVerdict
)
from backend.exporters.siem_exporter import (
    to_json, to_csv, to_cef, to_stix21
)


@pytest.fixture
def clean_verdict():
    return ShieldVerdict(
        action=Action.PASS,
        severity=Severity.CLEAN,
        results=[
            DetectionResult(
                detector="prompt_injection",
                detected=False,
                severity=Severity.CLEAN,
                confidence=0.0,
            )
        ],
    )


@pytest.fixture
def critical_verdict():
    return ShieldVerdict(
        action=Action.BLOCK,
        severity=Severity.CRITICAL,
        blocked=True,
        results=[
            DetectionResult(
                detector="credential_leak",
                detected=True,
                severity=Severity.CRITICAL,
                confidence=0.99,
                mitre_atlas=["T1552", "AML.T0048"],
                details={"matches": [{"pattern": "paystack_secret"}]},
            )
        ],
    )


# ── JSON export ───────────────────────────────────────────────────────────────
def test_json_export_is_valid_json(critical_verdict):
    output = to_json(critical_verdict, "tenant-123")
    parsed = json.loads(output)
    assert parsed["action"] == "block"
    assert parsed["severity"] == "critical"
    assert parsed["blocked"] is True
    assert "id" in parsed
    assert "timestamp" in parsed


def test_json_export_includes_tenant(clean_verdict):
    output = to_json(clean_verdict, "my-tenant")
    parsed = json.loads(output)
    assert parsed["tenant_id"] == "my-tenant"


def test_json_export_detections_list(critical_verdict):
    parsed = json.loads(to_json(critical_verdict, "t"))
    assert len(parsed["detections"]) == 1
    assert parsed["detections"][0]["detector"] == "credential_leak"


# ── CSV export ────────────────────────────────────────────────────────────────
def test_csv_export_has_header(critical_verdict):
    output = to_csv(critical_verdict, "tenant-123")
    assert "id" in output
    assert "severity" in output
    assert "action" in output


def test_csv_export_has_data_row(critical_verdict):
    lines = to_csv(critical_verdict, "tenant-123").strip().split("\n")
    assert len(lines) == 2   # header + data


# ── CEF export ────────────────────────────────────────────────────────────────
def test_cef_export_format(critical_verdict):
    output = to_cef(critical_verdict, "tenant-123")
    assert output.startswith("CEF:0|Tinlance|AIShield")
    assert "rt=" in output
    assert "cs1=" in output   # Action field


def test_cef_severity_critical_is_10(critical_verdict):
    output = to_cef(critical_verdict, "tenant-123")
    assert "|10|" in output


# ── STIX 2.1 export ───────────────────────────────────────────────────────────
def test_stix21_bundle_structure(critical_verdict):
    bundle = to_stix21(critical_verdict, "tenant-123")
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert len(bundle["objects"]) == 2   # indicator + report


def test_stix21_includes_mitre_references(critical_verdict):
    bundle = to_stix21(critical_verdict, "tenant-123")
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    ext_refs = indicator.get("external_references", [])
    assert any(r["source_name"] == "mitre-atlas" for r in ext_refs)


def test_stix21_tenant_in_report(critical_verdict):
    bundle = to_stix21(critical_verdict, "tenant-xyz")
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert report.get("x_tinlance_tenant") == "tenant-xyz"
    assert report.get("x_tinlance_blocked") is True
