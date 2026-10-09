"""
AI Shield — SIEM Exporter
===========================
Exports detection events to SIEM platforms.

Formats supported (matching ThreatFade + ReconOS OFE):
  - JSON          (default, all tiers)
  - CSV           (Starter+)
  - Splunk HEC    (Pro+)
  - CEF           (Pro+)
  - STIX 2.1      (Enterprise — matches ReconOS OFE format)

This module is a direct port of ThreatFade's siem_exporter.py
with the STIX 2.1 layer from ReconOS OFE added on top.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone

import httpx
import structlog

from backend.core.config import settings
from backend.core.shield_engine import ShieldVerdict

logger = structlog.get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _verdict_to_dict(verdict: ShieldVerdict, tenant_id: str | None = None) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "tenant_id": tenant_id,
        "action": verdict.action,
        "severity": verdict.severity,
        "blocked": verdict.blocked,
        "detections": [
            {
                "detector": r.detector,
                "detected": r.detected,
                "severity": r.severity,
                "confidence": r.confidence,
                "mitre_atlas": r.mitre_atlas,
            }
            for r in verdict.results if r.detected
        ],
    }


# ── JSON ──────────────────────────────────────────────────────────────
def to_json(verdict: ShieldVerdict, tenant_id: str | None = None) -> str:
    return json.dumps(_verdict_to_dict(verdict, tenant_id), indent=2)


# ── CSV ───────────────────────────────────────────────────────────────
def to_csv(verdict: ShieldVerdict, tenant_id: str | None = None) -> str:
    d = _verdict_to_dict(verdict, tenant_id)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "timestamp", "tenant_id", "action", "severity", "blocked"])
    writer.writeheader()
    writer.writerow({k: d[k] for k in ["id", "timestamp", "tenant_id", "action", "severity", "blocked"]})
    return output.getvalue()


# ── CEF ───────────────────────────────────────────────────────────────
def to_cef(verdict: ShieldVerdict, tenant_id: str | None = None) -> str:
    d = _verdict_to_dict(verdict, tenant_id)
    severity_map = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1, "clean": 0}
    cef_severity = severity_map.get(verdict.severity, 5)
    return (
        f"CEF:0|Tinlance|AIShield|0.1.0|AI_THREAT_DETECTED|AI Shield Detection|{cef_severity}|"
        f"rt={d['timestamp']} "
        f"dvchost=aishield "
        f"cs1={d['action']} cs1Label=Action "
        f"cs2={d['severity']} cs2Label=Severity "
        f"cs3={tenant_id or 'unknown'} cs3Label=TenantID"
    )


# ── Splunk HEC ────────────────────────────────────────────────────────
async def to_splunk_hec(verdict: ShieldVerdict, tenant_id: str | None = None) -> bool:
    """POST detection event to Splunk HTTP Event Collector."""
    if not settings.SPLUNK_HEC_URL or not settings.SPLUNK_HEC_TOKEN:
        logger.warning("splunk_hec_not_configured")
        return False

    payload = {
        "time": datetime.now(timezone.utc).timestamp(),
        "sourcetype": "ai_shield:detection",
        "source": "aishield",
        "event": _verdict_to_dict(verdict, tenant_id),
    }

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.post(
                settings.SPLUNK_HEC_URL,
                headers={"Authorization": f"Splunk {settings.SPLUNK_HEC_TOKEN}"},
                json=payload,
            )
            response.raise_for_status()
            logger.info("splunk_hec_exported", status=response.status_code)
            return True
        except Exception as e:
            logger.error("splunk_hec_failed", error=str(e))
            return False


# ── STIX 2.1 (Enterprise — ReconOS OFE format) ────────────────────────
def to_stix21(verdict: ShieldVerdict, tenant_id: str | None = None) -> dict:
    """
    Generate a STIX 2.1 bundle for the detection event.
    Format matches ReconOS OFE STIX export for cross-product consistency.
    """
    d = _verdict_to_dict(verdict, tenant_id)
    bundle_id = f"bundle--{uuid.uuid4()}"
    indicator_id = f"indicator--{uuid.uuid4()}"
    report_id = f"report--{uuid.uuid4()}"

    detectors = [r["detector"] for r in d["detections"]]
    mitre_refs = []
    for r in d["detections"]:
        mitre_refs.extend(r.get("mitre_atlas", []))

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": d["timestamp"],
                "modified": d["timestamp"],
                "name": f"AI Shield Detection — {d['severity'].upper()}",
                "description": f"Detected by: {', '.join(detectors)}. Action: {d['action']}.",
                "pattern": "[ai-traffic:content MATCHES 'threat']",
                "pattern_type": "stix",
                "valid_from": d["timestamp"],
                "labels": ["malicious-activity", "ai-threat"],
                "external_references": [
                    {"source_name": "mitre-atlas", "external_id": mid}
                    for mid in set(mitre_refs)
                ],
            },
            {
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": d["timestamp"],
                "modified": d["timestamp"],
                "name": f"AI Shield Incident Report — {d['id']}",
                "published": d["timestamp"],
                "object_refs": [indicator_id],
                "labels": ["threat-report"],
                "x_tinlance_tenant": tenant_id,
                "x_tinlance_action": d["action"],
                "x_tinlance_blocked": d["blocked"],
            },
        ],
    }
