"""Privacy-safe, tamper-evident compliance evidence export primitives.

Exports are evidence artifacts, not legal assessments, regulatory submissions, or
proof of delivery. Raw prompts, completions and detector detail blobs are excluded.
"""
from __future__ import annotations
import csv
import hashlib
import io
import json
import math
import re
import uuid
from datetime import datetime, timezone
from typing import Any

EXPORT_SCHEMA = "aithyrex.compliance-evidence-export.v1"
EVIDENCE_SCHEMA = "aithyrex.compliance-evidence.v1"
_ALLOWED_ACTIONS = {"pass", "log", "alert", "block"}
_ALLOWED_SEVERITIES = {"clean", "info", "low", "medium", "high", "critical"}
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")


def _iso_utc(value: Any) -> str | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _identifier(value: Any, *, fallback: str = "unknown") -> str:
    if not isinstance(value, str):
        return fallback
    value = value.strip()
    return value if _SAFE_IDENTIFIER.fullmatch(value) else fallback


def _safe_model(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable()).strip()
    return cleaned if _SAFE_MODEL.fullmatch(cleaned) else None


def _safe_length(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, min(int(value), 2_147_483_647))
    except (TypeError, ValueError, OverflowError):
        return 0


def _safe_confidence(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        return None
    return round(number, 6)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_export_envelope(
    event: Any,
    *,
    tenant_id: str,
    report_id: str | None = None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a deterministic evidence digest over allow-listed persisted fields."""
    event_id = str(getattr(event, "id", ""))
    event_created_at = _iso_utc(getattr(event, "created_at", None))
    findings: list[dict[str, Any]] = []
    raw_results = getattr(event, "results", None)
    if isinstance(raw_results, list):
        for item in raw_results:
            if not isinstance(item, dict) or item.get("detected") is not True:
                continue
            raw_mitre = item.get("mitre_atlas")
            mitre_ids = sorted({
                _identifier(value)
                for value in raw_mitre
                if isinstance(value, str) and _identifier(value) != "unknown"
            }) if isinstance(raw_mitre, list) else []
            raw_severity = str(item.get("severity", "unknown")).lower()
            findings.append({
                "detector": _identifier(item.get("detector")),
                "severity": raw_severity if raw_severity in _ALLOWED_SEVERITIES else "unknown",
                "confidence": _safe_confidence(item.get("confidence")),
                "confidence_calibrated": False,
                "mitre_atlas": mitre_ids,
            })
    findings.sort(key=lambda finding: (finding["detector"], finding["severity"], finding["mitre_atlas"]))
    raw_action = str(getattr(event, "action", "unknown")).lower()
    raw_event_severity = str(getattr(event, "severity", "unknown")).lower()
    evidence = {
        "schema_version": EVIDENCE_SCHEMA,
        "tenant_id": _identifier(tenant_id),
        "event_id": _identifier(event_id),
        "event_created_at": event_created_at,
        "model": _safe_model(getattr(event, "model", None)),
        "prompt_length": _safe_length(getattr(event, "prompt_len", 0)),
        "completion_length": _safe_length(getattr(event, "completion_len", 0)),
        "action": raw_action if raw_action in _ALLOWED_ACTIONS else "unknown",
        "severity": raw_event_severity if raw_event_severity in _ALLOWED_SEVERITIES else "unknown",
        "blocked": getattr(event, "blocked", False) is True,
        "findings": findings,
    }
    digest = hashlib.sha256(_canonical_json(evidence).encode("utf-8")).hexdigest()
    generated_at = generated_at or datetime.now(timezone.utc)
    return {
        "schema_version": EXPORT_SCHEMA,
        "report_id": report_id or str(uuid.uuid4()),
        "generated_at": _iso_utc(generated_at),
        "evidence_digest": digest,
        "evidence": evidence,
        "submission": {
            "status": "not_submitted",
            "legal_submission_performed": False,
            "regulatory_assessment": "not_performed",
        },
    }


def render_json(envelope: dict[str, Any]) -> str:
    return json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    if text[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        text = "'" + text
    return text.replace("\r", " ").replace("\n", " ")


def render_csv(envelope: dict[str, Any]) -> str:
    evidence = envelope["evidence"]
    findings = evidence["findings"] or [{}]
    fields = [
        "schema_version", "report_id", "generated_at", "evidence_digest",
        "tenant_id", "event_id", "event_created_at", "model", "action",
        "severity", "blocked", "prompt_length", "completion_length",
        "detector", "finding_severity", "confidence", "confidence_calibrated",
        "mitre_atlas", "submission_status", "legal_submission_performed",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for finding in findings:
        row = {
            "schema_version": envelope["schema_version"],
            "report_id": envelope["report_id"],
            "generated_at": envelope["generated_at"],
            "evidence_digest": envelope["evidence_digest"],
            **evidence,
            "detector": finding.get("detector", ""),
            "finding_severity": finding.get("severity", ""),
            "confidence": finding.get("confidence", ""),
            "confidence_calibrated": finding.get("confidence_calibrated", ""),
            "mitre_atlas": ",".join(finding.get("mitre_atlas", [])),
            "submission_status": envelope["submission"]["status"],
            "legal_submission_performed": envelope["submission"]["legal_submission_performed"],
        }
        row["blocked"] = str(row["blocked"]).lower()
        row["legal_submission_performed"] = str(row["legal_submission_performed"]).lower()
        writer.writerow({key: _csv_safe(row.get(key)) for key in fields})
    return output.getvalue()


def _markdown_cell(value: Any) -> str:
    return _csv_safe(value).replace("|", "\\|")


def render_markdown(envelope: dict[str, Any]) -> str:
    evidence = envelope["evidence"]
    lines = [
        "# Aithyrex Compliance Evidence Export",
        "",
        f"- Schema: {envelope['schema_version']}",
        f"- Report ID: {_markdown_cell(envelope['report_id'])}",
        f"- Generated at: {_markdown_cell(envelope['generated_at'])}",
        f"- Evidence SHA-256: {envelope['evidence_digest']}",
        "- Submission status: **NOT SUBMITTED**",
        "- Legal submission performed: **No**",
        "- Regulatory assessment performed: **No**",
        "",
        "## Persisted event",
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    for key in (
        "tenant_id", "event_id", "event_created_at", "model", "action",
        "severity", "blocked", "prompt_length", "completion_length",
    ):
        lines.append(f"| {key} | {_markdown_cell(evidence.get(key))} |")
    lines.extend(["", "## Detected findings", "", "| Detector | Severity | Confidence | Calibrated | MITRE ATLAS |", "|---|---|---:|---|---|"])
    for finding in evidence["findings"]:
        lines.append(
            "| " + " | ".join(_markdown_cell(value) for value in (
                finding["detector"], finding["severity"], finding["confidence"],
                finding["confidence_calibrated"], ", ".join(finding["mitre_atlas"]),
            )) + " |"
        )
    if not evidence["findings"]:
        lines.append("| None | — | — | — | — |")
    lines.extend([
        "",
        "> This artifact is a technical evidence export only. It is not legal advice, a regulatory determination, a submitted notification, or proof of delivery.",
        "",
    ])
    return "\n".join(lines)
