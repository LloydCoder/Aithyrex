"""
Aithyrex — AI Security Threat Mapping Report Generator
===================================================
Generates a structured mapping report linking Aithyrex
detectors to MITRE ATLAS and ATT&CK techniques.

Outputs:
  - JSON (machine-readable, SIEM import)
  - Markdown (GitHub-ready, human-readable)
  - CSV (for compliance spreadsheets)

Usage:
    python -m backend.core.mitre_report
    # Outputs to docs/mitre-atlas-mapping.md + JSON + CSV

CLI:
    aithyrex mitre-report --format markdown
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class CoverageEntry:
    technique_id: str
    technique_name: str
    tactic: str
    framework: str            # "ATLAS" or "ATT&CK"
    detector: str
    detector_method: str
    coverage_level: str       # "heuristic" | "planned"
    sprint: str               # When this was/will be implemented
    notes: str = ""
    attck_ref: Optional[str] = None


# ── Technique mapping (not a coverage or effectiveness claim) ─────────────────
COVERAGE_MAP: list[CoverageEntry] = [

    # ── MITRE ATLAS techniques ────────────────────────────────────────────────
    CoverageEntry(
        technique_id="AML.T0051",
        technique_name="LLM Prompt Injection",
        tactic="Initial Access",
        framework="ATLAS",
        detector="prompt_injection",
        detector_method="11 compiled regex patterns covering direct override, persona hijack, DAN mode, system tag injection, jailbreak triggers",
        coverage_level="heuristic",
        sprint="Sprint 1",
        notes="Direct injection. Indirect/RAG injection partially covered by data_poisoning detector.",
    ),
    CoverageEntry(
        technique_id="AML.T0048",
        technique_name="Exfiltration via ML Inference API",
        tactic="Exfiltration",
        framework="ATLAS",
        detector="covert_channel + credential_leak",
        detector_method="Entropy/encoding heuristics plus credential-format pattern matching; not independently validated as complete coverage",
        coverage_level="heuristic",
        sprint="Sprint 1",
        notes="Heuristics flag selected encoded/high-entropy patterns and credential formats; AI-specific effectiveness is not measured.",
        attck_ref="T1041",
    ),
    CoverageEntry(
        technique_id="AML.T0020",
        technique_name="Poison Training Data",
        tactic="Persistence",
        framework="ATLAS",
        detector="data_poisoning",
        detector_method="RAG context poisoning patterns, training data extraction fishing, context overflow detection, tool output injection scanning",
        coverage_level="heuristic",
        sprint="Sprint 4",
        notes="Context poisoning via 4-layer detection pipeline. Training weight poisoning not in scope (offline, not runtime).",
    ),
    CoverageEntry(
        technique_id="AML.T0040",
        technique_name="ML Model Inference API Access",
        tactic="Discovery",
        framework="ATLAS",
        detector="data_poisoning + c2_behaviour",
        detector_method="Training data extraction patterns + ThreatFade C2 pipeline",
        coverage_level="heuristic",
        sprint="Sprint 1/4",
        notes="Pattern-based extraction-probing heuristic; detection coverage and false-positive rate are not established.",
    ),
    CoverageEntry(
        technique_id="AML.T0043",
        technique_name="Craft Adversarial Data",
        tactic="Defense Evasion",
        framework="ATLAS",
        detector="covert_channel",
        detector_method="Unicode steganography detection, zero-width character scanning, base64/hex blob detection",
        coverage_level="heuristic",
        sprint="Sprint 1",
        notes="Selected encoded-payload heuristics only; image/audio adversarial examples are not covered by this mapping.",
    ),
    CoverageEntry(
        technique_id="AML.T0054",
        technique_name="LLM Jailbreak",
        tactic="Defense Evasion",
        framework="ATLAS",
        detector="prompt_injection",
        detector_method="DAN mode, developer mode, jailbreak keyword patterns",
        coverage_level="heuristic",
        sprint="Sprint 1",
        notes="Mapped to prompt-injection patterns; technique-level coverage is not established.",
    ),

    # ── MITRE ATT&CK cross-references ────────────────────────────────────────
    CoverageEntry(
        technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        framework="ATT&CK",
        detector="covert_channel",
        detector_method="ThreatFade entropy analysis, base64/hex/Unicode encoding detection in LLM completions",
        coverage_level="heuristic",
        sprint="Sprint 1",
        notes="Mapping only. Network-traffic results do not validate AI-text detection accuracy.",
    ),
    CoverageEntry(
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        framework="ATT&CK",
        detector="c2_behaviour",
        detector_method="ThreatFade C2 signal plus local heuristic mapping",
        coverage_level="heuristic",
        sprint="Sprint 1",
        notes="Intended relevance mapping only; AI-agent C2 detection effectiveness is not validated.",
    ),
    CoverageEntry(
        technique_id="T1095",
        technique_name="Non-Application Layer Protocol",
        tactic="Command and Control",
        framework="ATT&CK",
        detector="c2_behaviour",
        detector_method="ThreatFade QUIC/non-standard protocol detection",
        coverage_level="heuristic",
        sprint="Sprint 1",
        notes="Mapping only. Protocol-specific network findings do not establish AI-interaction detection coverage.",
    ),
    CoverageEntry(
        technique_id="T1552",
        technique_name="Unsecured Credentials",
        tactic="Credential Access",
        framework="ATT&CK",
        detector="credential_leak",
        detector_method="Locally maintained credential-format heuristics for common provider and token formats",
        coverage_level="heuristic",
        sprint="Sprint 1",
        notes="Pattern matching is heuristic and requires an independent credential test corpus.",
    ),
    CoverageEntry(
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        framework="ATT&CK",
        detector="covert_channel + c2_behaviour",
        detector_method="ThreatFade entropy + credential leak patterns",
        coverage_level="heuristic",
        sprint="Sprint 1",
        notes="Intended exfiltration mapping only; representative AI-interaction validation is required.",
    ),
]


def generate_json() -> str:
    """Generate machine-readable JSON coverage report."""
    return json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "product": "Aithyrex v0.1.0",
        "vendor": "Tinlance Limited",
        "total_techniques": len(COVERAGE_MAP),
        "full_coverage": 0,
        "mapped_techniques": len(COVERAGE_MAP),
        "assurance_note": "Technique mappings do not prove implementation completeness or detection effectiveness. All entries are heuristic mappings until validated by a reproducible test corpus.",
        "partial_coverage": sum(1 for e in COVERAGE_MAP if e.coverage_level == "partial"),
        "planned_coverage": sum(1 for e in COVERAGE_MAP if e.coverage_level == "planned"),
        "frameworks": {
            "ATLAS": sum(1 for e in COVERAGE_MAP if e.framework == "ATLAS"),
            "ATT&CK": sum(1 for e in COVERAGE_MAP if e.framework == "ATT&CK"),
        },
        "coverage": [
            {
                "technique_id": e.technique_id,
                "technique_name": e.technique_name,
                "tactic": e.tactic,
                "framework": e.framework,
                "detector": e.detector,
                "method": e.detector_method,
                "coverage_level": e.coverage_level,
                "sprint": e.sprint,
                "notes": e.notes,
                "attck_ref": e.attck_ref,
            }
            for e in COVERAGE_MAP
        ],
    }, indent=2)


def generate_markdown() -> str:
    """Generate a mapping report with explicit limits on assurance claims."""
    atlas = [e for e in COVERAGE_MAP if e.framework == "ATLAS"]
    attck = [e for e in COVERAGE_MAP if e.framework == "ATT&CK"]

    lines = [
        "# Aithyrex AI Security Threat Mapping Report",
        "",
        f"> Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "> Product: Aithyrex v0.1.0 | Vendor: Tinlance Limited",
        "> Assurance status: heuristic mappings only; no full-coverage or effectiveness claim.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Techniques mapped | {len(COVERAGE_MAP)} |",
        "| Full coverage claims | 0 |",
        f"| MITRE ATLAS mappings | {len(atlas)} |",
        f"| MITRE ATT&CK mappings | {len(attck)} |",
        "",
        "Technique mappings describe intended relevance only. They do not prove that a detector reliably detects a technique, that every variant is covered, or that false positives/negatives are bounded.",
        "",
        "## MITRE ATLAS mappings",
        "",
        "| Technique ID | Name | Tactic | Detector | Mapping status |",
        "|---|---|---|---|---|",
    ]

    for e in atlas:
        lines.append(
            f"| {e.technique_id} | {e.technique_name} | {e.tactic} | {e.detector} | {e.coverage_level} |"
        )

    lines += [
        "",
        "## MITRE ATT&CK mappings",
        "",
        "| Technique ID | Name | Tactic | Detector | Mapping status |",
        "|---|---|---|---|---|",
    ]
    for e in attck:
        lines.append(
            f"| {e.technique_id} | {e.technique_name} | {e.tactic} | {e.detector} | {e.coverage_level} |"
        )

    lines += ["", "## Mapping details", ""]
    for e in COVERAGE_MAP:
        lines += [
            f"### {e.technique_id} — {e.technique_name}",
            "",
            f"Framework: {e.framework}",
            f"Tactic: {e.tactic}",
            f"Detector: {e.detector}",
            f"Mapping status: {e.coverage_level}",
            f"Implementation milestone label: {e.sprint}",
            "",
            f"Method: {e.detector_method}",
            "",
        ]
        if e.notes:
            lines.extend([f"Qualification: {e.notes}", ""])
        if e.attck_ref:
            lines.extend([f"Related ATT&CK reference: {e.attck_ref}", ""])

    lines += [
        "## Validation status",
        "",
        "No AI-text detection accuracy, precision, recall, false-positive rate, or complete framework coverage is asserted by this report. ThreatFade network-traffic results are not evidence of AI-text detection performance. Each mapping must be validated against a versioned, representative adversarial corpus before an effectiveness claim is made.",
        "",
        "## Evidence required to upgrade a mapping",
        "",
        "- Versioned test cases tied to the technique and detector version.",
        "- Representative benign and malicious examples, including adversarial variants.",
        "- Reproducible precision, recall, false-positive and false-negative measurements.",
        "- Documented environment, thresholds, limitations and residual risks.",
        "",
        "© 2026 Tinlance Limited — Apache-2.0",
    ]
    return "\n".join(lines)


def generate_csv() -> str:
    """Generate CSV for compliance spreadsheets."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "technique_id", "technique_name", "tactic", "framework",
        "detector", "coverage_level", "sprint", "notes",
    ])
    writer.writeheader()
    for e in COVERAGE_MAP:
        writer.writerow({
            "technique_id": e.technique_id,
            "technique_name": e.technique_name,
            "tactic": e.tactic,
            "framework": e.framework,
            "detector": e.detector,
            "coverage_level": e.coverage_level,
            "sprint": e.sprint,
            "notes": e.notes,
        })
    return output.getvalue()


def write_reports(output_dir: str = "docs") -> dict[str, str]:
    """Write all formats to disk. Returns dict of path → format."""
    import os
    os.makedirs(f"{output_dir}", exist_ok=True)

    paths = {}

    md_path = f"{output_dir}/mitre-atlas-mapping.md"
    with open(md_path, "w") as f:
        f.write(generate_markdown())
    paths[md_path] = "markdown"

    json_path = f"{output_dir}/mitre-atlas-mapping.json"
    with open(json_path, "w") as f:
        f.write(generate_json())
    paths[json_path] = "json"

    csv_path = f"{output_dir}/mitre-atlas-mapping.csv"
    with open(csv_path, "w") as f:
        f.write(generate_csv())
    paths[csv_path] = "csv"

    return paths


if __name__ == "__main__":
    paths = write_reports()
    for path, fmt in paths.items():
        print(f"✅ {fmt}: {path}")
