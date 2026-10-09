"""
AI Shield — MITRE ATLAS Mapper
================================
Maps AI Shield detections to MITRE ATLAS (Adversarial Threat Landscape
for Artificial-Intelligence Systems) technique IDs.

ATLAS is the AI-specific extension of MITRE ATT&CK.
See: https://atlas.mitre.org

Also cross-references to ATT&CK where applicable (ThreatFade mappings).

Full coverage table: docs/mitre-atlas-mapping.md
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ATLASTechnique:
    id: str
    name: str
    tactic: str
    description: str
    attck_ref: str | None = None   # Cross-reference to ATT&CK


ATLAS_TECHNIQUES: dict[str, ATLASTechnique] = {
    "AML.T0051": ATLASTechnique(
        id="AML.T0051",
        name="LLM Prompt Injection",
        tactic="Initial Access",
        description="Adversary crafts malicious inputs to hijack LLM behaviour.",
    ),
    "AML.T0048": ATLASTechnique(
        id="AML.T0048",
        name="Exfiltration via ML Inference API",
        tactic="Exfiltration",
        description="Adversary uses ML model inference to exfiltrate data.",
        attck_ref="T1041",
    ),
    "AML.T0020": ATLASTechnique(
        id="AML.T0020",
        name="Poison Training Data",
        tactic="Persistence",
        description="Adversary poisons training data to influence model behaviour.",
    ),
    "AML.T0040": ATLASTechnique(
        id="AML.T0040",
        name="ML Model Inference API Access",
        tactic="Discovery",
        description="Adversary interacts with ML model via inference API.",
    ),
    "AML.T0043": ATLASTechnique(
        id="AML.T0043",
        name="Craft Adversarial Data",
        tactic="Defense Evasion",
        description="Adversary crafts inputs to evade ML-based defences.",
    ),
    # ATT&CK cross-references (from ThreatFade mappings)
    "T1027": ATLASTechnique(
        id="T1027",
        name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        description="Adversary obfuscates content to avoid detection.",
    ),
    "T1071.001": ATLASTechnique(
        id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        description="Adversary uses HTTP/S for C2 communications.",
    ),
    "T1095": ATLASTechnique(
        id="T1095",
        name="Non-Application Layer Protocol",
        tactic="Command and Control",
        description="Adversary uses non-standard protocol for C2.",
    ),
    "T1552": ATLASTechnique(
        id="T1552",
        name="Unsecured Credentials",
        tactic="Credential Access",
        description="Adversary searches for or obtains unsecured credentials.",
    ),
}


def get_technique(technique_id: str) -> ATLASTechnique | None:
    return ATLAS_TECHNIQUES.get(technique_id)


def enrich_detection(mitre_ids: list[str]) -> list[dict]:
    """Return full technique details for a list of MITRE IDs."""
    results = []
    for mid in mitre_ids:
        technique = get_technique(mid)
        if technique:
            results.append({
                "id": technique.id,
                "name": technique.name,
                "tactic": technique.tactic,
                "attck_ref": technique.attck_ref,
            })
    return results
