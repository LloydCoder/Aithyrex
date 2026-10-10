# Aithyrex AI Security Threat Mapping Report

> Updated: 2026-10-09
> Product: Aithyrex v0.1.0 | Vendor: Tinlance Limited
> Assurance status: heuristic mappings only; no full-coverage or effectiveness claim.

## Summary

| Metric | Value |
|---|---:|
| Techniques mapped | 11 |
| Full coverage claims | 0 |
| MITRE ATLAS mappings | 6 |
| MITRE ATT&CK mappings | 5 |

Technique mappings describe intended relevance only. They do not prove that a detector reliably detects a technique, that every variant is covered, or that false positives and false negatives are bounded.

## MITRE ATLAS mappings

| Technique ID | Name | Tactic | Detector | Mapping status |
|---|---|---|---|---|
| AML.T0051 | LLM Prompt Injection | Initial Access | prompt_injection | heuristic |
| AML.T0048 | Exfiltration via ML Inference API | Exfiltration | covert_channel + credential_leak | heuristic |
| AML.T0020 | Poison Training Data | Persistence | data_poisoning | heuristic |
| AML.T0040 | ML Model Inference API Access | Discovery | data_poisoning + c2_behaviour | heuristic |
| AML.T0043 | Craft Adversarial Data | Defense Evasion | covert_channel | heuristic |
| AML.T0054 | LLM Jailbreak | Defense Evasion | prompt_injection | heuristic |

## MITRE ATT&CK mappings

| Technique ID | Name | Tactic | Detector | Mapping status |
|---|---|---|---|---|
| T1027 | Obfuscated Files or Information | Defense Evasion | covert_channel | heuristic |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | c2_behaviour | heuristic |
| T1095 | Non-Application Layer Protocol | Command and Control | c2_behaviour | heuristic |
| T1552 | Unsecured Credentials | Credential Access | credential_leak | heuristic |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | covert_channel + c2_behaviour | heuristic |

## Validation status

No AI-text detection accuracy, precision, recall, false-positive rate, or complete framework coverage is asserted by this report. ThreatFade network-traffic results are not evidence of AI-text detection performance.

## Evidence required to upgrade a mapping

- Versioned test cases tied to the technique and detector version.
- Representative benign and malicious examples, including adversarial variants.
- Reproducible precision, recall, false-positive and false-negative measurements.
- Documented environment, thresholds, limitations and residual risks.

© 2026 Tinlance Limited — Apache-2.0
