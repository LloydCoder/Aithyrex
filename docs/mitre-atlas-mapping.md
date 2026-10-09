# AI Shield — MITRE ATLAS Coverage

> Generated: 2026-06-20  
> Product: AI Shield v0.1.0 | Vendor: Tinlance Limited

## Summary

| Metric | Value |
|--------|-------|
| Total techniques covered | 11 |
| Full coverage | 8 |
| Partial coverage | 3 |
| MITRE ATLAS techniques | 6 |
| MITRE ATT&CK cross-references | 5 |

---

## MITRE ATLAS Coverage

| Technique ID | Name | Tactic | Detector | Coverage | Sprint |
|---|---|---|---|---|---|
| [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) | LLM Prompt Injection | Initial Access | `prompt_injection` | ✅ full | Sprint 1 |
| [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) | Exfiltration via ML Inference API | Exfiltration | `covert_channel + credential_leak` | ✅ full | Sprint 1 |
| [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) | Poison Training Data | Persistence | `data_poisoning` | ✅ full | Sprint 4 |
| [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) | ML Model Inference API Access | Discovery | `data_poisoning + c2_behaviour` | ⚠️ partial | Sprint 1/4 |
| [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043) | Craft Adversarial Data | Defense Evasion | `covert_channel` | ⚠️ partial | Sprint 1 |
| [AML.T0054](https://atlas.mitre.org/techniques/AML.T0054) | LLM Jailbreak | Defense Evasion | `prompt_injection` | ✅ full | Sprint 1 |

---

## MITRE ATT&CK Cross-References

| Technique ID | Name | Tactic | Detector | Coverage |
|---|---|---|---|---|
| [T1027](https://attack.mitre.org/techniques/T1027) | Obfuscated Files or Information | Defense Evasion | `covert_channel` | ✅ full |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001) | Application Layer Protocol: Web Protocols | Command and Control | `c2_behaviour` | ✅ full |
| [T1095](https://attack.mitre.org/techniques/T1095) | Non-Application Layer Protocol | Command and Control | `c2_behaviour` | ⚠️ partial |
| [T1552](https://attack.mitre.org/techniques/T1552) | Unsecured Credentials | Credential Access | `credential_leak` | ✅ full |
| [T1041](https://attack.mitre.org/techniques/T1041) | Exfiltration Over C2 Channel | Exfiltration | `covert_channel + c2_behaviour` | ✅ full |

---

## Detection Method Details

### AML.T0051 — LLM Prompt Injection

**Framework:** ATLAS  
**Tactic:** Initial Access  
**Detector:** `prompt_injection`  
**Coverage:** full  
**Sprint:** Sprint 1  

**Method:** 11 compiled regex patterns covering direct override, persona hijack, DAN mode, system tag injection, jailbreak triggers

**Notes:** Direct injection. Indirect/RAG injection partially covered by data_poisoning detector.

### AML.T0048 — Exfiltration via ML Inference API

**Framework:** ATLAS  
**Tactic:** Exfiltration  
**Detector:** `covert_channel + credential_leak`  
**Coverage:** full  
**Sprint:** Sprint 1  

**Method:** ThreatFade entropy/Z-score + 18 credential patterns (peer-reviewed, merged to Nuclei/TruffleHog/Gitleaks)

**Notes:** Covert channel detected via entropy anomaly. Credential leak via pattern matching.

**ATT&CK Cross-reference:** T1041

### AML.T0020 — Poison Training Data

**Framework:** ATLAS  
**Tactic:** Persistence  
**Detector:** `data_poisoning`  
**Coverage:** full  
**Sprint:** Sprint 4  

**Method:** RAG context poisoning patterns, training data extraction fishing, context overflow detection, tool output injection scanning

**Notes:** Context poisoning via 4-layer detection pipeline. Training weight poisoning not in scope (offline, not runtime).

### AML.T0040 — ML Model Inference API Access

**Framework:** ATLAS  
**Tactic:** Discovery  
**Detector:** `data_poisoning + c2_behaviour`  
**Coverage:** partial  
**Sprint:** Sprint 1/4  

**Method:** Training data extraction patterns + ThreatFade C2 pipeline

**Notes:** Detects extraction probing. Does not detect benign inference access.

### AML.T0043 — Craft Adversarial Data

**Framework:** ATLAS  
**Tactic:** Defense Evasion  
**Detector:** `covert_channel`  
**Coverage:** partial  
**Sprint:** Sprint 1  

**Method:** Unicode steganography detection, zero-width character scanning, base64/hex blob detection

**Notes:** Detects encoded payloads in completions. Does not cover image/audio adversarial examples.

### AML.T0054 — LLM Jailbreak

**Framework:** ATLAS  
**Tactic:** Defense Evasion  
**Detector:** `prompt_injection`  
**Coverage:** full  
**Sprint:** Sprint 1  

**Method:** DAN mode, developer mode, jailbreak keyword patterns

**Notes:** Covered as a subset of prompt injection detection.

### T1027 — Obfuscated Files or Information

**Framework:** ATT&CK  
**Tactic:** Defense Evasion  
**Detector:** `covert_channel`  
**Coverage:** full  
**Sprint:** Sprint 1  

**Method:** ThreatFade entropy analysis, base64/hex/Unicode encoding detection in LLM completions

**Notes:** Z-score 14.76 validated on Merlin QUIC C2. Same methodology applied to token distributions.

### T1071.001 — Application Layer Protocol: Web Protocols

**Framework:** ATT&CK  
**Tactic:** Command and Control  
**Detector:** `c2_behaviour`  
**Coverage:** full  
**Sprint:** Sprint 1  

**Method:** ThreatFade full C2 pipeline — entropy + Z-score + MITRE TTP mapping

**Notes:** Detects AI agents used as C2 relay channels.

### T1095 — Non-Application Layer Protocol

**Framework:** ATT&CK  
**Tactic:** Command and Control  
**Detector:** `c2_behaviour`  
**Coverage:** partial  
**Sprint:** Sprint 1  

**Method:** ThreatFade QUIC/non-standard protocol detection

**Notes:** Validated against Merlin QUIC traffic. Other non-standard protocols partially covered.

### T1552 — Unsecured Credentials

**Framework:** ATT&CK  
**Tactic:** Credential Access  
**Detector:** `credential_leak`  
**Coverage:** full  
**Sprint:** Sprint 1  

**Method:** 18 regex patterns: AWS, OpenAI, Anthropic, GitHub, Stripe, Paystack, Flutterwave, Remita, Interswitch, JWT, PEM keys

**Notes:** Patterns peer-reviewed via PRs to TruffleHog (15k★), Gitleaks (10k★), Semgrep (11k★).

### T1041 — Exfiltration Over C2 Channel

**Framework:** ATT&CK  
**Tactic:** Exfiltration  
**Detector:** `covert_channel + c2_behaviour`  
**Coverage:** full  
**Sprint:** Sprint 1  

**Method:** ThreatFade entropy + credential leak patterns

**Notes:** Detects data encoded in LLM completions for exfiltration.

---

## Validation Baseline

ThreatFade entropy engine validated against real C2 malware traffic:

| Metric | Value |
|--------|-------|
| Packets analysed | 490,000+ |
| Malware type | Merlin QUIC C2 |
| Z-score detected | 14.76 |
| False positive rate | 0% |

The same Z-score/entropy methodology applied to LLM completions.

---

*© 2026 Tinlance Limited — Apache 2.0*