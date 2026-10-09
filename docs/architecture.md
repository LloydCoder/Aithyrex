# AI Shield — Architecture

## Overview

AI Shield is the surveillance layer of the Tinlance AI Security Platform.
It sits between any application and its LLM provider, inspecting every
prompt and completion in real time.

## Connection Map

```
AI SHIELD (Surveillance Layer)
        │
        ├── Detection Layer ──────────────────── ThreatFade v0.2.0
        │     POST /detect/json                  github.com/LloydCoder/tinlance-threatfade
        │     Z-score · Entropy · MITRE ATT&CK   490K+ packets · 0% FP rate
        │
        ├── Intelligence Layer ───────────────── ReconOS OFE
        │     ThreatFade C2 bridge               github.com/Tinlance/reconos-ofe
        │     STIX 2.1 export format             6,277 lines · 129 tests
        │
        ├── Compliance Layer ─────────────────── KalevioAI
        │     POST /incidents                    github.com/Tinlance/kalevio
        │     NIS2/DORA auto-reporting           27 EU member states
        │
        └── Orchestration Layer ──────────────── FusionOps
              SOC dashboard                      github.com/Tinlance/fusionops
              Triage + remediation agents
```

## Deployment Architecture

```
                    ┌─────────────────────┐
                    │     Your LLM App    │
                    └──────────┬──────────┘
                               │  HTTP / SDK wrapper
                    ┌──────────▼──────────┐
                    │     AI Shield       │
                    │  FastAPI Proxy      │
                    │  Port 8002          │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  ThreatFade  │  │  PostgreSQL  │  │    Redis     │
    │  Port 8000   │  │  Port 5432   │  │  Port 6379   │
    └──────────────┘  └──────────────┘  └──────────────┘
              │
    ┌──────────▼──────────┐
    │   LLM Provider API  │
    │   OpenAI / Anthropic│
    │   Groq / Local      │
    └─────────────────────┘
```

## Detection Pipeline

```
Incoming Request (prompt)
        │
        ▼
[1] Prompt Injection Detector     ← regex + semantic (Sprint 1/2)
        │
        ▼
[2] Credential Leak Scanner       ← 18 patterns, FDSE Toolkit
        │
        ▼
[3] Pre-flight verdict
        │
   BLOCK? ──yes──► 403 Forbidden (block mode, Pro+)
        │ no
        ▼
[LLM API call — forwarded]
        │
        ▼
Incoming Response (completion)
        │
        ▼
[4] Covert Channel Detector       ← ThreatFade entropy + Z-score
        │
        ▼
[5] C2 Behaviour Detector         ← ThreatFade full pipeline
        │
        ▼
[6] Credential Leak (completion)  ← same 18 patterns
        │
        ▼
[7] MITRE ATLAS enrichment
        │
        ▼
[8] SIEM export                   ← JSON/CSV/Splunk/CEF/STIX 2.1
        │
        ▼
[9] KalevioAI hook (if threshold) ← NIS2/DORA compliance
        │
        ▼
Response returned to application
```

## File Structure

See the [repo root README](../README.md) for the annotated file structure
and reuse annotations for each file.

## Shared Infrastructure

| Component | Source Repo | Reuse Type |
|-----------|-------------|------------|
| C2 detection engine | ThreatFade | HTTP call |
| NIS2/DORA hooks | KalevioAI | HTTP POST |
| SIEM export (4 formats) | ThreatFade | Direct port |
| STIX 2.1 export | ReconOS OFE | Direct port |
| FastAPI skeleton | KalevioAI | Scaffold copy |
| Multi-tenant auth | KalevioAI | Direct reuse |
| LemonSqueezy billing | KalevioAI/GiftMode | Direct reuse |
| Credential patterns (18) | FDSE Toolkit | Direct port |
| Detection YAML rules | OSS PRs (5 repos) | Peer-reviewed |

## MITRE Coverage

| Technique | Name | Detector |
|-----------|------|----------|
| AML.T0051 | LLM Prompt Injection | prompt_injection.py |
| AML.T0048 | Exfiltration via ML Inference API | covert_channel.py, credential_leak.py |
| AML.T0020 | Poison Training Data | data_poisoning.py (Sprint 2) |
| AML.T0040 | ML Model Inference API Access | data_poisoning.py (Sprint 2) |
| AML.T0043 | Craft Adversarial Data | c2_behaviour.py |
| T1027 | Obfuscated Files or Information | covert_channel.py |
| T1071.001 | C2 via Web Protocols | c2_behaviour.py |
| T1095 | Non-Application Layer Protocol | c2_behaviour.py |
| T1552 | Unsecured Credentials | credential_leak.py |
