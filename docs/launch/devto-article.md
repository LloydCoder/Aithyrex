---
title: "How I Applied C2 Network Detection to LLM Traffic (and Why Nobody Else Has)"
published: true
tags: security, llm, ai, python
series: Building AI Shield
cover_image: https://tinlance.com/ai-shield/cover.png
---

Every LLM deployment is a potential new C2 channel. I spent six months proving this — and building the tool that monitors it.

## The Problem Nobody Is Talking About

When your application calls OpenAI, Anthropic, or a local model, that conversation is invisible to every security tool you own. Your firewall doesn't see it. Your SIEM doesn't see it. Your WAF definitely doesn't see it.

This matters because:

**Prompt injection** — attackers embed malicious instructions in user input, documents, or tool outputs that hijack your agent's behaviour.

**Covert channels** — a compromised or manipulated model can encode exfiltrated data in its completions using steganographic patterns. These are invisible to content filters.

**C2 via AI agents** — autonomous agents calling external tools can be used as command-and-control relay channels. The traffic looks like normal HTTPS to your network monitor.

## The Validation: 490K Packets, Z-Score 14.76

My project ThreatFade validated C2 detection against real Merlin QUIC malware traffic — 490,000+ packets, Z-score 14.76, 0% false positive rate.

The methodology: Shannon entropy analysis + Z-score deviation from a clean baseline. Malicious traffic has anomalous entropy patterns that don't appear in normal communications.

The insight: **LLM completions are traffic**. A model encoding data in its output will show identical statistical anomalies to C2 network traffic. The detection methodology transfers directly.

## How AI Shield Works

```python
pip install ai-shield

from ai_shield import wrap
import openai

# One line. That's it.
client = wrap(openai.OpenAI(api_key="..."), api_key="your-shield-key")

# All calls now monitored
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": user_input}]
)
# AI Shield intercepted the prompt, checked it, forwarded to OpenAI,
# scanned the completion, returned the response.
# If anything was detected: PermissionError raised before the response reaches your app.
```

### The Detection Pipeline

Every prompt and completion runs through 5 parallel detectors:

```
Prompt arrives
    ↓
[1] PromptInjectionDetector     → 11 regex patterns, MITRE AML.T0051
[2] CredentialLeakDetector      → 18 patterns (AWS, OpenAI, Paystack, Flutterwave...)
[3] CovertChannelDetector       → ThreatFade entropy + Z-score
[4] C2BehaviourDetector         → Full ThreatFade pipeline
[5] DataPoisoningDetector       → Context integrity (Sprint 2)
    ↓
Aggregate → ShieldVerdict
    ↓
If MEDIUM/ambiguous → Parliament Ensemble
    ↓
PASS / ALERT / BLOCK
```

### The Parliament Ensemble

This is the part I haven't seen elsewhere. For ambiguous detections — medium confidence, single detector — two AI models vote independently:

```
Claude Sonnet: "BLOCK (0.82 confidence) — classic persona hijack attempt"
Grok-3:        "BLOCK (0.79 confidence) — instruction override pattern"
ThreatFade:    "ALLOW" (Z-score 0.3 — entropy clean)

Vote: 2-of-3 BLOCK → BLOCK with consensus
```

Neither model can unilaterally block a request. 2-of-3 required. ThreatFade is always the third vote — deterministic, no API call, instant.

## The Credential Pattern That Started It All

Before AI Shield, I contributed Nigerian fintech credential patterns to five security tools:

- Nuclei (24k ⭐) — Paystack, Flutterwave detection templates
- TruffleHog (15k ⭐) — Remita, Interswitch patterns
- Semgrep (11k ⭐) — merged on day one, now in global scans
- Gitleaks (10k ⭐)
- Slither (5k ⭐)

These same patterns are now in AI Shield's `CredentialLeakDetector`. They scan every LLM completion for leaked API keys before they reach your application.

A RAG-based customer support agent that ingests email threads can silently exfiltrate payment credentials through its responses. AI Shield catches that.

## The Technical Stack

- **Backend**: FastAPI + Python 3.12, PostgreSQL 16 + pgvector, Redis
- **Detection engine**: ThreatFade v0.2.0 (HTTP bridge — entropy/Z-score)
- **Parliament**: Claude Sonnet + Grok-3 + ThreatFade (2-of-3 vote)
- **Compliance**: KalevioAI → NIS2/DORA reports
- **SIEM**: JSON, Splunk HEC, CEF, STIX 2.1
- **Frontend**: Next.js 15 dashboard
- **Tests**: 101 passing, 76% coverage
- **Deploy**: AWS EC2 Stockholm (same server as ThreatFade)

## Pricing and Status

| Tier | Price | Inferences |
|------|-------|-----------|
| Free | $0 | 500/month |
| Starter | $49/mo | 25,000/month |
| Pro | $199/mo | 150,000/month — block mode |
| Enterprise | Custom | NIS2/DORA reports |

**GitHub**: https://github.com/Tinlance/ai-shield  
**PyPI**: `pip install ai-shield`  
**Free tier**: No credit card, 500 inferences/month

If you're deploying an LLM agent and want to monitor what's actually happening inside the inference path — this is the tool.

---

*Lloyd Chinaemerem — Detection Engineer, Tinlance Limited*  
*X: @lloydambition | GitHub: @LloydCoder*
