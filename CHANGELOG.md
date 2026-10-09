# AI Shield v0.1.0 — Initial Release

**Runtime security for LLM and agentic AI systems.**

---

## What's New

### Core Detection Engine

Five parallel detectors wired into `ShieldEngine`:

| Detector | Method | MITRE |
|----------|--------|-------|
| `PromptInjectionDetector` | 11 compiled regex patterns | AML.T0051 |
| `CredentialLeakDetector` | 18 peer-reviewed patterns | T1552, AML.T0048 |
| `CovertChannelDetector` | ThreatFade entropy + Z-score | AML.T0048, T1027 |
| `C2BehaviourDetector` | ThreatFade full pipeline | T1071.001, T1095 |
| `DataPoisoningDetector` | Stub — Sprint 2 implementation | AML.T0020 |

ThreatFade validation baseline: **Z-score 14.76 on Merlin QUIC malware, 0% false positive rate**.

### Parliament Ensemble

Multi-model AI consensus for ambiguous detections:
- Claude Sonnet 4 (primary)
- Grok-3 (secondary)
- ThreatFade Oracle (deterministic third vote)
- Rule: **2-of-3 votes required to BLOCK**
- Claude and Grok called in parallel — target latency < 2s

### Block Mode (Pro+)

Redis-backed model and agent blocking:
- `POST /enforce/block` — block model or agent by ID
- TTL-based expiry (default 24h)
- Allowlist bypass for trusted models
- Plan-gated: Pro and Enterprise only

### API

```
GET  /health                  — dependency health check
POST /detect/llm              — inspect prompt + completion
POST /detect/prompt           — pre-flight prompt check
POST /detect/agent            — agentic message stream scan
POST /enforce/block           — block model/agent (Pro+)
POST /enforce/unblock
POST /enforce/allow
GET  /enforce/blocked
GET  /reports/summary
POST /reports/compliance      — trigger NIS2/DORA report
POST /webhooks/lemonsqueezy   — billing events
POST /webhooks/paddle         — EU/Enterprise billing
WS   /monitor/stream          — live alert feed
```

### SIEM Export

| Format | Plan |
|--------|------|
| JSON | All |
| CSV | Starter+ |
| Splunk HEC | Pro+ |
| CEF | Pro+ |
| STIX 2.1 | Enterprise |

### Integrations

```python
# OpenAI
from ai_shield import wrap
client = wrap(openai.OpenAI(...), api_key="...")

# Anthropic
client = wrap(anthropic.Anthropic(...), api_key="...")

# LangChain
from ai_shield.integrations.langchain import AIShieldCallback
llm = ChatAnthropic(callbacks=[AIShieldCallback(api_key="...")])
```

### Compliance

- NIS2 Article 23 incident reporting via KalevioAI
- DORA operational resilience hooks
- SHA-256 hash-chained audit trail
- Trigger: CRITICAL detection or 3+ HIGH in 60 minutes (Enterprise)

### Infrastructure

- FastAPI + Python 3.12
- PostgreSQL 16 + pgvector (embeddings for Sprint 2)
- Redis (usage counters + block list)
- Clerk multi-tenant auth
- LemonSqueezy (global billing)
- Paddle (EU/Enterprise billing)
- Docker Compose dev environment
- GitHub Actions CI/CD (tests + OWASP scan + TruffleHog)

---

## Installation

```bash
# PyPI package (SDK wrapper only)
pip install ai-shield

# Full server
git clone https://github.com/Tinlance/ai-shield
cd ai-shield
make dev        # starts PostgreSQL + Redis + API
make test       # 101 passing tests
make demo       # Sprint 1 demo proof
```

---

## Test Coverage

```
101 tests passing
76% coverage

Unit tests:
  test_prompt_injection.py    12 tests
  test_credential_leak.py      9 tests
  test_shield_engine.py       11 tests
  test_parliament.py          15 tests
  test_block_mode.py          10 tests
  test_siem_exporter.py        9 tests
  test_nis2_dora.py            7 tests

Integration tests:
  test_api.py                 22 tests
  test_threatfade_bridge.py    4 tests
```

---

## What's Next (v0.2.0)

- [ ] `DataPoisoningDetector` — context integrity + embedding-space anomaly
- [ ] LlamaIndex middleware
- [ ] AutoGen / CrewAI agent callbacks
- [ ] MITRE ATLAS coverage report generator
- [ ] Olvrix bridge integration (`ai_shield_sync.py`)
- [ ] TwinGuard integration (FusionOps AI_AGENT_ABUSE escalation)
- [ ] EU AI Act compliance mapping

---

## Credits

Built by **Tinlance Limited** (RC: 7962164)  
Detection patterns peer-reviewed via PRs to Nuclei, TruffleHog, Semgrep, Gitleaks, Slither  
ThreatFade engine: github.com/LloydCoder/tinlance-threatfade  

Apache 2.0 — © 2026 Tinlance Limited
