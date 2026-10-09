# Show HN: AI Shield — Runtime security for LLM and agentic AI (Apache 2.0)

## Title
Show HN: AI Shield – Entropy-based C2 detection applied to LLM traffic (Apache 2.0)

## Body

Hi HN,

I'm Lloyd, a detection engineer from Nigeria. I've spent the last year contributing Nigerian fintech credential patterns to Nuclei, TruffleHog, Semgrep, Gitleaks, and Slither — all merged to production.

My main project, ThreatFade, validated C2 detection against 490K+ real Merlin QUIC malware packets — Z-score 14.76, 0% false positive rate.

The insight: the same statistical methodology (Shannon entropy + Z-score deviation) that detects C2 in network traffic should detect covert channels in LLM completions. AI agents are new C2 surfaces. Nobody is monitoring them at the inference layer.

**AI Shield** is the tool that does.

**What makes it different from LLM Guard, Lakera (now Check Point), and Bifrost:**

Those tools filter prompts using classifiers. That's necessary but not sufficient.

AI Shield adds an entropy-analysis layer on top — the same layer that caught Merlin QUIC C2 traffic at Z-score 14.76. When a compromised or manipulated model encodes exfiltrated data in its completions, the Shannon entropy of the token distribution deviates from the clean baseline. Classic prompt filtering misses this entirely.

AI Shield also adds the Parliament Ensemble: Claude Sonnet + Grok-3 vote independently on ambiguous detections. 2-of-3 required to block. ThreatFade is the deterministic third vote. Neither AI model can unilaterally block a request.

**Install:**

    pip install ai-shield

    from ai_shield import wrap
    import openai

    client = wrap(openai.OpenAI(api_key="..."), api_key="your-shield-key")
    # All calls now monitored — zero other changes needed

**Honest status:**

- Backend: FastAPI, 115 tests passing, PostgreSQL + Redis
- Detectors: prompt injection, credential leak (18 patterns), covert channel, C2 behaviour, data poisoning — all live
- Parliament Ensemble: Claude + Grok + ThreatFade (2-of-3 vote)
- Frontend: Next.js 15 dashboard built
- SIEM: JSON / Splunk HEC / CEF / STIX 2.1
- Compliance: NIS2/DORA hooks via KalevioAI (DORA is live now — January 2025)
- Deploy target: AWS EC2 Stockholm this week (same server as ThreatFade)
- Free tier: 500 inferences/month, no credit card

**Competitive note:** Lakera was acquired by Check Point in November 2025 ($300M). It's now an enterprise product routed through Cisco procurement. AI Shield is the accessible developer-first alternative.

GitHub: https://github.com/Tinlance/ai-shield
PyPI:   https://pypi.org/project/ai-shield
MITRE ATLAS coverage: github.com/Tinlance/ai-shield/blob/main/docs/mitre-atlas-mapping.md

Would love feedback specifically on the entropy-based covert channel detection approach — that's the part I haven't seen applied to LLM completions anywhere else.

— Lloyd (@lloydambition)
