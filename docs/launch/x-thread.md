# Draft X Thread — Aithyrex

> **Editorial status: DRAFT — do not publish until release and evaluation gates are met.**

**Post 1**

Aithyrex is a Tinlance project exploring security inspection for supported LLM interactions.

The goal is evidence-bearing findings—not another authority that can bypass policy or approvals.

**Post 2**

AI applications face risks from prompt injection, exposed credentials, untrusted retrieved context and tool calls that create side effects.

Detectors help, but they cannot replace least privilege, sandboxing and authorization at the execution boundary.

**Post 3**

Aithyrex includes pattern-based prompt-injection and credential detectors, encoding heuristics, a ThreatFade bridge and an advisory voting component.

Those are implementation capabilities, not a claim of complete threat coverage.

**Post 4**

Important caveat: ThreatFade's network-traffic metrics do not validate AI-text detection accuracy.

Aithyrex needs its own representative AI-interaction evaluation corpus, measured false positives/negatives and reproducible reports.

**Post 5**

Architecture boundary:

→ Aithyrex detects and emits findings
→ Auctaryn assesses agent context, memory, skills and action risk
→ Tinlance Agent Platform owns identity, policy, approvals and governed execution
→ AURONTRA owns IT resilience and operational workflows

**Post 6**

The current Python client requires an explicit service URL and Clerk session JWT. Missing configuration, network failures and malformed inspection responses fail closed.

Streaming/multimodal inputs and AsyncAnthropic are not supported by the current wrappers.

**Post 7**

MITRE ATLAS/ATT&CK references are heuristic mappings—not evidence that every technique is fully detected.

No 0% false-positive or complete-coverage claim is being made.

**Post 8**

Follow the engineering work: https://github.com/LloydCoder/Aithyrex

Aithyrex (formerly AI Shield) | Tinlance Limited | Apache-2.0

Publication remains blocked until the CI/security workflows, evaluation evidence and independent review are complete.
