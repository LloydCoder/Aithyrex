# Draft — Show HN: Aithyrex, an AI runtime security project

> **Do not publish yet.** This draft intentionally avoids unsupported accuracy, deployment, upstream-contribution, pricing, and standards-coverage claims.

## Proposed title

Show HN: Aithyrex — an evidence-first AI interaction security project

## Draft body

Hi HN,

Aithyrex is an open-source project from Tinlance exploring runtime threat detection for supported LLM interactions. The repository contains pattern-based prompt-injection and credential detectors, encoding heuristics, a ThreatFade bridge, an advisory voting component, API routes, and Python wrappers.

The design question is how to combine content-level signals with agent/runtime controls without creating a second authorization system. Aithyrex emits findings; the Tinlance Agent Platform remains the authority for identity, policy, approvals and governed execution.

One important limitation: ThreatFade's network-traffic results do not prove AI-text detection effectiveness. Aithyrex needs a separate representative AI-interaction corpus and reproducible precision/recall/false-positive measurements before we make claims about detection performance.

The SDK also has explicit limits: streaming and multimodal content are not supported by the current wrappers, and AsyncAnthropic is not supported. The client requires a configured service URL and Clerk session JWT; generic static API keys are not currently implemented.

Repository: https://github.com/LloydCoder/Aithyrex

Feedback that would be especially useful:

- Which adversarial datasets and evaluation protocols should be mandatory for this class of tool?
- How should findings bind to the exact action intent without becoming an authorization grant?
- What evidence is required before claiming coverage for a technique mapping?

This is a work in progress, not a claim that AI runtime security is solved. I plan to publish only after the CI/security gates and evaluation artifacts are independently reviewed.
