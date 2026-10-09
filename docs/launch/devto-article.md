---
title: "Aithyrex: Designing an Evidence-First AI Runtime Security Layer"
published: false
tags: security, llm, ai, python
---

> **Editorial status: DRAFT — do not publish until the release gates and evaluation evidence are reviewed.**

# Aithyrex: Designing an Evidence-First AI Runtime Security Layer

Aithyrex is Tinlance's project for inspecting supported AI interactions and producing security findings with explicit provenance. The repository includes pattern-based prompt-injection and credential detectors, encoding heuristics, a ThreatFade bridge, a voting component, API routes, and provider integration wrappers.

This is an engineering project, not a claim that AI runtime security is solved. The implementation and its evaluation are still being hardened.

## Why inspect AI interactions?

AI applications create security surfaces that traditional network telemetry alone cannot explain:

- Prompt injection can arrive through user input, retrieved documents, and tool output.
- Model outputs can inadvertently expose credentials or other sensitive content.
- Tool calls can turn untrusted model output into external side effects if authorization is not checked at execution time.
- Telemetry gaps can make an apparently clean result unreliable.

These risks require layered controls. A text detector is not a substitute for identity, least privilege, approval, sandboxing, or downstream authorization.

## How Aithyrex is structured

- **Local detectors** look for prompt-injection patterns, credential formats, encoding indicators and context-risk heuristics.
- **ThreatFade** supplies a separate behavioral/network signal. Its network-traffic results are not evidence of AI-text detection accuracy.
- **Parliament** is an advisory voting component. It may escalate a finding but cannot override a deterministic block; raw customer prompts and completions are withheld from external voters.
- **Tinlance Agent Platform** remains the authoritative identity, policy, approval and governed-execution layer.
- **Auctaryn** specializes in agent context, memory, skill and proposed-action risk; **AURONTRA** specializes in IT resilience and operations.

## What the SDK does and does not guarantee

The current Python client requires an explicitly configured Aithyrex API URL and a Clerk session JWT. It fails closed when the URL, token, transport, or response schema is missing or invalid.

The current provider wrappers are not universal gateways. Streaming and multimodal inputs are explicitly unsupported by the wrappers described here, and AsyncAnthropic is not supported. Tool-use output is inspected before the wrapper returns it, but the actual execution boundary must still enforce authorization.

Example for a configured service:

    import os
    from aithyrex import Shield

    shield = Shield(
        token=os.environ["AITHYREX_API_TOKEN"],
        base_url=os.environ["AITHYREX_API_URL"],
    )
    verdict = await shield.inspect(prompt="untrusted input")
    if verdict.blocked:
        raise PermissionError("Aithyrex blocked or could not safely inspect the request")

The example assumes an authenticated, provisioned tenant and a verified API endpoint. Generic static API keys are not currently supported.

## What still needs validation

- A representative adversarial and benign corpus with measured precision, recall, false positives and false negatives.
- Tenant isolation and authorization tests against a real deployment configuration.
- Provider-specific sync/async, streaming, multimodal and tool-call mediation tests.
- Durable evidence delivery, retry/idempotency behavior and recovery tests.
- Versioned cross-repository contracts and end-to-end integration evidence.

MITRE ATLAS and ATT&CK references in the repository are heuristic mappings, not proof of complete technique coverage. No 0% false-positive or other accuracy claim is made here.

## Project

- Repository: https://github.com/LloydCoder/Aithyrex
- Product: Aithyrex (formerly AI Shield)
- License: Apache-2.0

Publication should wait until the relevant CI, security audit, evaluation and independent review gates are complete.
