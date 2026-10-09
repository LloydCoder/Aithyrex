# Aithyrex Architecture and Trust Boundaries

**Product:** Aithyrex (formerly AI Shield)  
**Repository:** https://github.com/LloydCoder/Aithyrex  
**Status:** Implementation snapshot; not a production-readiness attestation.

## 1. Purpose and scope

Aithyrex is intended to detect threats in supported AI interactions and emit evidence-bearing findings. The current repository contains a FastAPI backend, local detector modules, an HTTP client for ThreatFade, a Parliament voting component, SIEM/reporting code, SDK wrappers and a dashboard.

Aithyrex is **not proven to be a universal transparent proxy** for every LLM provider. Enforcement depends on the caller using a supported, correctly configured integration and honoring the verdict. SDK wrappers and API routes must be validated per provider, version, streaming mode and tool-call path.

## 2. Canonical Tinlance boundaries

- **Aithyrex:** AI-interaction threat detection, detector findings, telemetry enrichment and versioned security signals.
- **Auctaryn:** agent context, memory, skill and proposed-action risk assessment.
- **Tinlance Agent Platform:** authoritative identity, tenant binding, authorization, policy, approvals, governed execution, tools/MCP, sandboxing, secrets, budgets and authoritative audit/evidence.
- **ThreatFade:** separate behavioral/network detection service. Network-traffic metrics are not validation of AI-text detection.
- **AURONTRA:** IT resilience, incident/ticket workflows and bounded remediation coordination.
- **FusionOps:** response workflow orchestration.
- **KalevioAI:** compliance evidence and reporting workflows; a webhook or report does not prove legal submission.
- **TSIC:** versioned cross-repository contracts, conformance and end-to-end evidence.
- **TADL:** developer-artifact and schema validation.

Aithyrex findings are untrusted signals, not authorization grants. Aithyrex must not become a competing identity, policy, approval or governed-execution authority.

## 3. Current logical flow

1. An application or supported SDK submits a prompt for pre-flight inspection.
2. Aithyrex runs local prompt-injection and credential-pattern detectors.
3. When a completion is supplied, Aithyrex runs credential, encoding/covert-channel, C2-behavior and context/data-poisoning heuristics.
4. ThreatFade is queried for supplementary telemetry. Missing, malformed or unavailable required telemetry is marked degraded; the current safety policy blocks rather than treating it as clean.
5. The deterministic detector verdict is aggregated. Parliament may provide advisory escalation; it cannot downgrade an existing BLOCK verdict. Raw prompt/completion content is withheld from external voting models.
6. Findings can be logged/exported and routed to downstream systems. Delivery durability and live cross-repository integration remain separate acceptance gates.

Logical components:

- Application or supported SDK
- Authenticated Aithyrex pre-flight / inspection API
- Prompt-injection detector
- Credential-pattern detector
- Covert-channel and encoding heuristics
- C2-behavior heuristics
- RAG/context-poisoning heuristics
- ThreatFade supplementary telemetry
- Deterministic verdict and advisory Parliament
- Finding, SIEM and report workflows
- Tinlance Agent Platform policy/authorization
- Authorized execution or response workflow

This describes intended responsibilities, not proof that every connection is currently deployed or live.

## 4. Detector semantics and limitations

| Detector | Current approach | Limitation |
|---|---|---|
| Prompt injection | Pattern-based detection | Not complete semantic analysis; false negatives/positives require corpus-based measurement. |
| Credential leakage | Locally maintained credential-format patterns | Coverage depends on tested formats; matches are redacted in findings. |
| Covert channel | Encoding heuristics plus ThreatFade signal | Network-traffic performance does not establish AI-text effectiveness. |
| C2 behavior | ThreatFade signal plus thresholds | No claim of detecting arbitrary agent C2 without representative AI-interaction evaluation. |
| Data poisoning/context risk | Runtime text heuristics | Does not establish detection of offline model-weight or training-data poisoning. |

MITRE ATLAS and ATT&CK references are **heuristic mappings**. A mapping is not evidence that the technique is fully covered.

## 5. Identity, tenant isolation and policy

- API routes requiring tenant access use verified Clerk JWTs with a configured trusted key, issuer and authorized-party allowlist.
- Requests must resolve to an active, provisioned tenant record. Tenant plan is read from server-side state, not JWT metadata.
- Production startup rejects missing JWT trust anchors, default application secrets, wildcard hosts/origins, non-TLS Redis, and default/local or non-TLS database URLs.
- WebSocket access uses a short-lived, single-use ticket rather than a long-lived JWT in a query string. The live tenant-scoped event publisher is not yet implemented; the endpoint must not be represented as a functioning event stream.
- Model allowlisting is disabled because it previously bypassed mandatory inspection.
- The Tinlance Agent Platform remains authoritative for final authorization and actual tool execution.

These controls require integration tests against the exact deployment configuration and tenant schema before release.

## 6. Failure semantics

- ThreatFade timeout, connection error, invalid JSON/schema or non-finite Z-score is a degraded result, never a clean result.
- Block-state and usage-accounting failures are fail-closed.
- Missing/invalid model votes abstain.
- Parliament can escalate but cannot lower the deterministic action rank.
- Unknown billing product IDs do not grant entitlements.
- Webhook signature validation requires configured provider secrets; missing secrets reject the event.
- Reports and compliance submissions that are not implemented return an explicit unavailable/not-implemented response instead of simulated success.

Fail-closed behavior can affect availability. Production owners must accept the documented outage policy and operate dependency health/incident runbooks.

## 7. Persistence and delivery caveats

Detection-event logging, SIEM dispatch and some alert paths still use in-process background tasks. They are not yet a durable outbox guarantee. Before production assurance, implement durable event persistence/outbox, retries, idempotency, dead-letter handling, delivery acknowledgements and crash/restart tests.

Dashboard data, report exports and compliance notifications must be sourced from persisted tenant-scoped backend records. Simulated data or local UI state must be explicitly labeled and cannot be presented as successful security action or legal filing.

## 8. Deployment and integrations

Repository configuration, an adapter class or a URL environment variable does not prove that a service is deployed or integrated. Deployment, DNS/TLS, service authentication, tenant isolation, API contract compatibility, SIEM receipt and cross-repository end-to-end flows must be verified separately.

No hosted Aithyrex API base URL is asserted by this document. SDK users must configure the actual verified service URL explicitly.

## 9. Assurance requirements

Before launch, maintain reproducible evidence for:

- Threat coverage and false-positive/false-negative evaluation on representative AI interaction data.
- SDK sync/async/streaming and tool-call mediation.
- Tenant-isolation and authorization regression tests.
- ThreatFade outage, invalid-response and recovery behavior.
- Durable evidence delivery and replay/idempotency.
- Billing webhook signature, replay, product-ID and entitlement transitions.
- Production deployment, rollback, backup/restore and operational SLOs.
- Versioned TSIC contract conformance and end-to-end integration tests.

Do not claim 100% security, 0% false positives, complete MITRE coverage, regulatory filing, production deployment, or a live integration without versioned, reproducible evidence.
