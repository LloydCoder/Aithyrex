# Aithyrex Architecture

**Status:** Architecture contract; not a production-readiness attestation.  
**Product lineage:** Aithyrex (formerly AI Shield).

## 1. Purpose and boundary

Aithyrex is the Tinlance service for detecting suspicious activity in supported AI interactions and emitting evidence-bearing findings. It is a detection and telemetry-enrichment component, not an identity provider, authorization engine, approval service, sandbox, or authoritative tool-execution plane.

- **Aithyrex:** AI-interaction detectors, findings, telemetry enrichment and detection evidence.
- **Auctaryn:** agent context, memory, skill and proposed-action risk assessment.
- **Tinlance Agent Platform:** authoritative identity/tenant binding, authorization, policy, approvals, governed execution, tools/MCP, sandbox, secrets, budgets and authoritative audit/evidence.
- **ThreatFade:** separate behavioral/network detection service. Its network-traffic metrics must not be presented as proof of AI-text detection quality.
- **AURONTRA:** IT resilience, incident/ticket workflows and bounded remediation coordination.
- **FusionOps:** response workflow orchestration.
- **KalevioAI:** compliance evidence/reporting workflows. Creating a report or notifying a service does not prove a regulator filing occurred.
- **TSIC:** cross-repository interface contracts and integration conformance, subject to the canonical registry definition.
- **TADL:** developer artifact/schema validation, compile and evaluation tooling.

Aithyrex findings are signals, not authorization grants. Any action that changes external state must be authorized by the owning execution/control plane.

## 2. Conceptual data flow

    Supported AI interaction / telemetry
                    |
                    v
          Aithyrex API + validation
                    |
                    v
       Detector execution and correlation
                    |
                    v
     Finding + detector evidence + provenance
                    |
                    v
       SIEM / incident / evidence integrations
                    |
                    v
     Tinlance Agent Platform policy and approval
       (only when a governed action is requested)
                    |
                    v
        Authorized executor / response workflow

This is the intended contract, not proof that every integration shown is deployed or live. Verify each integration against its versioned contract, credentials, environment, acknowledgement path and end-to-end test before describing it as operational.

## 3. Detection pipeline

The current backend includes detector modules for prompt injection, credential exposure, covert-channel indicators, C2-like behavior and data-poisoning heuristics. Module presence does not establish effectiveness or coverage.

1. Validate request shape and authenticate the tenant.
2. Resolve the active tenant and plan from server-side tenant state.
3. Apply block-state and usage-accounting controls; unavailable authoritative state must not be represented as clean or zero usage.
4. Execute the configured detector set and preserve detector-level results.
5. Treat unavailable ThreatFade responses as degraded telemetry, not a clean verdict.
6. Produce a finding with severity, confidence, detector identity and available provenance.
7. Deliver downstream notifications/reports only with explicit delivery state and correlated evidence.

The current agent detection endpoint concatenates supported string content for inspection; this is not equivalent to complete mediation of tool calls, MCP operations, streaming events, or pre-side-effect execution. Integrations must not claim that those paths are secured until tests prove interception before side effects.

## 4. Decision integrity

- A deterministic BLOCK or CRITICAL finding cannot be downgraded by Parliament or an external model.
- Parliament is advisory. It may raise an alert/escalation; ALLOW votes cannot erase detector findings.
- Missing, malformed, conflicting or unavailable votes are not proof of safety.
- An allowlist may not bypass mandatory detection or platform policy.
- Aithyrex does not authorize actions; the Tinlance Agent Platform remains the authority for policy, approvals and governed execution.

## 5. Identity, tenancy and entitlements

- API access requires a verifiable Clerk JWT with configured trust anchors and standard claim validation.
- An active Clerk organization must resolve to an active, provisioned Aithyrex tenant.
- Tenant plans are loaded from server-side database state; client-provided or token metadata must not grant paid entitlements.
- Billing webhooks must validate provider-specific signatures and map only explicitly configured product/price identifiers.
- Cross-tenant access, missing authentication configuration, unavailable tenant state and invalid entitlement state must fail closed.
- WebSocket monitoring uses a short-lived, one-use ticket. The endpoint must not be described as a live event stream until a tenant-scoped durable publisher and E2E tests exist.

## 6. External dependencies and failure semantics

| Dependency | Required behavior on failure |
|---|---|
| Clerk JWT verification | Reject unverifiable credentials; do not fall back to implicit development authentication |
| Tenant database | Return a service-unavailable error; do not infer tenant or plan |
| Redis usage accounting | Fail closed for governed requests when usage state is required; never return zero as a fallback |
| Redis block state | Do not infer an empty blocklist when state cannot be read |
| ThreatFade | Return explicit degraded/unavailable telemetry; downstream policy decides whether the path can proceed |
| SIEM/reporting endpoints | Record delivery outcome; do not claim durable delivery without acknowledgement/retry evidence |
| LLM ensemble providers | Treat errors or malformed responses as abstentions; they do not grant authorization |

Production rollout additionally requires bounded timeouts, retry budgets, idempotency, secret rotation, telemetry redaction, operational alerting and tested recovery procedures.

## 7. Security evidence and evaluation

No accuracy, false-positive/negative rate, complete MITRE ATLAS coverage, regulatory filing, live integration, SLA, or deployment claim is accepted without reproducible evidence tied to a code revision, environment, dataset, methodology and date.

Required evaluation includes:
- versioned benign and adversarial corpora;
- per-detector precision/recall and false-positive/negative reporting;
- regression tests for prompt injection, credential exposure, malformed detector output and dependency outages;
- tenant-isolation and authorization tests;
- streaming/tool-call/MCP pre-side-effect interception tests for any integration that claims those capabilities;
- durable event delivery, idempotency, retry and evidence-integrity tests;
- dependency, SAST, secret, frontend type-check/lint/build and container checks.

A green CI workflow is necessary but not sufficient for production readiness. A passing scan means only that the configured checks passed for the revision and scope that ran.

## 8. Deployment boundary

The backend uses FastAPI. The dashboard is a separate Next.js application. PostgreSQL stores tenant and operational state; Redis supports usage accounting, block state and short-lived monitor tickets. ThreatFade is a separately operated HTTP dependency.

Production configuration must use explicit HTTPS origins and hosts, TLS-protected database/cache connections, non-default secrets, configured JWT verification, and provider webhook secrets. Local development defaults are not production credentials. A Docker build is a packaging check, not proof of a secure or deployed production environment.

## 9. Evidence status

For the phase-by-phase status, known blockers, acceptance criteria and forensic review history, see FOUNDING_SPEC_RECONCILIATION.md. The ledger is authoritative for what has been implemented, tested, integrated, deployed or remains unverified.


## 10. Versioned contracts and request traceability

The API emits a UUID request identifier in the `X-Request-ID` response header. A valid UUID supplied by a caller is canonicalized and propagated; invalid values are replaced with a server-generated UUID. The trace ID is bound into structured log context and included in versioned responses.

- `aithyrex.detection-response.v1`: additive response envelope that retains existing flat fields for compatibility.
- `aithyrex.finding.v1`: stable finding identifier, trace ID, tenant, timestamp, action/severity, blocked/degraded flags, detector evidence and provenance.
- `aithyrex.detector-evidence.v1`: detector identity, detection result, severity, bounded confidence, technique IDs and structured details.
- `aithyrex.error.v1`: stable error code, safe message, trace ID, retryability and backward-compatible detail payload.

Request-validation errors omit rejected input values so prompts/completions are not echoed into error responses. Contract changes require explicit versioning and regression tests. The finding schema is a canonical data contract; its presence does not prove durable storage, delivery or downstream consumer integration.


## Platform action signal integration (Phase 8)

Aithyrex exposes `POST /api/v1/detect/action` as a threat-signal receiver for a proposed tool/action payload. It requires a short-lived Platform-signed RS256 assertion bound to the exact canonical payload. Aithyrex verifies the assertion, resolves the active tenant from server-side state, and returns evidence only.

This endpoint is deliberately **not** an authorization or execution endpoint:
- Tinlance Agent Platform owns identity, policy, approvals, action binding and governed execution.
- Auctaryn remains the separate context/action-risk assessment product.
- Aithyrex detects prompt-injection, credential and related runtime threat indicators in the exact proposed payload.
- The response is always advisory (`action=log`, `blocked=false`, `authorization_performed=false`, `execution_performed=false`). The Platform must make and enforce its own decision.

See [Platform Action Signal Contract](PLATFORM_ACTION_SIGNAL_CONTRACT.md). The contract is implemented and tested locally; live cross-repository integration, replay persistence and automated key rotation are not claimed.


## Signed context provenance signal (Phase 9)

Aithyrex exposes `POST /api/v1/detect/context` for a Platform-signed context bundle containing retrieved documents, tool output, memory, user input, or model output. The assertion binds the agent, context identifier, tenant, and SHA-256 of the canonical bundle, including each source identifier/type and content. Content and provenance metadata are bounded before scanning.

The response carries source identifiers, source types, content hashes, and an explicit `trust_boundary=untrusted` marker. A signature establishes integrity and the signer's assertion; it does not make retrieved/tool/model content safe, prove that source access was authorized, or grant execution permission. The response is advisory-only and never authorizes or executes an action.

The current phase scans the bundle as a whole and retains per-source hashes; it does not claim precise per-source detector attribution, a live Platform integration, or RAG retrieval authorization. The Platform remains responsible for access control, policy, approval, and governed execution. See [Context Provenance Contract](CONTEXT_PROVENANCE_CONTRACT.md).


## Signed behavioral sequence correlation (Phase 10)

Aithyrex exposes `POST /api/v1/detect/sequence` to analyze ordered event metadata supplied in a short-lived Platform-signed bundle. The deterministic rules correlate credential exposure, prompt injection, sensitive-data access, external-transfer requests, tool execution, and denied-action retries within bounded windows. The request is bounded to 100 events and a one-hour sequence window, and event timestamps and identities are validated.

This is a bundle analyzer, not a durable event stream. It reports matched rule IDs, event IDs, elapsed time, and uncalibrated heuristic severity. It never blocks or authorizes an action; the Platform remains the only authorization/execution authority. Source truth depends on the trusted assertion issuer. See [Behavioral Correlation Contract](BEHAVIORAL_CORRELATION_CONTRACT.md).


## Durable evidence and delivery outbox (Phase 11)

Detection evidence, high/critical alert records, and SIEM/alert/compliance delivery intents are committed in one PostgreSQL transaction before a tenant-bound detection response returns. The lifespan-owned worker claims outbox rows using leases and `SKIP LOCKED`, retries failures with bounded exponential backoff, and dead-letters after 12 attempts. Context and sequence findings use the same persistence path.

Delivery is at-least-once, not exactly-once. If persistence fails, the response exposes degraded state. Production requires `OUTBOX_WORKER_ENABLED=true` and Alembic revision `002_durable_delivery_outbox`. See [Delivery Outbox Contract](DELIVERY_OUTBOX_CONTRACT.md).

## 9. SDK and framework integration boundary

The Python SDK propagates a UUID X-Request-ID for each inspection and fails closed on invalid or mismatched response correlation identifiers. See [SDK and Gateway Integration Contract](SDK_GATEWAY_CONTRACT.md) for supported behavior and limitations.

Provider wrappers can preflight supported text before an upstream call and inspect supported output before returning it. They do not authorize tool calls, execute actions, mediate all provider streaming, or prove that downstream tool side effects are prevented. LangChain and LlamaIndex callbacks/observers are defense-in-depth only; the LlamaIndex observer inspects prompt and completion events independently to avoid cross-request state contamination. The legacy AutoGen/CrewAI wrappers are explicitly unsupported and refuse construction rather than implying protection.

For any actual tool/MCP operation, the Tinlance Agent Platform must enforce identity, policy, approval and authorization at the execution boundary. Aithyrex findings remain advisory signals.

The Platform-signed action, context and sequence receiver contracts consume each assertion JTI once through an atomic tenant/contract-scoped Redis replay guard. Duplicate assertions return HTTP 409; unavailable replay state returns HTTP 503 and fails closed. Redis async clients are created using the synchronous from_url factory and closed on shutdown. See [TSIC Conformance](TSIC_CONFORMANCE.md) and the [contract manifest](../contracts/tsic/aithyrex-contracts.v1.json).

