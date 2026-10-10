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
