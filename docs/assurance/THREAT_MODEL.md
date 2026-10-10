# Aithyrex Security Threat Model

**Scope:** Aithyrex runtime AI-security detection, risk findings, tenant-scoped evidence, ThreatFade integration, service APIs, outbox delivery and deployment controls. This is an engineering threat model, not an independent assessment or certification.

## Assets and security objectives

- Tenant identity, entitlements and organization boundaries.
- Prompts, completions, tool arguments, model/provider metadata and detector outputs.
- API keys, Clerk JWT trust anchors, database/Redis credentials, service credentials and webhook secrets.
- Detection findings, evidence hashes, audit records and delivery state.
- Availability of request processing, dependency health, rate limits, usage accounting and outbox delivery.
- Integrity of release artifacts, detector code, configuration and evaluation results.

## Trust boundaries

1. External client → Aithyrex API: untrusted request bodies, headers, model output and caller-controlled identifiers.
2. Aithyrex → Clerk identity: JWT signature, issuer and authorized-party validation. The public key is a trust anchor; service-to-service callers must not impersonate human sessions.
3. Aithyrex → PostgreSQL/Redis: tenant-scoped persistence, quotas, replay protection, and durable delivery state.
4. Aithyrex → ThreatFade: external detection dependency. Timeouts, malformed responses and outage must remain degraded, never be interpreted as clean evidence.
5. Aithyrex → Tinlance Agent Platform / product bridges: Aithyrex findings are advisory. The Agent Platform remains the authoritative identity, policy, approval and governed-execution plane.
6. CI/release pipeline → deployed artifact: dependencies, build output, image digest, configuration and external evidence manifest.
7. Operator → production controls: secret rotation, migrations, tenant provisioning, rollback and backup/restore.

## Adversaries and abuse cases

| Abuse case | Required control | Verification evidence |
|---|---|---|
| Forged, expired, wrong-issuer or wrong-authorized-party JWT | Cryptographic signature and claim validation; fail closed | Auth unit/integration tests and independent review |
| Cross-tenant IDOR or evidence export | Derive tenant from verified identity and scope every query by tenant | Cross-tenant negative tests and database/RLS review |
| Prompt injection or model output tries to override policy | Deterministic security rules outrank model votes; malformed/unavailable decisions fail closed | Adversarial tests and policy-decision traces |
| ThreatFade outage or malformed response treated as clean | Explicit degraded state; no clean-shaped fallback | Fault-injection tests and observability evidence |
| Redis outage bypasses quotas/replay checks | Fail closed for security-critical operations; distinguish unavailable from zero usage | Redis fault-injection tests |
| CSV formula injection or evidence tampering | Output encoding, canonical digest, tenant scoping, clear digest limitations | Export tests and forensic audit |
| Outbox retry causes duplicate delivery | At-least-once semantics, idempotency key, retry/dead-letter evidence | Delivery contract tests and reconciliation metrics |
| Secret/config leakage through logs or health endpoints | Error-class-only diagnostics, no raw prompts/secrets/URLs | Log/health redaction tests |
| Release claim outruns evidence | Fail-closed evidence manifest tied to exact commit SHA | Release gate tests and independent review |
| Compromised dependency/build pipeline | Dependency audit, secret scan, static analysis, immutable artifact digest | Workflow evidence tied to candidate SHA |

## Critical invariants

- Aithyrex detection findings are signals, not authorization grants.
- The Tinlance Agent Platform remains authoritative for agent identity, policy, approvals and execution.
- A detector timeout, malformed response, missing evidence, quota-store failure, or invalid security decision is not an ALLOW.
- A health endpoint cannot establish detection effectiveness.
- Evidence hashes are content-integrity aids, not signatures, trusted timestamps, immutable storage or proof of origin.
- Compliance exports do not decide legal applicability, submit regulator notifications, or prove delivery.
- No release is approved while required AI-text evaluation, independent review, production deployment, restore drill or SLO evidence is absent.

## Residual risks requiring independent review

- Detector effectiveness and false-positive behavior across models, languages, attack families and benign hard negatives.
- End-to-end interception coverage for all supported model/tool/MCP execution paths.
- Multi-tenant isolation under concurrency and all export/report routes.
- Durable event-delivery semantics, downstream idempotency, dead-letter recovery and live telemetry.
- Production deployment architecture, key rotation, availability, restore/recovery and SLO attainment.
- Regulatory statements and any external certification scope.
