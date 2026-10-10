# Aithyrex Operations Runbook

## Status and evidence boundaries

This runbook defines minimum operational procedures for Aithyrex. It is not evidence that a production deployment exists, that a backup has been restored successfully, or that an SLO has been achieved. Record environment, revision, operator, timestamps, command output, and evidence links for every operational drill.

## Health probes and traffic management

- `GET /health/live` is process liveness only. It must not call PostgreSQL, Redis, or ThreatFade. A successful response means the HTTP process is responding, not that protected inference is safe.
- `GET /health/ready` checks PostgreSQL, Redis, and ThreatFade with bounded per-dependency timeouts. It returns HTTP 200 only when all required dependencies report healthy; otherwise it returns HTTP 503. Use this endpoint for load-balancer readiness and rollout gating.
- `GET /health` is a backward-compatible diagnostic endpoint. It returns HTTP 200 with `status=ok|degraded`; new orchestration should use the dedicated liveness/readiness endpoints.
- Health responses must never include exception messages, credentials, database URLs, Redis URLs, hostnames from error text, or raw prompts/completions.
- A health probe is not a detector-quality check. A reachable ThreatFade endpoint does not establish calibrated AI-text detection.

## Provision a tenant

Tenant provisioning is operator-controlled; there is no self-service public provisioning endpoint.

1. Verify the Clerk organization ID and organization name in the Clerk dashboard through an authorized administrative session.
2. Configure the target environment's database URL, including TLS and non-default credentials. Do not commit production secrets.
3. From the repository root and the intended environment, run:

       python scripts/provision_tenant.py --clerk-org-id org_... --name "Organization Name"

4. Confirm the command reports the tenant UUID and the Free plan. The script does not accept a plan argument and cannot grant paid entitlements.
5. Verify that a member of the organization can authenticate with a valid Clerk session JWT and that another organization cannot access this tenant's records.

The command is idempotent for an already-active tenant. It refuses to silently reactivate an inactive tenant; follow the approved administrative recovery process instead.

## Deactivate a tenant

Use an authorized database administration process to set the tenant's active flag to false. Do not delete the tenant or its evidence records as a routine deactivation step. Record the operator, ticket, reason and timestamp in the organization's change/audit system.

## Production configuration gates

- Set `APP_ENV=production`.
- Set a non-default `APP_SECRET_KEY` of at least 32 characters; use a secret manager, not a committed environment file.
- Configure `CLERK_JWT_KEY`, an HTTPS `CLERK_JWT_ISSUER`, and an explicit `CLERK_AUTHORIZED_PARTIES` list.
- Configure a remote `postgresql+asyncpg` `DATABASE_URL` with non-default credentials and an explicit `ssl=require` or `ssl=verify-full` query parameter.
- Configure a remote `rediss://` `REDIS_URL` with non-default authentication.
- Configure explicit HTTPS `ALLOWED_ORIGINS` and a non-wildcard `ALLOWED_HOSTS` allow-list.
- Configure ThreatFade over HTTPS and provide its API key through the deployment secret manager.
- Set `OUTBOX_WORKER_ENABLED=true`; verify the database migration is applied and the outbox worker can claim, retry, and dead-letter delivery rows.
- Configure upstream request-body limits at the reverse proxy/API gateway; application schema limits run after JSON parsing.
- Before exposing the API, verify database migrations, backups, restore procedures, TLS certificates, health probes, telemetry, alerts, capacity limits and rollback.
- Never use the development Compose credentials, mounted source volume, `--reload`, or publicly exposed local PostgreSQL/Redis ports as a production deployment pattern.

The application validates production configuration at startup. This check validates configuration shape, not remote reachability, secret rotation, backup freshness, high availability, or deployment correctness.

Database connection budget: `(DB_POOL_SIZE + DB_MAX_OVERFLOW) × API worker/process count` is the approximate maximum application pool capacity. Keep this below the database's connection limit with explicit headroom for migrations, administration, monitoring, and other services. Set pool timeout/recycle values for the deployment's proxy and database policy; do not increase pools without measuring saturation and database capacity.

## Proposed service objectives — not yet measured

Use these as initial targets to validate with real traffic before treating them as contractual SLOs:

| Indicator | Initial target | Measurement rule |
|---|---|---|
| API availability | 99.9% monthly | Successful eligible API requests / eligible requests; exclude only documented maintenance and client errors |
| Readiness recovery | Within 5 minutes | Time from dependency recovery to readiness returning HTTP 200 |
| Detection request latency | p95 under 500 ms, excluding upstream model latency | Measure by route and operation; publish sample size and window |
| Critical outbox backlog | Alert when oldest pending item exceeds 5 minutes | Query persisted pending/processing rows; monitor dead-letter counts separately |
| Security event delivery | No silent loss after database commit | Reconcile outbox rows to acknowledged delivery outcomes; delivery is at-least-once |
| Restore capability | Quarterly restore drill | Restore to isolated environment and verify migrations, event counts, tenant boundaries and application startup |

Do not claim an SLO is met until the metric source, time window, exclusions, and actual observed result are recorded. Do not promise exactly-once external delivery.

## Observability and alerting

Capture structured metadata with trace/request ID, tenant UUID (not organization secrets), route, status, normalized error class, dependency latency, detector/degraded state, outbox age/attempts, and deployment revision. Do not log raw prompts, completions, retrieved documents, tool arguments, authorization headers, API keys, exception text from remote services, or full credential-bearing URLs.

Minimum alerts:
- Readiness continuously 503 or dependency latency above configured threshold.
- Elevated 5xx/429 rates or sustained p95/p99 latency regression.
- Outbox oldest pending age above target, rising retry count, or dead-letter growth.
- Redis/PostgreSQL connection pool exhaustion, storage pressure, failed backups, or failed restore verification.
- Repeated signature failures, assertion replay, cross-tenant access denials, unexpected configuration changes, or secret-scanning alerts.
- Production startup validation failure or unexpected worker shutdown.

Alerts must link to the trace ID, runbook and deployment revision, not to raw sensitive payloads.

## Secret and key rotation

1. Inventory each secret, owner, consumer, environment, expiry/rotation interval, and emergency revocation procedure.
2. Prefer overlapping key versions where supported. Deploy the new trust anchor to consumers before issuing new credentials; verify authentication with the new key; then revoke the old key.
3. Rotate immediately after suspected exposure, suspicious CI execution, unauthorized access, or vendor incident. Revoke associated sessions/tokens and inspect downstream access logs.
4. Do not paste secret values into tickets or audit logs. Record secret identifier/version, actor, timestamp and outcome only.
5. Platform assertion issuer key rotation must be coordinated with the Tinlance Agent Platform; a configured public key is a trust anchor and rotation is not yet automated by Aithyrex.

## Backup, restore, and recovery

- Use managed PostgreSQL backups with encryption, restricted access, retention policy, and point-in-time recovery where supported. Store backup credentials separately from database credentials.
- Back up PostgreSQL data and migration/version metadata; Redis is operational state for rate limiting/replay protection and must be configured for the durability/availability required by the deployed environment. Do not treat a Redis backup as a replacement for PostgreSQL evidence.
- At least quarterly, restore into an isolated environment with no production outbound credentials. Apply/verify migrations, compare expected tenant/event/outbox counts, verify tenant isolation, run health probes and a bounded smoke test, then securely destroy the drill environment.
- Record recovery point (RPO), recovery time (RTO), data-loss window, failed steps and corrective actions. RPO/RTO values are not established until approved and measured.
- Do not run destructive recovery commands against production without an approved change, independent confirmation of target environment, and a verified backup.

## Deployment, rollback, and migrations

1. Deploy an immutable image tied to a commit SHA; record image digest and dependency/security workflow links.
2. Verify production config validation, TLS, database/Redis connectivity, readiness, migration state, and outbox worker health before routing traffic.
3. Run a tenant-isolation smoke test using two dedicated test tenants; never use customer prompt content as test data.
4. Shift traffic gradually and monitor readiness, 5xx/429 rates, dependency latency, detector degraded state and outbox backlog.
5. Roll back to the last known-good immutable image if readiness, error rates, or data integrity cross the approved threshold. Database schema changes must be backward-compatible with the rollback image or have a separately rehearsed recovery procedure.
6. Never claim deployment or rollback success from a CI build alone; capture environment-specific deployment and smoke-test evidence.

## Incident handling

- A degraded Aithyrex inspection is not a clean result; callers must stop protected downstream actions.
- Block-state or usage-accounting failures are fail-closed and may affect availability.
- A missing or malformed ThreatFade response is degraded.
- Preserve correlation IDs and evidence references. Keep raw prompts/completions out of general tickets and logs; use a separately approved restricted evidence store if content preservation is legally or operationally necessary.
- For suspected credential compromise: disable affected integration, revoke/rotate secrets, review access logs, identify impacted tenants, preserve evidence, notify the incident owner, and record the recovery decision.
- For cross-tenant exposure: disable the affected route/integration, preserve trace IDs and database audit evidence, assess the full tenant scope, rotate relevant credentials, and require independent review before re-enabling.
- Treat a generated report or webhook response as distinct from proof of delivery or legal filing.

## Known operational blockers and non-claims

- Service-to-service authentication for AURONTRA and other product integrations must use a dedicated service identity; a Clerk user session token is not a durable service credential.
- External delivery is at-least-once, not exactly-once. Dead-letter replay tooling, durable metrics and production alert routing must be configured and tested.
- Self-service tenant provisioning and automated organization lifecycle webhooks are not implemented.
- Production deployment, HA, backup freshness, restore success, measured SLOs and live ecosystem integration must be verified independently; this repository alone does not prove them.


## Security engineering references

- [OWASP AISVS 1.0 — Infrastructure, Configuration & Deployment Security (C4)](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C04-Infrastructure.md)
- [OWASP AISVS 1.0 — Monitoring, Logging & Anomaly Detection (C12)](https://github.com/OWASP/AISVS/tree/main/1.0/research/chapters/C12-Monitoring-and-Logging)
- [OWASP ASVS 5.0 — Configuration (V13)](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md)
- [NIST SP 800-218 — Secure Software Development Framework (SSDF) v1.1](https://csrc.nist.gov/pubs/sp/800/218/final)

These references inform verification criteria; they do not constitute certification or evidence that every requirement is satisfied.
