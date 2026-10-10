# Phase 16 — Operations and Deployment Forensic Audit

**Phase:** 16 — operations and deployment hardening  
**Branch:** `godmode/phase-16-operations-deployment`  
**Audit status:** implementation in progress; final acceptance requires the final PR-head CI and Security Scan to pass.

## Scope

Harden production configuration validation, process/dependency health semantics, shutdown resource cleanup, local-development deployment boundaries, and the operator runbook. This phase does not claim a production deployment, achieved SLOs, high availability, or a successful backup/restore drill.

## Baseline findings

- The legacy `/health` endpoint performed dependency probes but always returned HTTP 200, so orchestrators could not distinguish readiness from process liveness by status code.
- Health checks had no per-dependency timeout, allowing slow or hung dependencies to stall the probe.
- Redis health responses included exception text, which can reveal endpoint or connection details.
- Production database TLS validation used substring matching against the entire URL, allowing misleading matches outside the actual `ssl` query parameter.
- The `pyproject.toml` server extra did not explicitly declare the PyJWT crypto and cryptography packages required by runtime JWT validation and the new RSA trust-anchor check.
- Production Redis validation required TLS scheme but did not require remote host or non-default authentication.
- The application shut down Redis clients but did not dispose the SQLAlchemy engine pool. A failing outbox worker during shutdown could interrupt subsequent cleanup.
- The operations runbook did not define explicit liveness/readiness behavior, SLO measurement rules, secret rotation, restore drills, or rollback evidence. Docker Compose exposed development credentials and database/Redis ports without a prominent local-only warning.

## Implemented controls

- Add a production configuration validator that parses URLs and validates actual scheme, host, credentials, TLS query parameters, a parseable RSA Clerk JWT public key, trusted hosts, HTTPS origins, bounded SQLAlchemy pool settings, and durable outbox-worker configuration. Declare PyJWT[crypto] and cryptography in the installable server extra. Errors identify configuration variable names only and never echo secret values.
- Add `/health/live` (process-only) and `/health/ready` (HTTP 503 when any required dependency is unhealthy), keep legacy `/health` response semantics for compatibility, bound each dependency probe, and remove Redis exception text.
- Dispose the SQLAlchemy engine during shutdown, make pool capacity/timeout/recycle settings configurable and bounded, log request duration/outcome, and log outbox-worker shutdown failures without skipping remaining resource cleanup.
- Label Compose and `.env.example` as local-development-only, bind published ports to loopback, add a container liveness healthcheck, and use a canonical non-root container user.
- Expand the operations runbook with probe semantics, proposed-but-unmeasured SLOs, telemetry/privacy rules, alerts, key rotation, backup/restore, deployment/rollback, incident procedures, and explicit non-claims.
- Add regression tests for URL parsing, RSA trust-anchor parsing, loopback/default credentials, wildcard hosts, HTTPS origins, database pool bounds, liveness/readiness semantics, probe timeouts, health-error redaction, and shutdown cleanup.

## Acceptance gate

- Unit and integration tests, offline red-team regression, Ruff, Bandit, Semgrep, frontend dependency audit/type-check/lint/build, Docker build, dependency audit, and secret scan pass on the final PR head.
- Forensic review verifies URL parsing is structural (not substring-based), no secret values are included in validation errors, readiness is bounded, liveness does not call dependencies, error payloads are sanitized, and shutdown cleanup continues after worker errors.
- Merge only after both CI and Security Scan are green; then verify post-merge workflows.

## Residual gates

- SLOs are proposed targets only until measured against real traffic with documented windows and exclusions.
- No production deployment, managed secret-manager integration, automatic rotation, database/Redis HA, successful backup/restore drill, or disaster-recovery RPO/RTO is proven by repository CI.
- A health response does not establish detector accuracy, live integration correctness, or permission to execute an action.
