# Aithyrex ↔ Olvrix Bridge

**Status: prototype adapter; not evidence of a live or production integration.**

This directory contains the Aithyrex-side adapter currently implemented in `ai_shield_sync.py`. `AIShieldSync` is retained as a legacy class name; `AithyrexSync` is the canonical alias.

## Intended use

The adapter can request Aithyrex inspection for scraped HTML, generated website content, generated outreach and high-severity ThreatFade signals. It returns an explicit blocked/degraded result when Aithyrex is not configured, unreachable, or returns an invalid response. Consumers must treat `safe: false` as a stop signal and must not send/deploy content when inspection is degraded.

Empty input is treated as a no-op and is returned as safe without a remote inspection. Callers must ensure this behavior is appropriate for their workflow.

## Required configuration

- `AITHYREX_API_URL`: explicitly verified HTTPS service base URL. No hosted URL is assumed by this repository.
- `AITHYREX_API_TOKEN`: currently expected to be a Clerk session JWT for an active, provisioned organization. This is not a suitable durable service-to-service credential. Production integration is blocked until a supported service-principal credential contract is implemented and validated through the Tinlance Agent Platform.
- `FUSIONOPS_API_URL` and `FUSIONOPS_API_KEY`: optional, explicitly configured FusionOps destination and credential. The adapter reports notification success only after an HTTP success response.

Legacy `AI_SHIELD_API_URL` and `AI_SHIELD_API_KEY` environment variables are not the canonical configuration and should be removed during migration.

## Contract and security constraints

- The adapter calls the versioned Aithyrex API route `/api/v1/detect/llm`.
- Aithyrex currently verifies Clerk JWTs and resolves an active tenant from server-side state. It does not implement generic static API-key authentication.
- Do not place a human's long-lived session token in a server environment as a permanent service credential.
- No direct Aithyrex-to-Olvrix production integration is claimed until service authentication, tenant binding, payload schemas, rate limits, retries, and end-to-end tests are complete.
- FusionOps delivery is separate from Aithyrex inspection. A local result or configured URL is not proof of receipt unless the HTTP response is successful and correlated evidence is retained.
- The adapter's Z-score escalation threshold is a local integration rule, not a validated AI-text detection threshold.

## Integration acceptance checklist

- [ ] Provisioned service identity and tenant-bound authorization contract approved by the Tinlance Agent Platform owners.
- [ ] TLS and service authentication verified in the target environment.
- [ ] Schema validation and explicit degraded-state handling tested.
- [ ] Scraped content, generated content, outreach and ThreatFade event paths tested end to end.
- [ ] Consumer proves it stops downstream classification/send/deployment on block or degraded inspection.
- [ ] Retry, idempotency, timeout, logging-redaction and delivery acknowledgement tests pass.
- [ ] TSIC contract conformance evidence recorded.

Do not use the adapter as a production security control until all required checks are complete.
