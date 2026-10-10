# Billing webhook security and idempotency

## Security boundary

The Lemon Squeezy and Paddle endpoints are public webhook receivers, not Clerk-authenticated user APIs. Each request must pass the provider-specific signature verifier before JSON is processed. Paid entitlements are mapped only from configured provider variant/price IDs; an unknown identifier cannot grant a plan.

## Durable deduplication and ordering

- Paddle events use the provider's stable top-level `event_id` as the idempotency key.
- Lemon Squeezy's documented payload does not expose a stable event ID, so Aithyrex uses a SHA-256 digest of the exact signed request body as the delivery key.
- PostgreSQL enforces a unique `(provider, event_key)` constraint. The event ledger stores the payload digest and event metadata, not the raw webhook body or secret.
- Event reservation, tenant-plan mutation and the final event status are committed in one database transaction. If the tenant update fails, the transaction rolls back and the route returns a retryable failure.
- A repeated completed event is acknowledged as a duplicate without applying the entitlement update again. Reusing a Paddle event ID with a different payload digest is rejected.
- Subscription events are serialized by locking the tenant row. Paddle's `occurred_at` and Lemon Squeezy's subscription `updated_at` are compared against the latest processed event for that provider/resource; an older or equal snapshot is marked stale and cannot overwrite newer state.
- Subscription events without a usable resource ID or event timestamp are rejected rather than being applied without ordering protection.

## Required database migration sequence

Apply migrations in order:

1. `001_initial_schema`
2. `002_durable_delivery_outbox`
3. `003_billing_webhook_idempotency`

Do not enable provider webhook endpoints against a database that has not applied migration 003. Verify migration state and database backup/restore procedures before production use.

## Operational limits and release evidence

- Provider secrets, live provider configuration, successful subscription lifecycle tests against provider sandboxes, and production delivery are environment-specific and are not proven by repository CI.
- The ledger currently has no automated retention/pruning policy or operator-facing replay UI. Define retention, alerting and recovery procedures before high-volume production use.
- Signature validation and deduplication do not replace provider account configuration review, subscription reconciliation, independent security assessment, or controlled production verification.
- Never log raw webhook payloads, signatures, or signing secrets. Log event IDs/digests and normalized status only.
