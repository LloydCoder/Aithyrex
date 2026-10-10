# Durable evidence and delivery outbox contract

**Phase:** 11 — durable evidence/delivery  
**Storage:** PostgreSQL `detection_events` + `delivery_outbox`  
**Worker setting:** `OUTBOX_WORKER_ENABLED=true` (required in production)

## Transaction boundary

For each tenant-bound detector verdict, Aithyrex awaits evidence persistence before returning the verdict. The detection event, any high/critical alert rows, and three delivery intents (`siem_dispatch`, `alert_dispatch`, `nis2_dora_evaluate`) are inserted in one database transaction. Context-inspection and behavioral-sequence findings use the same persistence path. If persistence fails, the response is marked degraded; it does not silently present the evidence write as successful.

The outbox payload contains the event ID, not a duplicate of raw prompt or completion text. Existing detector evidence is stored in the event record. Logs for persistence failures use exception types rather than raw database exception text.

## Worker lifecycle and retry semantics

The FastAPI lifespan owns a named worker task, retains its reference, cancels it on shutdown, and awaits bounded shutdown. The worker claims rows with PostgreSQL row locks and `SKIP LOCKED`, sets a processing lease, and dispatches outside the claim transaction. Stale processing leases can be reclaimed after five minutes.

Statuses: `pending`, `processing`, `delivered`, `dead`. Failures use exponential backoff capped at 1,024 seconds, with a maximum of 12 attempts before dead-lettering. The last-error field stores only the exception class, not exception text. Unique event/type and dedupe-key constraints prevent duplicate outbox intents for the same event.

Delivery is **at least once**, not exactly once. A process crash after an external side effect but before marking the row delivered can cause a retry and duplicate notification. Downstream idempotency is not assumed. A dead-letter row remains durable for operator inspection; no self-service replay endpoint is claimed.

## Migration and deployment

Apply Alembic revision `002_durable_delivery_outbox` after `001_initial_schema` before deploying the delivery worker. Apply `003_billing_webhook_idempotency` after revision 002 before enabling billing webhook processing; see [Billing Webhook Security](BILLING_WEBHOOK_SECURITY.md). Set `OUTBOX_WORKER_ENABLED=true` in production; production startup refuses to run with the worker disabled. The worker must be monitored for pending/processing/dead row counts and repeated delivery failures.

## Boundaries and residual risks

- PostgreSQL is the durable source for event evidence and delivery intents; Redis is still the real-time usage counter source.
- If PostgreSQL is unavailable before commit, the event/outbox transaction cannot be made durable. The response is marked degraded, but no database-backed retry can exist until the database returns.
- External delivery can duplicate after an ambiguous network result; exactly-once delivery is not promised.
- NIS2/DORA high-cluster aggregation still uses in-memory state and can reset on process restart; durable compliance aggregation is a separate gap.
- Outbox retention, operator replay tooling, and production metrics/alerts for dead letters must be configured or implemented before claiming complete operational readiness.
