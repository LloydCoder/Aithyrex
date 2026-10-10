# Tinlance integration conformance — Aithyrex

**Machine-readable manifest:** [aithyrex-contracts.v1.json](../contracts/tsic/aithyrex-contracts.v1.json)

## Authority boundary

Tinlance Agent Platform owns agent identity, tenant authorization, policy, approval, action binding, and governed execution. Aithyrex validates Platform-signed assertions, inspects the exact signed payload, and emits versioned advisory findings. Aithyrex does not return an allow/deny/approval grant and never executes a tool/action. This conformance record does not claim a live Platform-to-Aithyrex deployment or end-to-end interception.

## Contract matrix

| Contract | Endpoint | Signed header | Replay namespace | Duplicate |
|---|---|---|---|---|
| `aithyrex.agent-action-signal.v1` | `POST /api/v1/detect/action` | `X-Platform-Action-Assertion` | `agent-action` | HTTP 409 |
| `aithyrex.context-inspection.v1` | `POST /api/v1/detect/context` | `X-Platform-Context-Assertion` | `context` | HTTP 409 |
| `aithyrex.behavioral-correlation.v1` | `POST /api/v1/detect/sequence` | `X-Platform-Sequence-Assertion` | `sequence` | HTTP 409 |

All three contracts require an RS256 assertion with configured issuer/audience, a bounded lifetime, tenant binding, and a canonical digest of the exact request payload. Request mutation after signing is rejected. A signature proves assertion integrity and origin under the configured trust anchor; it does not establish that source content is safe or that a proposed action is authorized.

## Replay and Redis behavior

- Consume the assertion only after signature and payload-binding validation, before tenant capacity checks and detector work.
- Use an atomic Redis `SET key 1 NX EX ttl` operation; namespace by contract and tenant.
- Store only a SHA-256 digest of the assertion `jti` in the key, not the raw identifier.
- Set TTL from `exp - now`, bounded to at most 300 seconds. Expired assertions are rejected.
- A duplicate returns HTTP 409. Replay-state failure returns HTTP 503; the request must not fall through to detection.
- A consumed assertion is one-shot. If downstream capacity or persistence fails, the trusted Platform must mint a fresh assertion for a retry.
- Redis clients are initialized using the synchronous `redis.asyncio.from_url` factory and closed during application shutdown. Rate-limit and usage-counter state failures remain fail-closed.

## Verification

The CI suite must verify:
- Atomic first-use/replay behavior, TTL bounds, hashed JTI keys, contract namespace separation, expired assertions, and Redis outage fail-closed behavior.
- HTTP-level first-use success and duplicate rejection for all three signed endpoints.
- Payload tampering rejection before assertion consumption.
- Correct Redis client construction and shutdown behavior.
- All three versioned contracts and advisory-only response semantics remain represented in the machine-readable manifest.

## Remaining external gates

- Live integration against the real Tinlance Agent Platform issuer, key lifecycle, tenant provisioning, and execution hooks.
- Cross-repository contract tests against a pinned Platform build and a deployment-level pre-side-effect test proving the executor cannot run before Platform policy/approval.
- Coordinated key rotation, production Redis HA/monitoring, and operational replay-state alerts.
- Detector accuracy and false-positive/false-negative calibration on a representative labeled corpus.

A passing local/CI conformance suite establishes receiver-side behavior for the covered contracts only. It does not certify cross-repository or production integration.
