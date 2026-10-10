# Platform-signed agent action signal contract

**Contract:** `aithyrex.agent-action-signal.v1`  
**Endpoint:** `POST /api/v1/detect/action`  
**Caller:** Tinlance Agent Platform or a trusted adapter holding a Platform-signed assertion.

## Architectural boundary

Aithyrex inspects the exact proposed tool/action payload and emits threat findings. It does **not** approve, deny, block, execute, or grant permission for an action. The Tinlance Agent Platform remains authoritative for agent identity, policy, approvals, action binding, and governed execution. Auctaryn may perform its separate context/action-risk assessment; Aithyrex must not duplicate that authority.

The route is intentionally separate from the user-facing Clerk-authenticated detection routes. It accepts a Platform assertion signed with RS256 and verifies the assertion against a configured public key, issuer, and audience. Missing verification configuration fails closed with HTTP 503.

## Request

Header:

```http
X-Platform-Action-Assertion: <short-lived RS256 JWT>
```

JSON body:

```json
{
  "agent_id": "agent-42",
  "action_id": "action-123",
  "tool_name": "send_email",
  "arguments": {"to": "person@example.com", "subject": "Review"},
  "context": "Human approval is pending."
}
```

Limits:
- At most 100 messages for the agent-inspection API.
- Action tool name at most 256 characters; action ID and agent ID at most 255 characters.
- Action context at most 20,000 characters.
- Canonical action payload at most 100,000 UTF-8 bytes.
- The route validates the tenant against server-side active-tenant state. Caller-provided tenant or role labels are not trusted.

## Assertion claims

Required signed JWT claims:

| Claim | Requirement |
|---|---|
| `iss` | Exact configured Platform issuer |
| `aud` | Must include the configured Aithyrex audience |
| `sub` | Must equal request `agent_id` |
| `tenant_id` | UUID of an active provisioned Aithyrex tenant |
| `action_id` | Must equal request `action_id` |
| `tool_name` | Must equal request `tool_name` |
| `action_payload_sha256` | SHA-256 of canonical action payload bytes |
| `jti` | Non-empty assertion/event identifier, max 128 characters |
| `iat`, `exp` | Integer timestamps; lifetime must be positive and no more than 300 seconds |

Only `RS256` is accepted. The public key, issuer, and audience are configured through `PLATFORM_ACTION_JWT_PUBLIC_KEY`, `PLATFORM_ACTION_JWT_ISSUER`, and `PLATFORM_ACTION_JWT_AUDIENCE`. No development bypass or unsigned-token mode exists.

### Canonical payload hash

The signed `action_payload_sha256` is the lowercase SHA-256 digest of UTF-8 bytes from JSON serialized with sorted keys, compact separators, `ensure_ascii=False`, and `allow_nan=False`:

```json
{"tool_name":"...","arguments":{},"context":"..."}
```

A changed tool name, argument, or context causes HTTP 403. The assertion must be generated for the exact payload to be inspected.

## Response contract

The response contains `detected`, `severity`, `degraded`, evidence, and these explicit boundary fields:

- `advisory_only: true`
- `authorization_performed: false`
- `execution_performed: false`
- embedded finding `action: "log"` and `blocked: false`

It intentionally has no `allowed`, `denied`, or `approved` result. A degraded detector is a signal for the Platform to handle under its own policy; it is not an Aithyrex authorization decision.

## Failure behavior and residual risks

- Missing/invalid assertion: HTTP 401.
- Action/claim mismatch: HTTP 403.
- Missing trust configuration or unavailable tenant state: HTTP 503.
- Invalid/oversized body: HTTP 422.
- No action is executed by this endpoint, including on detection or error.
- The current endpoint does not persist a replay cache. `jti` is returned for downstream deduplication; replaying an assertion can duplicate a signal but cannot execute or authorize an action here. Durable idempotency is a later evidence-pipeline requirement.
- Key rotation is configuration-based; coordinated Platform/Aithyrex rotation is required. JWKS discovery/rotation automation is not claimed.
- This repository defines and tests the receiver contract. A live Platform-to-Aithyrex integration and end-to-end action interception are not claimed until separately tested.
