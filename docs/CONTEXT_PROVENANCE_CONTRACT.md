# Context provenance inspection contract

**Contract:** `aithyrex.context-inspection.v1`  
**Endpoint:** `POST /api/v1/detect/context`  
**Caller:** Tinlance Agent Platform or a trusted adapter holding a Platform-signed RS256 assertion.

## Boundary and semantics

Aithyrex inspects a context bundle and returns a versioned threat signal. It does not authorize retrieval, approve a context source, grant execution permission, or execute actions. Tinlance Agent Platform remains authoritative for identity, tenant binding, retrieval authorization, policy, approval, and governed execution. Auctaryn remains the separate context/action-risk product.

A valid signature proves the assertion was signed by the configured trust anchor and that the signed bundle has not changed. It does **not** prove that the underlying source is safe, that the source was authorized, or that a document's instructions should be followed. Every source is explicitly marked `trust_boundary=untrusted`.

## Request

Header: `X-Platform-Context-Assertion: <short-lived RS256 JWT>`

Example body:

```json
{
  "agent_id": "agent-42",
  "context_id": "ctx-42",
  "items": [
    {"source_type": "retrieved_document", "source_id": "doc-7", "content": "Retrieved text"},
    {"source_type": "tool_output", "source_id": "tool-2", "content": "Tool response"}
  ]
}
```

Supported source types: `retrieved_document`, `tool_output`, `memory`, `user_input`, `model_output`.

Limits: 32 items; 20,000 characters per item; 100,000 aggregate characters; 250,000 serialized UTF-8 bytes. The route rejects oversized bundles rather than truncating them. The serialized limit is enforced after JSON parsing; deployments must also configure an upstream/server request-body limit to protect the parser from oversized raw HTTP bodies.

## Signed claims

Required claims: `iss`, `aud`, `sub`, `jti`, `tenant_id`, `context_id`, `context_bundle_sha256`, `iat`, `exp`.

- `iss` and `aud` must match configured Platform trust anchors.
- `sub` must equal the request agent ID.
- `tenant_id` must identify an active, provisioned Aithyrex tenant in server-side state.
- `context_id` must equal the request context ID.
- `context_bundle_sha256` is SHA-256 of canonical UTF-8 JSON containing the agent ID, context ID, and ordered source entries (source type, source ID, and content). JSON object keys are sorted; separators are compact; non-JSON numeric values are rejected.
- `iat` and `exp` must be valid integer timestamps with a positive lifetime no longer than 300 seconds.
- Only RS256 is accepted. Current trust-anchor settings are `PLATFORM_ACTION_JWT_PUBLIC_KEY`, `PLATFORM_ACTION_JWT_ISSUER`, and `PLATFORM_ACTION_JWT_AUDIENCE`.

## Response

The response includes the bundle finding and source evidence (source ID/type and SHA-256 of content), while excluding raw source content from provenance. It always declares `advisory_only=true`, `authorization_performed=false`, and `execution_performed=false`; the embedded finding uses `action=log` and `blocked=false`.

Threat detection currently scans the combined bundle. The response preserves source lineage but does not claim that a particular detector fired on a particular source. Detection confidence is not calibrated without a representative labeled corpus.

## Failures and residual risks

- Missing/invalid assertion: HTTP 401.
- Signed bundle mismatch: HTTP 403.
- Missing trust configuration, unavailable tenant/capacity state: HTTP 503.
- Invalid/oversized bundle: HTTP 422.
- Rate/usage limit: HTTP 429.
- No content is truncated or echoed in validation errors.
- The route does not execute actions or return authorization grants.
- Persistent replay deduplication, automated key rotation, live Platform integration, retrieval authorization, per-source detector attribution, and empirical detection calibration are not claimed complete.
