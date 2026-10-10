# Aithyrex SDK and Gateway Integration Contract v1

**Status:** Implemented SDK contract; provider/framework coverage is explicitly bounded.  
**Applies to:** Python client, OpenAI/Anthropic wrappers, LangChain callback, LlamaIndex observer and legacy integration import paths.

## Security invariants

1. SDK calls use the configured Aithyrex API URL and a verified user/session bearer token. The package does not treat a static API key as a distinct credential type; the current api_key parameter is a compatibility alias for a bearer session token.
2. Missing URL/token, insecure non-loopback HTTP, transport errors, non-2xx responses, malformed responses, invalid trace identifiers and mismatched response/request trace IDs produce a degraded blocked verdict.
3. Every SDK inspection generates a UUID X-Request-ID. If the server returns the ID in the response body or response header, it must be a valid UUID and match the request ID. The SDK exposes the correlated ID on the verdict for support and evidence correlation.
4. Provider wrappers must inspect supported text before invoking the upstream model. If preflight is blocked or degraded, the provider request must not be sent.
5. Supported wrappers inspect returned text and tool-call descriptions before returning the response to the caller. This does not authorize or execute a tool call, and it cannot reverse provider-side processing that has already occurred.
6. Streaming, multimodal payloads, provider-specific tool execution, framework lifecycle edge cases and complete mediation of MCP/tool side effects are not claimed as secured by these wrappers. Unsupported inputs/streaming must be rejected explicitly rather than silently bypassed.
7. Framework callbacks and observers are defense-in-depth telemetry/integration points, not a substitute for the Tinlance Agent Platform's authoritative pre-side-effect policy/approval/execution boundary.
8. Aithyrex findings remain advisory security signals. Only the Tinlance Agent Platform may authorize or govern execution.

## Trace correlation

The SDK creates a fresh UUID per inspection and sends it as X-Request-ID. Aithyrex echoes its validated request identifier in the response header and versioned response body. When a response supplies either identifier, the SDK validates UUID syntax and checks that body/header values agree with the originating request. A mismatch is treated as a protocol-integrity failure and fails closed.

The trace ID is correlation metadata, not authentication, tenant identity, authorization, or proof that an event was durably persisted.

## Integration support matrix

| Integration | Current behavior | Explicit limitation |
|---|---|---|
| OpenAI sync/async chat completions | Preflight, provider call, postflight; checks text and serializes returned tool-call metadata for inspection | Streaming and multimodal input rejected; tool execution is outside this wrapper |
| Anthropic synchronous messages | Preflight and postflight of supported text/tool-use content | Async and streaming are unsupported; multimodal/tool-result content rejected |
| LangChain callback | Preflight on LLM start, postflight on completion, tool input/output hooks | Callback semantics vary by framework/version; not an authoritative execution gate |
| LlamaIndex observer | Inspects supported LLM, retrieval and tool event text | Observer API/version behavior varies; not an authoritative execution gate |
| AutoGen/CrewAI compatibility middleware | Legacy compatibility surface only | Do not treat it as a supported production security boundary unless an integration-specific acceptance test proves pre-side-effect coverage |

## Required conformance tests

- Missing credentials and API URL fail closed.
- Insecure remote HTTP fails closed.
- Timeout, connection, HTTP, JSON and schema errors fail closed.
- Request IDs are valid UUIDs and are sent on every inspection.
- Invalid or mismatched response trace IDs fail closed.
- A blocked/degraded preflight prevents the upstream provider call.
- Supported output/tool-call content is inspected before a response is returned to the caller.
- Unsupported streaming/multimodal requests are rejected explicitly.
- Framework hook errors are not silently treated as clean.
- Integration tests prove behavior against the actual supported provider/framework versions before a compatibility claim is promoted.

## Release gate

A green CI workflow proves only the tests and static checks executed by that workflow. It does not establish provider-wide coverage, production deployment, detector accuracy, regulatory compliance, or complete pre-side-effect tool/MCP mediation. Keep those gates open until reproducible integration/E2E evidence exists.
