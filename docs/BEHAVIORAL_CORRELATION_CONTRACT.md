# Behavioral sequence correlation contract

**Contract:** `aithyrex.behavioral-correlation.v1`  
**Endpoint:** `POST /api/v1/detect/sequence`  
**Caller:** Tinlance Agent Platform or trusted adapter holding a Platform-signed RS256 assertion.

## Purpose and boundary

This endpoint correlates an ordered, signed bundle of event metadata. It does not execute actions, block actions, grant permission, or replace the Platform's authorization policy. The event sequence must be supplied by a trusted caller and bound to the exact request bytes through a canonical digest. A signed sequence establishes integrity of the submitted metadata; it does not independently prove the truth of every event.

## Request and limits

Header: `X-Platform-Sequence-Assertion: <short-lived RS256 JWT>`

The body includes `agent_id`, `sequence_id`, and an ordered list of events. Each event has a unique `event_id`, a constrained `event_type`, a timezone-aware `occurred_at`, and optional bounded `tool_name`, `finding_id`, and signal identifiers.

- 2–100 events per sequence.
- Maximum sequence span: 1 hour.
- Event timestamps must be ordered and cannot be more than 30 seconds in the future.
- Event IDs must be unique.
- The JWT must have a positive lifetime no greater than 300 seconds.
- The signed digest covers agent ID, sequence ID, ordered event IDs/types/timestamps, tool names, finding IDs, and signal identifiers. Timestamps are canonicalized to UTC before hashing.

Deployments must set an upstream/server request-body limit; schema-level limits run after JSON parsing.

## Deterministic correlation rules

| Rule ID | Sequence | Window | Severity |
|---|---|---:|---|
| `credential_exposure_then_external_transfer` | Credential-exposure signal → external-transfer request | 10 min | Critical |
| `injection_then_external_action` | Prompt-injection signal → external-transfer request or tool execution | 10 min | High |
| `sensitive_access_then_external_transfer` | Sensitive-data access → external-transfer request | 10 min | High |
| `denied_action_retried` | Policy denial → same tool proposed again | 5 min | Medium |

These are explainable heuristics, not calibrated probabilities or verdicts of malicious intent. A correlation finding contains the rule ID, paired event IDs, and elapsed time; it does not include raw prompts or customer content. An isolated signal does not produce a multi-event correlation finding.

## Response and failures

The response uses `aithyrex.behavioral-correlation.v1`, reports the analyzed event count and matched rules, and always declares `advisory_only=true`, `authorization_performed=false`, and `execution_performed=false`. The embedded finding uses `action=log` and `blocked=false`.

Missing assertion returns 401; signed sequence mismatch returns 403; invalid/oversized/unordered sequences return 422; missing trust or unavailable tenant/capacity state returns 503; rate/usage limits return 429.

## Known limitations

- This is caller-supplied sequence analysis, not a persistent event stream or cross-request state store.
- No durable replay deduplication, cross-agent graph correlation, or production Platform wiring is claimed.
- Event truth and source authorization depend on the trusted Platform assertion issuer.
- Correlation rules are not empirically calibrated; false positives and false negatives are expected until evaluated against a labeled, representative corpus.
- Correlation output never authorizes or blocks an action.
