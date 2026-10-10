# Aithyrex threat coverage matrix

**Scope:** repository-local detector and API evidence as of Phase 7. This is a traceability document, not a claim of comprehensive threat coverage, validated accuracy, certification, or production readiness.

Status meanings:
- **Implemented / heuristic:** deterministic code exists and has unit coverage; accuracy and false-positive rate are not established.
- **Partial:** a signal can be observed, but a key trust boundary, semantic capability, or evaluation gate is missing.
- **Deferred:** no complete control is claimed in this phase.

| Threat / control | Status | Implementation and test evidence | Limits / next control |
|---|---|---|---|
| Direct prompt injection and role override | Implemented / heuristic | `PromptInjectionDetector`; `test_ignore_previous_instructions`, `test_system_tag_injection`, `test_developer_mode`, `test_persona_hijack` | Rule matching is not a semantic classifier. Confidence is explicitly uncalibrated. |
| Encoded prompt-injection instructions | Implemented / heuristic | Bounded Base64/hex decoding; `test_base64_encoded_injection_is_detected_without_decoding_evidence`, `test_hex_encoded_injection_is_detected_without_decoding_evidence` | Only bounded common encodings are inspected; arbitrary obfuscation, encryption, and multimodal payloads are not covered. |
| Invisible Unicode compatibility/control obfuscation | Partial | NFKC normalization and removal of selected zero-width/bidi controls; `test_invisible_unicode_controls_are_normalized` | Does not normalize every homoglyph or language-specific obfuscation. |
| Credential-like strings in prompts/completions | Implemented / heuristic | Local credential-format patterns; `test_paystack_secret_key_detected`, `test_anthropic_key_detected`, `test_aws_access_key_detected`, `test_credential_evidence_never_contains_secret_substrings` | Pattern list is not exhaustive or independently calibrated. Provider formats change; false-positive/negative rates are unknown. |
| Sensitive-value redaction in detector evidence | Implemented for credential matches and prompt-injection rule evidence | Credential matches return `[REDACTED]`; prompt-injection evidence returns stable rule IDs, not matched text | Audit logging, tracing, SIEM exporters and every other detector still require independent privacy review. |
| Oversized agent messages / aggregate content | Implemented at API schema boundary | `test_agent_message_content_limit_is_enforced`, `test_agent_aggregate_content_limit_is_enforced_without_echoing_content`, `test_agent_message_count_limit_is_enforced` | Reverse-proxy/server request-body limits must also be configured in deployments; Pydantic validation is not a network-layer body-size limit. |
| Indirect injection in RAG documents and tool outputs | Partial | Concatenated agent content is scanned by the rule detector | Current route does not authenticate source labels or bind findings to retrieved-document/tool-output provenance. Source-aware lineage and authorization are deferred to Phase 9. |
| ThreatFade C2/covert-channel signals over AI text | Partial; advisory-only | ThreatFade bridge and offline evaluator from Phase 6 | No representative, independently labeled AI-interaction corpus is present. Network-traffic performance does not validate AI-text performance. No enforcement or calibrated confidence claim. |
| Platform-signed pre-execution action signal | Implemented signal receiver | `POST /api/v1/detect/action`; RS256 assertion and exact canonical payload binding; integration tests cover tampering and advisory-only results | Does not authorize or execute. Live cross-repository integration, persistent replay deduplication, and automated key rotation are not yet verified. |
| Tool-call authorization / excessive agency | Deferred to authoritative control plane | Aithyrex emits detection findings only | Aithyrex is not the authorization authority. Tinlance Agent Platform must enforce identity, policy, approvals, exact action binding, and pre-side-effect mediation. |
| Multi-turn / cross-agent behavioral correlation | Deferred | No validated temporal correlation control claimed | Requires durable event identity, sequence semantics, and representative evaluation. |
| Data poisoning / RAG integrity | Partial | Signed context-bundle receiver binds source IDs/types/content hashes and marks every source untrusted; detection is bundle-level | Does not prove retrieval authorization, content safety, per-source detector attribution, live Platform wiring, or calibrated effectiveness; requires a labeled evaluation corpus. |
| Multimodal prompt injection (image/audio/video) | Deferred | No coverage claimed | Requires modality-specific parsing, safe OCR/transcription, provenance, and adversarial tests. |
| Structured-output/schema abuse and downstream side effects | Deferred | Versioned API response contracts do not validate every model output or downstream action | Must be handled at integration boundaries with schema validation and Platform-governed execution. |

## Required interpretation

1. A passing unit test demonstrates the asserted behavior for that fixture; it does not establish detector effectiveness.
2. The `confidence` field is not a probability unless a versioned calibration study says so. The current prompt-injection and credential detectors report `confidence_calibrated: false` and use zero as the uncalibrated numeric value.
3. The ThreatFade evaluator's synthetic tests validate metrics and gate mechanics only. Phase 6's empirical acceptance gate remains open until a representative, independently labeled corpus and same-sample baseline are evaluated.
4. No detector in this matrix replaces Tinlance Agent Platform authorization or grants permission to execute a tool/action.
