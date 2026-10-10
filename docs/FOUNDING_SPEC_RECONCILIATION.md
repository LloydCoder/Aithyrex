# Aithyrex Founding Specification Reconciliation and Remediation Ledger

**Status:** Active remediation; not a release-readiness attestation.
**Product lineage:** Aithyrex (formerly AI Shield).
**Repository:** https://github.com/LloydCoder/Aithyrex
**Architectural authority:** Tinlance Agent Platform remains authoritative for identity, authorization, policy, approvals, governed execution, sandboxing, secrets, budgets and authoritative audit/evidence.

## 1. Purpose and evidence rules

This document reconciles the founding AI Shield specification with the current repository and establishes a phase-gated remediation plan. Repository presence is evidence of code, not proof of correct runtime behavior. Tests are evidence only for the paths and fixtures they exercise. A green workflow is necessary but not sufficient for production readiness.

Do not claim AI-text detection accuracy, false-positive rate, complete MITRE coverage, regulatory filing, live ecosystem integration, SLA, or deployment status without reproducible evidence tied to version, environment, dataset and date. ThreatFade's reported network-traffic metrics do not validate AI-text detection.

## 2. Canonical ecosystem boundaries

- **Aithyrex:** AI-interaction threat detection, telemetry enrichment and evidence-bearing findings.
- **Auctaryn:** agent context, memory, skill and proposed-action risk assessment. It is not a competing execution authority.
- **Tinlance Agent Platform:** authoritative identity, tenant binding, authorization, policy, approval, governed execution, tools/MCP, sandbox, secrets, budgets and audit/evidence.
- **ThreatFade:** separately operated behavioral/network detection service; consumers must preserve unavailable/degraded states.
- **AURONTRA:** IT resilience, incident/ticket workflows and bounded remediation coordination.
- **FusionOps:** response workflow orchestration.
- **KalevioAI:** compliance evidence/reporting workflows; notification or export does not prove legal submission.
- **TSIC:** versioned cross-repository contracts, conformance and end-to-end integration evidence.
- **TADL:** developer-artifact, schema and compile/evaluation validation.

Security flow: observe → detect/correlate → submit a finding or recommendation → authoritative Platform policy/approval → authorized execution or response workflow → preserve correlated evidence. Aithyrex findings must never be interpreted as authorization grants.

## 3. Founding capability inventory

| Capability | Repository evidence | Required qualification / acceptance gate |
|---|---|---|
| Prompt injection detection | `backend/detectors/prompt_injection.py` | Representative adversarial corpus, false-positive/negative measurements, regression tests and model-specific scope.
| Credential exposure detection | `backend/detectors/credential_leak.py` | Test corpus for supported credential formats, redaction tests, secret-safe logging and measured coverage; no unsupported accuracy claims.
| Covert-channel analysis | `backend/detectors/covert_channel.py` | Encoding heuristics are indicators, not proof; ThreatFade outage must be explicit and AI-text evaluation must be independent.
| C2-style behavior | `backend/detectors/c2_behaviour.py` | Network telemetry and AI interaction are different domains; calibrate thresholds with representative data.
| RAG/data-poisoning heuristics | `backend/detectors/data_poisoning.py` | Do not claim training-data poisoning detection unless training/data lineage is observed and tested.
| Parliament ensemble | `backend/agents/parliament.py` | Advisory only. It may escalate, never downgrade hard BLOCK/CRITICAL decisions; missing votes/telemetry are not ALLOW.
| Tenant authentication | `backend/core/auth.py` | Verify JWT signature, issuer, expiry and authorized party; plan entitlements must come from server-side billing state.
| Quotas and block state | `backend/core/usage_counter.py`, `backend/core/block_mode.py` | Unavailable state cannot be represented as zero usage or an empty blocklist.
| SIEM and compliance | `backend/core/siem_dispatch.py`, `backend/compliance/nis2_dora.py` | Durable delivery, retries, idempotency, acknowledgement and auditable human/legal submission boundaries.
| Dashboard and billing | `frontend/` and `backend/core/billing.py` | Demo data must be labeled; UI must not report unperformed exports/filings; provider signatures and entitlements must be authoritative.
| Framework SDKs | `ai_shield/`, `integrations/` | Test sync/async/streaming, tool-call mediation, provider versions, error paths and pre-side-effect enforcement.

## 4. Baseline blockers and disposition

The baseline findings below were verified against the repository and CI evidence. Phase 0–4 changes address the listed code/CI blockers; the final acceptance gate is the current head's green workflow evidence in Section 6.

1. **Dependency resolution:** the original NumPy 2.1.1 / LangChain 0.2.16 conflict was resolved by pinning NumPy 1.26.4. Dependency installation and the dependency vulnerability audit now pass.
2. **Static analysis:** the original Ruff findings were fixed rather than ignored. Ruff is blocking in CI and currently passes; Bandit and Semgrep also pass.
3. **Secret scanning:** the prior TruffleHog identical-base/head configuration is replaced with event-aware ranges for PR/push events and a full-history mode for scheduled/manual scans. The current secret scan passes.
4. **Authentication and tenancy:** arbitrary-token fallback was removed. Clerk JWT signature/claim verification is explicit, active organization tenancy and server-side plan resolution are required, production configuration validates trust anchors and TLS-backed dependencies, and authenticated API calls use tenant-scoped Redis rate limiting.
5. **Decision integrity:** Parliament is advisory. Existing BLOCK/CRITICAL decisions are immutable, ALLOW votes cannot erase detector findings, and missing/invalid votes or required ThreatFade telemetry do not prove safety.
6. **Detector and dependency failures:** ThreatFade transport/schema failures are explicitly degraded. Detector exceptions and invalid detector results become high-severity degraded findings and fail closed. Block-state and usage-accounting outages fail closed; inference reservations use atomic Redis accounting.
7. **Enforcement boundaries:** the model allowlist enforcement endpoint is disabled; block/unblock request identifiers, reasons and TTLs are bounded. Failed block-state writes are not reported as successful.
8. **Billing:** absent webhook secrets/signatures are rejected, Paddle's timestamped signature format is verified, and unknown product/price identifiers cannot grant paid entitlements. Provider replay protection and durable idempotent processing remain later-phase work.
9. **Frontend truthfulness:** synthetic dashboard metrics/alerts and simulated reporting actions were removed. Unimplemented live feeds, billing data, exports and filings are explicitly shown as unavailable rather than successful.
10. **Explicit later-phase work:** durable outbox/retry/idempotency, service-to-service identity for product integrations, live tenant-scoped event publishing, persisted finding/report queries, and verified pre-side-effect mediation for tool/MCP/streaming paths are not claimed complete in Phase 0–4.

## 5. Phase sequence and acceptance gates

Each phase is completed only after code/tests/docs are reconciled, required workflows are green, a phase-specific forensic audit is recorded, and residual risk is documented. Do not skip phases because a later phase appears more visible.

### Stage A — Baseline and safe foundations

- **Phase 0 — Forensic baseline and architecture reconciliation.** Inventory repository, workflows, deployment claims, contracts, product names and evidence; classify every claim as implemented/tested/deployed/integrated/unverified. Acceptance: this ledger and an auditable baseline commit exist.
- **Phase 1 — Reproducible build and blocking CI.** Resolve dependency constraints, fix Ruff findings, make tests and security scans actionable, pin third-party actions to immutable SHAs, and ensure scans actually execute. Acceptance: all required CI/security workflows green without masking required tests.
- **Phase 2 — Identity and tenant isolation.** Verify Clerk JWTs; remove implicit development auth; bind requests to server-side tenant membership; authenticate WebSocket sessions; test cross-tenant isolation. Acceptance: invalid, expired, wrong-issuer, wrong-party and cross-tenant requests are denied.

### Stage B — Decision integrity and runtime safety

- **Phase 3 — Deterministic policy integrity.** Hard BLOCK/CRITICAL decisions cannot be downgraded by LLM votes; malformed, missing or conflicting votes abstain/escalate; allowlists cannot skip mandatory detectors. Acceptance: adversarial decision-table tests pass.
- **Phase 4 — Dependency failure, quotas, billing and rate limits.** Required detector outages and accounting/block-state outages are explicit; quota enforcement is atomic; provider webhook signatures are correct; unknown product IDs never grant paid entitlement. Acceptance: fail-open regression tests pass.
- **Phase 5 — Canonical contracts and telemetry schemas.** Version findings, trace IDs, provenance, tenant binding, degraded-state semantics and stable error contracts. Acceptance: schema compatibility and invalid-payload tests pass.

### Stage C — AI-specific detection assurance

- **Phase 6 — ThreatFade bridge and statistical validation.** Validate transport/auth/schema, retries and degraded states; evaluate AI interaction data separately from network traffic. Acceptance: reproducible evaluation report with dataset, baseline, precision/recall, calibration and false-positive bounds.
- **Phase 7 — Threat coverage.** Test prompt injection, sensitive-data exposure, indirect injection, tool-output injection, context overflow and supported encoding heuristics; map to versioned threat taxonomies without claiming full coverage from static mappings. Acceptance: threat-by-test traceability is complete for declared scope.
- **Phase 8 — Agent identity and pre-execution action risk.** Consume trusted action metadata, bind assessments to exact action/resource/agent/tenant/intent and preserve Platform authority. Acceptance: pre-side-effect mediation demonstrated with a trusted harness.
- **Phase 9 — Context, RAG and exfiltration controls.** Track provenance and trust boundaries across retrieved context, tool output and model output. Acceptance: isolation and indirect-injection regression corpus passes.
- **Phase 10 — Multi-step behavioral analysis.** Correlate events over time without inferring unsupported agent behavior from isolated text. Acceptance: reproducible sequence-based evaluation and bounded state lifecycle.

### Stage D — Reliability and ecosystem integration

- **Phase 11 — Durable evidence and delivery.** Replace fire-and-forget critical event delivery with durable outbox/queue, retries, idempotency and dead-letter handling. Acceptance: crash/retry/replay tests prove no silent loss.
- **Phase 12 — SDK, gateway and framework integration.** Verify supported provider/framework versions, sync/async/streaming behavior, tool call paths and failure policy. Acceptance: contract and end-to-end tests cover every claimed integration.
- **Phase 13 — Tinlance ecosystem and TSIC conformance.** Define versioned contracts for ThreatFade, Auctaryn, AURONTRA, FusionOps, KalevioAI and Platform adapters as appropriate; verify real endpoint compatibility. Acceptance: cross-repo conformance and traceable end-to-end evidence.

### Stage E — Evaluation and compliance

- **Phase 14 — AI security evaluation and red team.** Build repeatable adversarial suites, regression gates and a documented risk model. Acceptance: agreed coverage, thresholds and residual risks are evidence-backed.
- **Phase 15 — Compliance evidence and exports.** Distinguish mapping, evidence generation, report creation, notification and legal submission; verify export formats and provenance. Acceptance: no simulated filing is presented as real submission.

### Stage F — Enterprise readiness

- **Phase 16 — Operations and deployment.** Production configuration validation, secrets rotation, observability, SLOs, incident runbooks, backups, recovery and tenant-safe dashboards. Acceptance: tested deployment/recovery evidence.
- **Phase 17 — Independent assurance and controlled launch.** Full code/docs/workflow audit, threat model review, supply-chain evidence, release gates, rollback drill and accepted residual-risk register. Acceptance: independent phase audit and signed release decision.

## 6. Phase 0–4 implementation and forensic verification

**Branch:** `godmode/phase-00-04-hardening`  
**Verified implementation revision:** `c64f07309c05ac6c362378dc5745f01f70040155`  
**CI workflow:** https://github.com/LloydCoder/Aithyrex/actions/runs/38022062023  
**Security workflow:** https://github.com/LloydCoder/Aithyrex/actions/runs/38022061811

### Implemented in this phase

- Reconciled the README, architecture contract, operator runbook, CLI/client language, and launch material with canonical Aithyrex naming and Tinlance boundaries.
- Fixed the dependency conflict; made Ruff, Bandit, Semgrep, frontend dependency audit, TypeScript, ESLint, frontend build, tests, Docker build, and secret/dependency scanning blocking checks.
- Added Clerk JWT trust-anchor validation, active organization/tenant resolution, server-side entitlements, production startup gates, HTTPS ThreatFade requirements, and tenant-scoped atomic rate limiting.
- Made Parliament advisory-only and protected deterministic BLOCK/CRITICAL decisions from downgrade; made detector exceptions, invalid detector output, required ThreatFade telemetry loss, Redis usage failures and block-state failures fail closed.
- Added bounded inspection/enforcement inputs, atomic usage reservation, hardened webhook signatures and unknown-price handling, and explicit failure semantics for block-state writes.
- Removed misleading dashboard demo data and made unsupported reporting/live-feed capabilities visibly unavailable.
- Added regression coverage for authentication, rate limiting, production configuration, detector exceptions, Parliament integrity, billing signatures, enforcement bounds, block-state failures, and oversized requests.

### Verification evidence

The verified implementation revision passed all required jobs:

- Unit tests: **179 passed**.
- API integration tests: **28 passed**.
- Bandit SAST: passed.
- Ruff lint: passed.
- Semgrep: passed.
- Frontend dependency audit, TypeScript check, ESLint and production build: passed.
- Docker image build: passed.
- Dependency vulnerability audit: passed.
- TruffleHog secret scan: passed.

The CI run above reported all four CI jobs successful; the separate security workflow reported both jobs successful. The subsequent ledger-only update must also pass CI before this PR is merged.

### Phase 0–4 forensic conclusion

Phase 0–4 implementation and verification gates are satisfied for the scope stated here. This is **not** a claim that Phases 5–17 are complete, that all product integrations are live, that the system is deployed to production, or that the product is 100% secure.

Residual risks intentionally remain for later phases: versioned finding/trace/provenance contracts; AI-specific ThreatFade statistical validation; broader threat-evaluation corpora; exact action binding and pre-side-effect Platform mediation; RAG/context lineage; multi-step behavior correlation; durable evidence delivery; provider/framework streaming coverage; cross-repository TSIC conformance; red-team evaluation; verified compliance exports; production deployment/recovery drills; and independent assurance.

The branch is not merged at the time of this ledger revision. The PR must remain open until the documentation-updated head has green CI/security workflows and the phase audit is accepted.

## 7. Phase 5 implementation and forensic verification

**Phase branch:** `godmode/phase-05-contracts-telemetry`  
**Verified implementation revision:** `e6398837037a4c9639dd1c17b8dc1fdcab010d79`  
**CI workflow:** https://github.com/LloydCoder/Aithyrex/actions/runs/38022923598  
**Security workflow:** https://github.com/LloydCoder/Aithyrex/actions/runs/38022923594

### Implemented

- Published all detection response and error schemas in OpenAPI, alongside canonical Pydantic contracts for detector evidence (`aithyrex.detector-evidence.v1`), findings (`aithyrex.finding.v1`), detection responses (`aithyrex.detection-response.v1`) and errors (`aithyrex.error.v1`).
- Added UUID request IDs, validated/canonicalized `X-Request-ID` propagation, response headers, structured request lifecycle logs and safe internal-error responses.
- Kept legacy flat detection fields while adding a nested versioned finding for compatibility.
- Standardized FastAPI and Starlette HTTP errors, including 404s; validation errors omit rejected input values.
- Ensured blocked preflight detections retain a versioned finding inside the error detail.
- Updated architecture documentation and added schema, trace propagation, validation redaction, unhandled-error and blocked-finding regression tests.

### Verification evidence

- Unit tests: **184 passed**.
- API integration tests: **34 passed**.
- Bandit, Ruff and Semgrep: passed.
- Frontend dependency audit, TypeScript, ESLint and production build: passed.
- Docker image build: passed.
- Dependency vulnerability audit and secret scan: passed.

### Phase 5 forensic conclusion

Phase 5 implementation and CI gates are green for the contract and traceability scope above. The finding model is a canonical schema, **not** durable storage, a transactional outbox, proof of downstream delivery, or proof of cross-service trace propagation. Those remain later-phase requirements. W3C Trace Context/OpenTelemetry export, persisted finding IDs, schema-registry publication, idempotent event delivery and consumer conformance are not claimed complete.

The documentation-only update must also pass CI/security workflows before this phase PR is merged.

## 8. Research baseline

- OWASP AISVS 1.0 provides testable AI-security requirements and recommends choosing verification depth based on risk; use versioned requirement IDs and distinguish AI-specific controls from general application/supply-chain controls: https://github.com/OWASP/AISVS
- OWASP AISVS access-control requirements emphasize explicit allow-lists/default-deny, retrieval authorization and tenant isolation: https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C05-Access-Control-and-Identity.md
- Clerk recommends verifying session-token signatures and standard claims; its current guidance favors `authenticateRequest()` or manual JWT verification with a trusted key, rather than accepting decoded claims: https://clerk.com/docs/guides/sessions/manual-jwt-verification
- GitHub recommends pinning third-party actions to full-length commit SHAs and using least-privilege workflow permissions: https://docs.github.com/en/actions/reference/security/secure-use

## 9. Explicit release prohibitions until evidence exists

- No claim of production readiness, 100% security, 0% false positives, or 99.9% SLA without scoped, repeatable evidence.
- No claim that all ATLAS techniques are covered because a mapping file lists them.
- No claim of legal/regulatory filing from a generated report, webhook request or dashboard toast.
- No claim of live integration from an adapter class, URL setting, or mocked unit test alone.
- No release while required CI/security workflows are failing, skipped, or configured to silently continue after failure.
