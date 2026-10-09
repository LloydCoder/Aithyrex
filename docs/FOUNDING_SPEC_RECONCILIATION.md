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

## 4. Known blockers from baseline inspection

1. Previous CI run `37912754190` failed dependency installation because `numpy==2.1.1` conflicts with `langchain==0.2.16`, which requires NumPy <2 on Python 3.12.
2. The same CI run failed Ruff with 68 findings (25 import-order, 24 unused-import, 1 redefinition, 3 f-string-without-placeholder, 1 multiple-import finding). These must be fixed rather than silently treated as clean.
3. Previous security run `37912754282` failed dependency audit before producing a vulnerability assessment because dependency resolution failed.
4. The previous TruffleHog invocation used identical base/head commits and therefore scanned no commit range. The scan configuration must distinguish PR/push ranges from full-history scans.
5. Authentication previously accepted arbitrary bearer tokens when Clerk secret configuration was empty. The remediation branch replaces this with explicit JWT verification trust anchors and fail-closed behavior; production startup must require those settings.
6. Parliament previously allowed consensus/override paths to downgrade detector verdicts. It is being constrained to advisory escalation only, with missing ThreatFade telemetry abstaining.
7. ThreatFade outages previously returned a clean-shaped fallback. The remediation branch marks such responses degraded and blocks when required telemetry is unavailable.
8. Redis usage failure previously returned zero usage, and model allowlisting bypassed all detection. Both behaviors are being removed or constrained.
9. Billing previously accepted missing webhook secrets and used a non-Paddle-specific signature calculation. Signature validation and unknown-price behavior are being corrected.
10. Background `asyncio.create_task()` delivery, dashboard demo behavior, WebSocket authentication, tenant isolation, SDK pre-side-effect mediation, and durable evidence remain explicit later-phase audit targets.

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

## 6. Current remediation branch status

Branch: `godmode/phase-00-04-hardening`.

Changes made so far on this branch:
- Resolved the declared NumPy/LangChain version conflict by pinning NumPy 1.26.4.
- Added PR scanning and event-specific/full-history TruffleHog range selection; pinned checkout/setup-python and TruffleHog actions to full SHAs.
- Rewrote the repository README around canonical product boundaries and evidence-qualified claims.
- Added explicit Clerk JWT verification trust anchors and removed the implicit arbitrary-token fallback; production startup checks are being added.
- Marked ThreatFade outage responses as degraded; propagated degraded state into detectors.
- Changed Parliament behavior toward abstention for missing ThreatFade telemetry and escalation-only decision integration.
- Removed blanket allowlist detection bypass and made block-state/usage-accounting outages fail closed.
- Replaced permissive webhook secret behavior and corrected Paddle timestamped signature verification; unknown Paddle prices map to Free.

These changes are not yet considered phase-complete until the full CI/security workflows run and their logs are inspected. This branch is not merged. Any finding in the current working diff can invalidate the stated status.

## 7. Research baseline

- OWASP AISVS 1.0 provides testable AI-security requirements and recommends choosing verification depth based on risk; use versioned requirement IDs and distinguish AI-specific controls from general application/supply-chain controls: https://github.com/OWASP/AISVS
- OWASP AISVS access-control requirements emphasize explicit allow-lists/default-deny, retrieval authorization and tenant isolation: https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C05-Access-Control-and-Identity.md
- Clerk recommends verifying session-token signatures and standard claims; its current guidance favors `authenticateRequest()` or manual JWT verification with a trusted key, rather than accepting decoded claims: https://clerk.com/docs/guides/sessions/manual-jwt-verification
- GitHub recommends pinning third-party actions to full-length commit SHAs and using least-privilege workflow permissions: https://docs.github.com/en/actions/reference/security/secure-use

## 8. Explicit release prohibitions until evidence exists

- No claim of production readiness, 100% security, 0% false positives, or 99.9% SLA without scoped, repeatable evidence.
- No claim that all ATLAS techniques are covered because a mapping file lists them.
- No claim of legal/regulatory filing from a generated report, webhook request or dashboard toast.
- No claim of live integration from an adapter class, URL setting, or mocked unit test alone.
- No release while required CI/security workflows are failing, skipped, or configured to silently continue after failure.
