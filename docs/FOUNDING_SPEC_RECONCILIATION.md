# Aithyrex Founding Specification Reconciliation

**Document status:** Baseline reconciliation; not a security certification  
**Repository:** [LloydCoder/Aithyrex](https://github.com/LloydCoder/Aithyrex)  
**Audited revision:** `a552abf4a676de46bb8962d717d05e6b9e50d788` (`main`, 2026-10-09)  
**Product lineage:** AI Shield → Aithyrex (working product name; trademark clearance remains open)  
**Company:** Tinlance  
**Purpose:** Separate the founding product intent from what source code, tests, CI, deployment evidence, and external integrations actually demonstrate.

## 1. Executive determination

Aithyrex is a substantial prototype with detector modules, an orchestration engine, a ThreatFade client, enforcement endpoints, a multi-model Parliament, SIEM/compliance components, SDK integrations, a dashboard, and billing-related code. The presence of these components does **not** establish that they are secure, effective, production-ready, or commercially operational.

**Release posture at this audited revision: NOT APPROVED as a production security boundary.** The highest-priority blockers are:
1. Authentication can accept arbitrary bearer tokens when the Clerk secret is absent.
2. The Parliament can downgrade detector decisions; its ThreatFade vote treats low Z-scores as an affirmative ALLOW.
3. A model allowlist bypasses every detector.
4. ThreatFade and Redis failures can look like clean/zero results, creating fail-open behavior and potentially bypassing usage enforcement.
5. Dependency auditing cannot resolve the declared dependency set; the secret-scan workflow fails because its configured base and head resolve to the same commit. Neither CI failure by itself proves a vulnerable dependency or leaked secret.
6. Background event/SIEM/compliance tasks are not durably queued; process failure can lose work.
7. Dashboard exports, filing, alert data, and rule actions include simulated/local-state behavior and must not be presented as completed backend operations without confirmation.
8. Integration tests and Semgrep are configured non-blocking in the current CI workflow.

This document is a **source-level and CI-configuration review** of the identified revision. It is not a live penetration test, a complete test run, a deployment verification, or an independent detector-performance benchmark.

## 2. Status vocabulary

- **VERIFIED:** Independently confirmed by repeatable test evidence or an authoritative operational record.
- **IMPLEMENTED — UNVERIFIED:** A code path/component exists, but correctness, coverage, or operational behavior has not been demonstrated sufficiently.
- **PARTIAL:** Some behavior exists; key scope, control, reliability, or integration requirements are missing.
- **SIMULATED:** UI/demo/local state or a placeholder represents an action without evidence the real backend action completed.
- **UNIMPLEMENTED:** No sufficient implementation evidence identified in this review.
- **UNSUPPORTED CLAIM:** Product/marketing language exceeds the evidence currently available.
- **BLOCKER:** Must be resolved before the affected production claim or control is relied on.

A source file is evidence that code exists, not proof that a security property holds.

## 3. Founding specification reconciliation

| Founding capability or claim | Current evidence at audited revision | Status | Required reconciliation |
|---|---|---|---|
| Five detectors run through one engine: prompt injection, credential leakage, covert channels, C2-like behavior, and RAG/context poisoning | Detector modules exist and `ShieldEngine` instantiates and fans out to them | IMPLEMENTED — UNVERIFIED | Add a versioned adversarial evaluation set, per-detector precision/recall, false-positive/negative reporting, regression tests, and a detector failure-state contract |
| ThreatFade provides entropy/Z-score behavior analysis for AI text | HTTP client and detector bridge exist | PARTIAL / BLOCKER | The bridge returns a clean-shaped fallback on timeouts, connection failures, HTTP errors, and unexpected exceptions. Preserve degraded/error state in the final verdict; never equate unavailable analysis with clean traffic |
| ThreatFade's network-traffic validation establishes AI-text detection quality | Prior network validation is cited in product narrative, but it is not an AI-text benchmark | UNSUPPORTED CLAIM | Keep network and AI-text datasets/results separate. Publish dataset scope, labels, sample sizes, threshold selection, confidence intervals, and reproducible evaluation results before stating AI-specific accuracy or zero false positives |
| Parliament uses Claude, Grok, and deterministic ThreatFade voting | Parallel model calls, vote aggregation, and a Z-score vote are implemented | PARTIAL / BLOCKER | Treat model outputs as advisory. Hard policy denials and deterministic critical findings must not be downgraded. Abstention, parse errors, timeouts, and missing telemetry must not become ALLOW. A low Z-score is not proof of safety |
| Critical findings are blocked deterministically | Base aggregation maps CRITICAL to BLOCK, but later Parliament logic can replace the verdict for eligible cases | PARTIAL / BLOCKER | Enforce a non-overridable policy layer after detector/AI analysis; define explicit precedence and test all downgrade paths |
| Block Mode supports tenant-scoped blocks and allows | Block mode and enforcement routes exist | IMPLEMENTED — UNVERIFIED | Verify tenant isolation, TTL expiry, race behavior, auditability, and authorization. Replace broad model-level detector bypass with narrowly scoped exceptions that name principal/action/resource, reason, owner, expiry, and audit record |
| SIEM exports include JSON/CSV/CEF/Splunk HEC/STIX according to plan | Exporter and dispatch components exist | IMPLEMENTED — UNVERIFIED | Verify schemas against consumers, tenant scoping, retries, idempotency, redaction, delivery acknowledgements, dead-letter handling, and plan entitlements |
| Compliance thresholds notify KalevioAI and produce NIS2/DORA reports | Compliance evaluation/integration code exists | PARTIAL | A payload or webhook request is not proof of a legally valid filing. Track jurisdiction, applicability, incident classification, deadlines, responsible approver, destination acknowledgement, and immutable evidence. Avoid claiming automatic regulatory submission without end-to-end proof |
| API routes are authenticated and tenant-isolated | Clerk-oriented auth dependency exists | BLOCKER | Missing Clerk secret activates a development path accepting arbitrary tokens and fabricating a Pro tenant. Production must fail startup on missing auth configuration; verify issuer, signature, expiry, audience/authorized party and server-side tenant membership/entitlements |
| Usage plans are enforced | Redis-backed counter exists | BLOCKER | Redis unavailability returns zero counts and zero increments; quota check/increment is not atomic; only Free hard cutoff is enforced consistently. Use atomic reservations/limits and a documented fail-closed or explicit degraded policy; reconcile with durable billing records |
| Billing webhooks securely grant plan entitlements | Billing and webhook code exists | IMPLEMENTED — UNVERIFIED / BLOCKER | Missing webhook secrets must fail closed. Verify each provider's official signature algorithm and replay/idempotency rules. Resolve plan from server-authoritative subscription state, not client-editable JWT metadata. Test upgrades, downgrades, refunds, cancellations, retries, and duplicate events |
| OpenAI/Anthropic/LangChain/LlamaIndex SDKs secure requests | Integration modules exist in the tree | IMPLEMENTED — UNVERIFIED | Test supported upstream versions and all sync/async/streaming paths. Demonstrate inspection before side effects and coverage of tool calls, tool results, retrieval context, and MCP boundaries. A callback or task-description scan alone is not runtime enforcement |
| Dashboard alerts/reports/rules reflect real backend state | Reviewed frontend pages contain seeded alerts, synthetic metrics, local-state rule actions, and simulated export/filing behavior | SIMULATED / PARTIAL | Mark fixtures clearly as demo data. Connect controls to real APIs and show success only after backend confirmation; failed exports/filings must show explicit failure state |
| WebSocket monitor is tenant-scoped and authenticated | Monitor route and frontend stream exist; source review identified missing client auth propagation | PARTIAL / BLOCKER | Authenticate the WebSocket handshake, authorize tenant/channel membership, reject unauthenticated clients, and test cross-tenant stream isolation |
| “Full MITRE ATLAS coverage” | Mapping artifacts and technique labels exist | UNSUPPORTED CLAIM | Describe specific implemented detections mapped to techniques; distinguish a mapping from detection coverage and validate against versioned adversarial test cases |
| “First tool” applying this method to LLM inference | No documented prior-art search or comparative evidence attached | UNSUPPORTED CLAIM | Remove “first” until a documented, defensible prior-art review supports the exact wording |
| “99% confidence,” “0% false positives,” and competitor non-replicability | Narrative claims are not backed here by reproducible AI-specific evaluation | UNSUPPORTED CLAIM | Publish precise scope and methodology; never generalize results beyond the dataset and operating conditions tested |
| 99.9% SLA, air-gap/on-prem, SSO/SAML, unlimited rules, and enterprise-grade guarantees | Pricing/feature descriptions exist; operational evidence was not established by this review | UNSUPPORTED CLAIM until verified | Each commercial promise needs acceptance criteria, deployment evidence, runbooks, support coverage, capacity tests, and contract-aligned limits |
| Security CI protects merges | Unit tests and security jobs exist, but integration tests and Semgrep use `continue-on-error: true` | PARTIAL / BLOCKER | Make required checks blocking after dependencies/services are made deterministic; pin third-party actions to reviewed immutable SHAs; define required status checks and branch protection |
| Dependency audit and secret scanning pass | Latest inspected Security Scan run fails both jobs | BLOCKER | Dependency audit fails at package resolution, not at a confirmed vulnerability finding. TruffleHog fails because configured base and head are identical. Repair both workflows, then rerun and inspect actual findings |
| Production deployment is operational and secure | Repository contains deployment-related configuration and docs; this review did not verify the live deployment | UNVERIFIED | Verify deployed revision, TLS, secret configuration, migrations, health/readiness, tenant isolation, backup/restore, incident response, observability, and rollback against an evidence checklist |

## 4. Confirmed CI failure analysis

Workflow run: [Security Scan run 37912754282](https://github.com/LloydCoder/Aithyrex/actions/runs/37912754282)

### 4.1 Dependency audit — package resolver failure

The `pip-audit -r backend/requirements.txt` step fails before completing the audit because pip cannot resolve the declared requirements. The log reports conflicting dependencies involving requirement-file entries and `numpy==2.1.1`, ending in `ResolutionImpossible`.

**Interpretation:** this run does not establish whether the resolved application dependency set contains known vulnerabilities. The declared dependency set must first be made resolvable and reproducible; then run the audit and triage actual advisory findings. Do not fix this by suppressing the audit or blindly upgrading every package.

### 4.2 TruffleHog — scan configuration failure

The workflow passes the repository default branch as `base` and `HEAD` as `head`. On this push, both resolve to commit `a552abf4a676de46bb8962d717d05e6b9e50d788`. TruffleHog explicitly exits with: “BASE and HEAD commits are the same. TruffleHog won't scan anything.”

**Interpretation:** this is a scanner invocation/configuration failure, not a confirmed secret finding. The remediation branch changes push/PR scans to compare event SHAs, leaves scheduled-scan inputs empty for the action's full-history mode, and pins TruffleHog to the exact action revision observed in the failed run. **This proposed workflow change is not yet validated by a new CI run.** If any credential is confirmed exposed, revoke/rotate it and investigate history; do not merely suppress the finding.

### 4.3 CI enforcement gaps

The current CI file marks integration tests and Semgrep as `continue-on-error: true`. A green workflow can therefore coexist with failed integration or Semgrep checks. Make these required checks blocking after tests are reliable in CI; provision disposable services or deterministic test doubles rather than leaving the check permanently non-blocking.

## 5. Architecture and safety invariants

These are required product invariants, not optional enhancements:

1. **Policy authority is deterministic.** LLM evaluators may enrich context or recommend actions; they cannot grant permissions or downgrade a hard policy denial.
2. **Unknown is not clean.** Detector, policy, authentication, quota, evidence, or downstream service failure must be represented explicitly. Each control must declare whether failure blocks, degrades safely, or permits a narrowly bounded operation.
3. **Authorize actions, not just text.** Inspect and authorize tool calls before execution, bind decisions to tenant/principal/resource/action, and validate tool outputs before they are reintroduced as trusted context.
4. **No broad model allowlist.** Model identity alone is not authorization. Exceptions must be narrowly scoped, time-bounded, attributable, revocable, and audited.
5. **Tenant isolation is end-to-end.** Enforce at API, database query/RLS, cache keys, queues, WebSockets, exports, and third-party dispatch.
6. **Evidence is durable and attributable.** Security events and delivery work require durable persistence/outbox or queue semantics, stable event IDs, idempotency, retries, delivery status, and redaction controls.
7. **Entitlements are server-authoritative.** The authenticated identity, tenant membership, subscription state, plan, limits, and permitted actions must be resolved and checked server-side.
8. **Claims follow evidence.** Marketing/UI must distinguish code-present, tested, benchmarked, deployed, integrated, and contractually supported capabilities.

## 6. Tinlance ecosystem boundaries

Aithyrex is the AI-runtime detection and policy-evaluation integration layer. It must not become a second authority for shared identity, authorization, approvals, sandboxing, secrets, governed execution, or audit if those responsibilities belong to the Tinlance Agent Platform.

- **Aithyrex:** observe AI interactions and agent behavior; identify threats; emit structured findings/evidence; request policy decisions or enforcement through explicit interfaces.
- **Tinlance Agent Platform:** authoritative identity, authorization, policy, approvals, governed execution, tool/MCP access, sandbox, secrets, budgets, audit, and execution evidence where integrated.
- **ThreatFade:** separately maintained behavioral/network detection service; Aithyrex consumes its documented contract and reports dependency health.
- **FusionOps:** orchestration and response workflow.
- **TwinGuard:** containment/kill-switch capabilities, only through explicit authorized contracts.
- **KalevioAI:** compliance evidence/report workflows; a notification must not be described as a completed legal filing unless acknowledged by the actual destination.

Integration status must be tracked independently from component existence. Do not describe the full Detect → Decide/Enforce → Orchestrate → Contain → Prove chain as operational until every boundary is exercised end-to-end.

## 7. Release gates

Aithyrex must not be promoted to production enforcement until all gates below have evidence attached to a specific commit and environment.

- [ ] **G1 — Authentication:** no production dev bypass; startup rejects missing/invalid auth configuration; negative JWT and tenant-membership tests pass.
- [ ] **G2 — Decision integrity:** hard-deny invariants cannot be overridden by Parliament; malformed model responses and abstentions never imply ALLOW; property-based decision tests pass.
- [ ] **G3 — Dependency degradation:** ThreatFade/Redis/database/provider outages are visible and follow documented safe behavior; no clean-shaped fallback hides an unavailable control.
- [ ] **G4 — Usage and billing:** atomic quota reservation, authoritative entitlements, webhook signature/replay tests, and all subscription lifecycle tests pass.
- [ ] **G5 — Tenant isolation:** API, DB, cache, WebSocket, queue, SIEM, report, and webhook isolation tests pass.
- [ ] **G6 — Durable evidence:** crash/retry/idempotency tests prove events and delivery attempts are not silently lost.
- [ ] **G7 — Runtime action coverage:** SDK and agent/MCP adapters prove pre-side-effect interception across documented supported versions and paths.
- [ ] **G8 — Security CI:** requirements resolve from a clean Python 3.12 environment; dependency audit completes; secret scan completes; Bandit, Ruff, Semgrep, unit and integration tests are required checks.
- [ ] **G9 — Evaluation:** versioned attack/benign corpus, reproducible metrics, regression thresholds, and independent review for performance claims.
- [ ] **G10 — UI truthfulness:** all demo fixtures are labeled; exports/rules/filing display backend-confirmed outcomes only.
- [ ] **G11 — Operations:** deployed commit verified; secrets, TLS, backups/restore, migration/rollback, alerts, runbooks, incident response, and load/chaos behavior evidenced.
- [ ] **G12 — Commercial claims:** pricing limits, SLA, compliance claims, on-prem/air-gap, SSO, and retention guarantees match implemented and tested behavior.

## 8. Ordered remediation plan

**P0 — Restore decision and identity integrity**
1. Remove auth bypass; fail closed on missing production configuration.
2. Separate detector aggregation from policy enforcement. Hard denials are monotonic and non-overridable.
3. Treat Parliament outputs as advisory; make parse/timeout/abstention paths explicit and non-permissive.
4. Remove broad allowlist bypass.
5. Make ThreatFade and Redis degraded states explicit and prevent false-clean/quota bypass.

**P1 — Restore build and security signal**
6. Resolve dependency constraints with a reproducible lock/constraints strategy and documented compatibility tests.
7. Fix TruffleHog push/schedule base-head handling and pin the action to an immutable SHA.
8. Make Semgrep and integration tests blocking once deterministic dependencies are provisioned.
9. Add negative security tests for auth, policy downgrades, service outages, tenant boundaries, quotas, and webhook verification.

**P2 — Make the runtime and evidence reliable**
10. Add durable outbox/queue delivery, idempotency, retry/dead-letter semantics, and per-tenant event provenance.
11. Add action/tool-call authorization before side effects and context trust boundaries for retrieval, tool results, and MCP.
12. Validate SDK interception for streaming, async, exceptions, and supported version ranges.
13. Replace synthetic dashboard behavior with API-backed state and truthful completion/error statuses.

**P3 — Prove product value and integration**
14. Build a reproducible AI-runtime evaluation corpus and publish scoped metrics.
15. Validate SIEM, KalevioAI, FusionOps, TwinGuard, and Tinlance Agent Platform contracts with end-to-end tests.
16. Complete operational readiness and reconcile website/pricing claims with verified capability.
17. Keep the Aithyrex name provisional until legal/trademark and domain review is completed.

## 9. Evidence ledger and audit limitations

Evidence inspected for this baseline:
- Repository tree and default-branch revision `a552abf4a676de46bb8962d717d05e6b9e50d788`.
- `backend/core/auth.py`, `backend/core/shield_engine.py`, `backend/agents/parliament.py`, `backend/core/usage_counter.py`, `backend/core/threatfade_client.py`.
- `.github/workflows/ci.yml`, `.github/workflows/security-scan.yml`, and the corresponding failing workflow job logs.
- Dashboard behavior and component inventory from the source-level review summarized in this document.

Not established by this baseline:
- A complete local test execution or fresh CI run after remediation.
- Live production configuration, deployed commit, external provider credentials, or successful end-to-end integration.
- AI-specific detection precision/recall or zero-false-positive claims.
- Regulatory filing completion, production SLA, or legal brand clearance.

**Change-control rule:** update this document only when new source, test, CI, deployment, or external acknowledgement evidence changes a status. Each change should reference the commit/run/environment and distinguish implementation from verification.
