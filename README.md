# Aithyrex

**Agentic AI Runtime Security — “AI can act. Aithyrex watches.”**

Aithyrex (formerly AI Shield) is Tinlance’s AI-interaction threat detection service. It inspects supported LLM prompts, completions, and related telemetry for suspicious patterns, emits findings with provenance, and integrates with downstream policy and response systems.

## Product boundary

- **Aithyrex:** AI-interaction threat detection, detector evidence, telemetry enrichment, and versioned security findings.
- **Auctaryn:** agent context, memory, skill, and proposed-action risk assessment.
- **Tinlance Agent Platform:** authoritative identity, tenant binding, authorization, policy, approvals, governed execution, sandboxing, secrets, budgets, and authoritative audit/evidence.
- **ThreatFade:** separately operated behavioral/network detection service; its network-traffic metrics do not by themselves validate AI-text detection.
- **AURONTRA:** IT resilience, operations, incident/ticket workflows, and bounded remediation orchestration.
- **FusionOps:** response workflow orchestration.
- **KalevioAI:** compliance evidence/reporting workflows; a webhook or generated report is not proof of legal filing.
- **TSIC:** cross-repository integration contracts, conformance and end-to-end evidence. TADL validates developer artifacts and schemas.

Aithyrex findings are signals, not authorization grants. Aithyrex must not create a competing identity, policy, approval, or governed-execution authority. Any enforcement request must be evaluated by the authoritative Platform at the actual execution boundary.

## Security and assurance status

The Phase 0–17 engineering implementation sequence is complete for its documented acceptance scope. This is not a production-readiness attestation: the release remains BLOCKED pending independent AI-text effectiveness evaluation, independent security review, controlled production deployment/rollback, backup/restore evidence, measured SLOs, and authorized legal/compliance review. A capability is not production-ready merely because code or a test exists. Claims about detection accuracy, false-positive rates, standards coverage, uptime, automatic regulatory filing, and live integrations require reproducible evidence scoped to the tested dataset, environment, version, and date.

ThreatFade results obtained from network traffic must not be presented as validation of AI-text detection unless a separate, representative AI-traffic evaluation establishes that claim.

## Development

- Supported CI baseline: Python 3.12.
- Install: `python -m pip install -r backend/requirements.txt`
- Unit tests: `pytest backend/tests/unit/ -v --tb=short`
- Integration tests: `pytest backend/tests/integration/ -v --tb=short`
- Static analysis: `bandit -r backend/ -ll -x backend/tests/` and `ruff check backend/`

Configure credentials through environment variables. Never commit secrets. Production must not use development authentication fallbacks.

### Health and operations

- `GET /health/live` is a dependency-free process liveness probe.
- `GET /health/ready` checks required dependencies with bounded timeouts and returns HTTP 503 when degraded.
- `GET /health` remains a backward-compatible diagnostic response whose JSON status may be `degraded` while HTTP remains 200.
- The Compose configuration and active `.env.example` values are for local development only, not production.

See [Operations Runbook](docs/OPERATIONS.md) for production configuration gates, monitoring, proposed-but-unmeasured SLOs, secret rotation, backup/restore, deployment/rollback, and incident response. Repository CI does not prove a live deployment, successful restore drill, or achieved SLO.

### Release assurance

Aithyrex is not currently certified or approved for production release. The fail-closed release manifest is at docs/assurance/release-evidence.json; the evaluator is scripts/assurance/check_release_readiness.py. The current release disposition remains BLOCKED until the representative AI-text evaluation, independent review, production deployment/rollback, backup/restore, SLO measurement and legal/compliance review gates have verifiable evidence tied to the exact candidate SHA.

See [Release Readiness](docs/assurance/RELEASE_READINESS.md), [Threat Model](docs/assurance/THREAT_MODEL.md), and [Independent Review Protocol](docs/assurance/INDEPENDENT_REVIEW_PROTOCOL.md).

## Phase and evidence policy

Every phase requires code changes where needed, automated tests, blocking CI, a forensic review of the resulting diff and test evidence, reconciled documentation, and an explicit acceptance decision. Green CI is necessary but not sufficient for release readiness.

See [docs/FOUNDING_SPEC_RECONCILIATION.md](docs/FOUNDING_SPEC_RECONCILIATION.md) for the founding specification, phase-by-phase implementation and forensic audit record, known residual risks, and outstanding release gates.

### SDK and framework integrations

See [SDK and Gateway Integration Contract](docs/SDK_GATEWAY_CONTRACT.md) for supported provider behavior, request trace correlation, fail-closed semantics, and explicitly unsupported paths. Framework callbacks are defense-in-depth, not an execution authorization boundary.


### Tinlance integration conformance

See [TSIC Conformance](docs/TSIC_CONFORMANCE.md) and the [machine-readable contract manifest](contracts/tsic/aithyrex-contracts.v1.json) for signed action, context and behavioral-sequence contracts, one-time assertion replay protection, and the boundary between advisory findings and Platform authorization.

### Red-team evaluation

Run the offline synthetic regression gate with `python -m backend.evaluation.red_team_suite`. See [Red-Team Evaluation](docs/RED_TEAM_EVALUATION.md) for corpus provenance, thresholds, standards alignment and explicit limitations. A passing regression gate does not approve a release or establish production detection accuracy.
