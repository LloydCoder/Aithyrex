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

This repository is under active remediation. A capability is not production-ready merely because code or a test exists. Claims about detection accuracy, false-positive rates, standards coverage, uptime, automatic regulatory filing, and live integrations require reproducible evidence scoped to the tested dataset, environment, version, and date.

ThreatFade results obtained from network traffic must not be presented as validation of AI-text detection unless a separate, representative AI-traffic evaluation establishes that claim.

## Development

- Supported CI baseline: Python 3.12.
- Install: `python -m pip install -r backend/requirements.txt`
- Unit tests: `pytest backend/tests/unit/ -v --tb=short`
- Integration tests: `pytest backend/tests/integration/ -v --tb=short`
- Static analysis: `bandit -r backend/ -ll -x backend/tests/` and `ruff check backend/`

Configure credentials through environment variables. Never commit secrets. Production must not use development authentication fallbacks.

## Phase and evidence policy

Every phase requires code changes where needed, automated tests, blocking CI, a forensic review of the resulting diff and test evidence, reconciled documentation, and an explicit acceptance decision. Green CI is necessary but not sufficient for release readiness.

See [docs/FOUNDING_SPEC_RECONCILIATION.md](docs/FOUNDING_SPEC_RECONCILIATION.md) for the founding specification, known blockers, acceptance gates, and phased remediation record.

### SDK and framework integrations

See [SDK and Gateway Integration Contract](docs/SDK_GATEWAY_CONTRACT.md) for supported provider behavior, request trace correlation, fail-closed semantics, and explicitly unsupported paths. Framework callbacks are defense-in-depth, not an execution authorization boundary.

