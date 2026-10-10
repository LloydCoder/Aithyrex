# Independent Security Review Protocol

## Independence and reviewer qualifications

The reviewer must not be the primary author of the reviewed implementation, must disclose financial/organizational conflicts, and must have experience in application security, AI/LLM security, multi-tenant systems and evidence-based testing. If a fully independent reviewer is unavailable, the gate remains blocked; an internal self-review is not an independent assessment.

## Required review package

- Exact candidate commit SHA, image digest, dependency lock/SBOM and workflow links.
- Current threat model, data-flow/trust-boundary diagram, API contracts and security architecture.
- Findings register with severity, preconditions, reproduction steps, expected/actual results, owner and closure evidence.
- Test/evaluation corpus manifest and AI-text evaluation report, including held-out data and false-positive analysis.
- Multi-tenant isolation and authorization tests, failure-injection results, evidence export audit and production configuration gates.
- Deployment, monitoring, backup/restore, rollback and incident-response evidence.
- Explicit list of unsupported claims and residual risks.

## Review procedure

1. Verify candidate and artifact digests match the evidence manifest.
2. Reproduce a clean build and run the declared CI/security workflows.
3. Review identity, tenant scoping, deterministic decisions, fail-closed behavior, tool/action boundaries, quotas, evidence persistence and external dependency failure modes.
4. Independently sample detector cases and benign hard negatives; inspect dataset leakage, labeling quality and statistical reporting.
5. Run focused abuse cases from the threat model, including malformed inputs, timeouts, Redis/DB failures, cross-tenant IDs, replay, prompt injection, and evidence export edge cases.
6. Validate that no Aithyrex finding is treated as authorization to execute an action; verify the Agent Platform remains authoritative.
7. Review operational readiness and the truthfulness of product/regulatory claims.
8. Classify each finding. Critical/high findings must be fixed and retested. Medium/low residual findings require a named risk owner, rationale, mitigation, expiry/review date and explicit acceptance.
9. Issue a signed report tied to the exact candidate SHA. The report must state scope, methods, exclusions, limitations, findings, evidence references and recommendation.

## Decision outcomes

- **Pass:** no open critical/high findings; required evaluation and operational gates are satisfied; residual risks are explicitly accepted.
- **Conditional:** only if policy permits a bounded, non-production pilot with documented limitations and no unresolved critical/high findings.
- **Fail / blocked:** evidence missing, candidate mismatch, independent review unavailable, critical/high finding open, evaluation not representative, or production controls unverified.

A pass is scoped to the exact revision and test/evaluation conditions reviewed. It is not a guarantee of security, certification, or effectiveness against all future threats.
