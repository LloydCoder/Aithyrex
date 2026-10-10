# Aithyrex Release Readiness and Controlled Launch

**Current disposition: BLOCKED — not certified or production-release-ready.**

This document distinguishes repository implementation evidence from external assurance. A green CI pipeline proves that the checked revision passed the configured automation; it does not prove real-world AI-text detection accuracy, an independent security review, a production deployment, a successful restore drill, or regulatory compliance.

## Release decision rule

A release is eligible only when all release-blocking gates in release-evidence.json are marked passed, each gate has valid evidence, and the manifest's release_candidate_sha exactly matches the candidate commit SHA. No verbal assurance, green CI alone, or unverified URL may substitute for evidence.

Evaluate a candidate from the repository root with:

    python scripts/assurance/check_release_readiness.py --manifest docs/assurance/release-evidence.json --candidate-sha "$GITHUB_SHA" --json

The command exits non-zero while any release-blocking gate is unresolved. Do not run this as a blocking default CI step until the external evidence has been produced; CI tests the gate's fail-closed behavior instead. The current manifest intentionally remains blocked.

## Gate ownership and evidence

| Gate | Owner | Minimum evidence |
|---|---|---|
| CI, static analysis and packaging | Engineering | Workflow URLs tied to the exact candidate SHA |
| Dependency and secret scanning | Security Engineering | Successful scans for the exact candidate |
| AI-text effectiveness | Security Engineering + independent evaluator | Versioned dataset, labeling methodology, held-out results, metrics and signed review |
| Independent security review | Independent reviewer | Scope, conflicts disclosure, findings, reproduction steps, closure evidence and signed report |
| Production deployment and rollback | Platform Operations | Image digest, environment identity, tenant-isolation smoke test, readiness evidence and rollback drill |
| Backup and restore | Platform Operations | Isolated restore record, integrity checks, measured RPO/RTO and corrective actions |
| SLO measurement | SRE | Real traffic measurements, source, window, exclusions, sample sizes and alert exercise |
| Regulatory claims review | Legal/compliance owner | Written applicability/claims review and evidence for any certification claim |

## AI-text evaluation requirements

The dataset must be versioned, hashed, and held out from detector tuning. It must include attacks and benign hard negatives across the detector families actually claimed by Aithyrex: prompt injection, credential/data exfiltration, covert-channel behavior, AI-text C2-like behavior, and data poisoning. Report results by detector, attack family, model/provider, language, and benign/attack class. Include precision, recall, false-positive rate, confidence intervals, sample sizes, and error analysis. Document labeler instructions and adjudication for disagreements.

Do not generate synthetic scores or treat ThreatFade network-traffic evaluation as proof of AI-text detector performance. If no qualifying corpus exists, keep this gate blocked and restrict claims accordingly.

## Controlled launch

After all gates pass:
1. Freeze the candidate SHA and dependency/image digests.
2. Obtain independent review sign-off and risk-owner approval for any accepted residual findings.
3. Deploy to a controlled environment with restricted tenants and bounded capabilities.
4. Verify readiness, authorization boundaries, tenant isolation, event evidence, outbox delivery, alerts, backup/restore and rollback.
5. Use explicit launch criteria and rollback thresholds. Expand traffic only after the observed metrics meet the approved criteria.
6. Record the launch decision, reviewers, evidence links, residual risks and exact artifact digests.

## Prohibited claims without evidence

Do not describe Aithyrex as “100% secure,” “zero false positives,” certified, regulator-approved, production-deployed, or effective against all AI threats without current, scoped, independently supported evidence. Do not imply that compliance evidence exports perform a legal assessment or submit a filing.
