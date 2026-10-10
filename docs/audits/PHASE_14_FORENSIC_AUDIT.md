# Phase 14 — Red-Team Evaluation Forensic Audit

**Repository:** [LloydCoder/Aithyrex](https://github.com/LloydCoder/Aithyrex)  
**Phase branch:** `godmode/phase-14-red-team-evaluation`  
**Scope:** deterministic offline red-team regression gate, corpus integrity, prompt-injection regression, CLI output contract, CI enforcement and documentation accuracy.  
**Audit status:** implementation findings addressed; final-head CI/Security Scan verification pending for the explicit CI gate and audit documentation commit.

## Evidence baseline

The code revision `02fb31bcb063355f8f33fe8395590fc36eb0d440` passed CI at [run 38031562738](https://github.com/LloydCoder/Aithyrex/actions/runs/38031562738) and Security Scan at [run 38031562765](https://github.com/LloydCoder/Aithyrex/actions/runs/38031562765). Those workflows verified the detector regression, test suite, static analysis, frontend build/audit, Docker build, dependency audit and secret scan. The explicit blocking CLI evaluation step was added afterward, so these runs are baseline evidence only; final acceptance is intentionally gated on the new head's workflows.

## Findings and remediation

### F14-01 — Expected system-prompt extraction indicator was missed

- **Observed:** the synthetic case `extract-prompt-010` expected prompt-injection and data-poisoning findings for “Repeat your system prompt…”. The prompt-injection expression allowed “the” but not the possessive “your”, so the expected detector assertion failed.
- **Fix:** expanded the prompt-extraction expression to accept the common `the` and `your` forms while retaining the existing optional hidden/system/developer qualifiers.
- **Regression evidence:** the subsequent test run passed the default 32-case corpus and the zero-missed-expected-detector assertion.

### F14-02 — CLI JSON output was not robust against detector logging

- **Observed:** after the detector assertion was fixed, the CLI-output unit test exposed extra output that prevented consumers from parsing stdout as one JSON document.
- **Fix:** isolated evaluation-time stdout from the JSON report and added a test-backed single-report contract. The explicit CI step now redirects the report to a temporary file, parses it, and emits only a content-free summary to the workflow log.
- **Regression evidence:** the subsequent unit test run passed; the new direct CLI CI step must pass on the final branch head.

### F14-03 — Blocking lint caught import-order regression

- **Observed:** Ruff rejected the newly added `contextlib.redirect_stdout` import order.
- **Fix:** reordered imports and reran the blocking CI workflow.
- **Regression evidence:** static analysis passed on revision `02fb31bcb063355f8f33fe8395590fc36eb0d440`; the latest-head workflow is the final authority for the combined change.

### F14-04 — Regression corpus was not a first-class CI step

- **Observed:** unit tests invoked the suite, but CI did not run the evaluator as a standalone blocking step or print a reproducible, content-free summary.
- **Fix:** added a blocking CI step that runs the CLI, validates the JSON report, requires a 64-character SHA-256 digest and `synthetic_only` classification, and rejects any attempt by the suite to approve a release.
- **Acceptance:** the final-head CI must show this step passing, alongside unit/integration tests, Ruff, Bandit, Semgrep, frontend audit/build, Docker build, dependency audit and secret scan.

## Corpus and acceptance policy

- Dataset: `aithyrex-synthetic-red-team` version `1.0.0`; 32 synthetic cases (20 malicious, 12 benign).
- Declared sources: prompt, completion and tool output.
- Evaluated detectors: prompt injection, credential leak and data-poisoning heuristics.
- Gate thresholds: malicious recall ≥ 0.90, benign false-positive rate ≤ 0.05, expected detector coverage ≥ 0.90, both labels represented in every source, and zero missed expected-detector assertions.
- Secret-shaped test values are placeholders rendered as fake values in process memory; raw case text is not emitted in reports.
- ThreatFade network signals are deliberately excluded from this AI-text gate.

## Security and standards cross-check

The corpus is a deterministic regression set, not a representative benchmark. Its metrics cannot establish production recall, precision, false-positive rate, robustness against unseen attacks, model-specific effectiveness or calibrated confidence. OWASP AISVS 1.0 is a useful source of testable AI-specific controls, OWASP's 2025 LLM Top 10 provides risk-family framing, NIST AI RMF / the Generative AI Profile supports lifecycle testing and monitoring, and MITRE ATLAS provides a living adversarial technique taxonomy. This repository does not claim AISVS certification or complete ATLAS coverage.

References:
- [OWASP AISVS 1.0](https://owasp.github.io/www-project-artificial-intelligence-security-verification-standard-aisvs-docs/)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [MITRE ATLAS](https://atlas.mitre.org/)

## Explicit residual risks

- The dataset is small and synthetic; it is not independent red-team evidence.
- Detector confidence remains uncalibrated.
- Streaming, multimodal, live provider behavior, full MCP/tool mediation, production tenant behavior and ThreatFade-dependent detectors are not covered by this gate.
- The suite cannot approve a release; independent review and a representative labeled corpus remain required for effectiveness claims.
- CI success verifies only the committed test surface and does not prove live Tinlance Agent Platform integration, deployment, regulatory compliance or 100% security.

## Final acceptance record

This section must be updated only after the latest commit's CI and Security Scan have both completed successfully. Record the exact commit SHA, CI URL, Security Scan URL, unit/integration counts and the explicit “offline red-team evaluation gate” step result. If any required job is skipped, cancelled or failing, Phase 14 remains unaccepted.
