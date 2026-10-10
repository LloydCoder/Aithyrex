# Changelog

Notable repository changes are recorded here. This file does not certify a release or replace the release-evidence process. Version `0.1.0` is declared in `pyproject.toml`; a published GitHub Release or PyPI availability must be verified separately.

## Unreleased

### Documentation and repository readiness

- Reframed public project documentation under the canonical **Aithyrex** name.
- Clarified that Aithyrex emits evidence-bearing AI-interaction threat findings and does not own authoritative identity, authorization, policy, approval or governed execution.
- Added contributor, support, security-reporting and issue-intake guidance.
- Added a repository maintenance checklist and curated `llms.txt` index.
- Hardened the PyPI publication workflow by pinning third-party actions to reviewed commit SHAs and updating its package-name guidance.

### Assurance status

- The documented Phase 0–17 engineering implementation sequence is accepted for its stated scopes.
- The product release remains **BLOCKED** pending representative independent AI-text effectiveness evaluation, independent security review, controlled production deployment and rollback evidence, a successful backup/restore drill, measured SLOs, and authorized legal/compliance review.
- The offline synthetic red-team regression suite is not evidence of production detection accuracy.
- ThreatFade network-traffic results must not be represented as AI-text detector validation.

## Versioning policy

Use dated/versioned entries when a release is actually prepared. Before publishing a tag, verify package metadata, release-candidate SHA, dependency and secret scans, release gates, changelog accuracy, and PyPI trusted-publishing configuration. Do not create a release solely because package metadata contains a version.
