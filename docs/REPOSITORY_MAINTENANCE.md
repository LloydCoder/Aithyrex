# Repository Maintenance Checklist

Use this checklist during routine maintenance and before any release. Record evidence in pull requests or release records; do not mark a control complete merely because a file exists.

## Every pull request

- [ ] Keep the README, changelog and docs aligned with actual behavior.
- [ ] Run relevant tests and disclose checks not run.
- [ ] Review authentication, tenant isolation, secret handling, privacy and failure semantics for affected paths.
- [ ] Ensure logs, fixtures and screenshots contain no secrets, raw customer prompts/completions or personal data.
- [ ] Ensure findings remain advisory and cannot bypass Tinlance Agent Platform authorization.
- [ ] Verify relative documentation links and new external links.
- [ ] Check workflow changes for least privilege, pinned actions and untrusted-input handling.

## Weekly or on dependency-change PRs

- [ ] Review Python and npm dependency advisories and update constraints/lockfiles consistently.
- [ ] Review GitHub Actions updates and pin third-party actions to reviewed full commit SHAs.
- [ ] Review secret-scan and dependency-audit results, including scheduled scans.
- [ ] Review open security advisories and coordinate private disclosure as appropriate.
- [ ] Confirm issue templates and support links resolve.

## Before a tagged release

- [ ] Confirm version, changelog, package name, wheel/sdist contents and release notes.
- [ ] Confirm PyPI trusted publishing is configured for the intended project and protected environment.
- [ ] Freeze the exact release-candidate SHA and artifact digests.
- [ ] Verify all release-blocking gates in the external evidence bundle against that exact SHA.
- [ ] Obtain independent AI-text evaluation and signed independent security review.
- [ ] Verify controlled deployment, tenant-isolation smoke tests, rollback and post-deployment checks.
- [ ] Complete an isolated backup/restore drill and record measured RPO/RTO.
- [ ] Measure operational SLOs using representative traffic and document methodology.
- [ ] Obtain authorized legal/compliance review for regulatory or certification claims.
- [ ] Confirm public performance and coverage claims are scoped to evidence.
- [ ] Do not release while any blocking gate remains unresolved.

## Quarterly or ownership change

- [ ] Verify CODEOWNERS, maintainer access, branch rules and required status checks in GitHub settings.
- [ ] Verify security reporting and Code of Conduct contacts are monitored.
- [ ] Review support boundaries, supported versions and deprecation policy.
- [ ] Review README links, llms.txt, architecture boundaries and repository metadata.
- [ ] Update this checklist when project practices change.
