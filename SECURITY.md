# Security Policy

## Supported versions

Security fixes are prioritized for the current default branch. A version is supported only when the project explicitly identifies it as supported in a release announcement; a package version alone does not establish a support commitment.

## Report a vulnerability privately

**Do not open a public issue or pull request for an unpatched vulnerability.**

1. Prefer GitHub's private vulnerability reporting: [Report a vulnerability privately](https://github.com/LloydCoder/Aithyrex/security/advisories/new). If unavailable, email **security@tinlance.com**.
2. Include the affected commit/version, impact, prerequisites, reproducible steps or a minimal proof of concept, and any safe mitigation.
3. Do not include customer prompts/completions, credentials, access tokens, personal data or production secrets. Redact logs and payloads.
4. Allow maintainers reasonable time to validate and coordinate a fix before public disclosure.

## Response targets

- **Initial acknowledgement:** within 3 business days.
- **Initial triage:** within 7 business days of receipt.

These are response targets, not a guarantee of remediation or a service-level agreement. Complex reports may require additional investigation; the maintainer should communicate material changes to the expected timeline.

## What to expect

The maintainer will attempt to confirm receipt, reproduce the issue safely, assess severity and affected versions, coordinate a fix or mitigation, and agree on disclosure timing with the reporter where practical. Do not test systems or data you do not own or have permission to assess.

## Scope and architectural notes

Reports involving authentication, tenant isolation, secret handling, detector failure semantics, evidence integrity, webhooks, SDK interception or policy/response integrations are in scope when they affect this repository. Aithyrex findings are not authorization grants; Tinlance Agent Platform remains authoritative for identity, policy, approval and governed execution.
