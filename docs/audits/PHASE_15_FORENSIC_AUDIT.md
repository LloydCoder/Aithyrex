# Phase 15 — Compliance Evidence Export Forensic Audit

**Phase:** Compliance evidence and exports  
**Branch:** godmode/phase-15-compliance-evidence-exports  
**Audit status:** implementation and acceptance pending latest-head CI and Security Scan.

## Scope

Implement tenant-scoped export of persisted detection-event metadata in JSON, CSV and Markdown without exposing raw prompt/completion content or arbitrary detector detail blobs. Make the evidence digest deterministic and explicitly distinguish evidence generation from regulatory assessment, notification and legal submission.

## Security invariants

- Enterprise entitlement is checked server-side before database access.
- Event UUID and authenticated tenant UUID are bound in the same database predicate.
- Missing and cross-tenant events are indistinguishable (404); storage failure returns 503 and never produces a placeholder report.
- Exports include only allow-listed fields; raw prompts, completions and detector details are excluded.
- CSV formula prefixes are neutralized, identifiers and MITRE IDs are validated, and response caching is disabled.
- Digest is computed over canonical evidence JSON and excludes per-export metadata, allowing stable re-export verification.
- Export clearly states not_submitted; no legal determination or filing is implied.

## Acceptance criteria

- Unit tests prove digest stability, content minimization, CSV formula safety, identifier normalization and explicit submission disclaimers.
- Route tests prove Enterprise-only access, tenant-bound lookup, non-enumerating 404, malformed UUID handling, storage failure behavior, supported formats and digest/cache headers.
- CI and Security Scan must pass on the final branch head, followed by forensic review and post-merge workflow verification.

## External and residual gates

A green workflow does not establish legal sufficiency, regulatory applicability, production deployment, database immutability, external report delivery, or regulator acknowledgement. The current /summary endpoint remains 501 and is not claimed implemented.
