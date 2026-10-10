# Aithyrex Compliance Evidence Exports

## Purpose and authority boundary

Aithyrex exports a tenant-scoped, content-minimized technical evidence artifact from an already-persisted detection event. The export is not legal advice, a regulatory determination, a notification to a regulator, or proof of delivery. It explicitly reports **not_submitted** and **legal_submission_performed=false**.

Tinlance Agent Platform remains authoritative for identity, authorization and governed execution. KalevioAI remains a separate compliance evidence/reporting workflow. Aithyrex does not infer that an event meets a statutory reporting threshold or automatically file a NIS2/DORA report.

## API

- **GET** /api/v1/reports/compliance/{event_id}?format=json|csv|markdown
- Compatibility: **POST** /api/v1/reports/compliance?incident_id={event_uuid}&format=json|csv|markdown

The legacy incident_id parameter is an alias for a persisted detection_events.id UUID. Both routes require a server-authorized Enterprise tenant. The event lookup includes both event UUID and tenant UUID in the same SQL predicate. Missing and cross-tenant events return the same 404. Database unavailability returns 503; no empty or synthetic report is generated.

The /summary endpoint remains explicitly unimplemented and returns 501; this phase does not claim persisted summary analytics.

## Export contents and integrity

- Versioned schema: **aithyrex.compliance-evidence-export.v1**.
- SHA-256 digest is computed over canonical JSON for the immutable, allow-listed evidence body, excluding per-export report ID and generation time. Re-exporting the same persisted event yields the same evidence digest.
- Findings include detector identifier, severity, uncalibrated confidence metadata and allow-listed MITRE IDs. Arbitrary detector details, raw prompts, completions and matched values are never exported.
- CSV output neutralizes spreadsheet formula prefixes; Markdown output escapes table delimiters and control characters.
- Responses include X-Aithyrex-Evidence-Digest, Cache-Control: no-store, Pragma: no-cache and an attachment filename.
- Each export includes explicit not_submitted, legal_submission_performed=false and regulatory_assessment=not_performed fields.

The digest provides tamper-evidence for the exported allow-listed event snapshot; it is not a digital signature, trusted timestamp, external notarization, proof of delivery, or immutable database guarantee.

## Verification

Tests cover stable digest behavior, redaction of detector detail blobs, confidence/identifier normalization, CSV formula injection, format rendering, Enterprise entitlement, tenant-scoped lookup, non-enumerating 404s, malformed UUIDs, no-store headers, digest headers and database outage semantics.

## Residual limitations

- The report is built from the persisted detection event and does not include raw prompts or full detector details by design.
- It does not establish incident significance, statutory applicability, report deadlines, legal sufficiency, or successful filing.
- The database's retention, backup, access logging and tamper-resistant storage are separate operational controls.
- External KalevioAI delivery and any regulator submission remain separate workflows requiring explicit acknowledgement and human/legal oversight.
