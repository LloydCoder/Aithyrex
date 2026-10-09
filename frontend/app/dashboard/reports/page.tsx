'use client'

const REPORT_CAPABILITIES = [
  { label: 'JSON findings export', detail: 'Tenant-scoped export from persisted findings', status: 'Not implemented' },
  { label: 'CSV findings export', detail: 'Tenant-scoped export from persisted findings', status: 'Not implemented' },
  { label: 'CEF / Splunk HEC', detail: 'Acknowledged SIEM delivery with retries and idempotency', status: 'Not verified' },
  { label: 'STIX 2.1', detail: 'Schema-validated threat-intelligence export', status: 'Not verified' },
  { label: 'NIS2 / DORA evidence', detail: 'Evidence package generation and approval workflow', status: 'Not implemented' },
]

export default function ReportsPage() {
  return (
    <div style={{ maxWidth: '1100px' }}>
      <div style={{ marginBottom: '24px' }}>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
          color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px',
        }}>// Reporting</div>
        <h1 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '22px', fontWeight: 700, color: '#FFFFFF' }}>
          Exports & Compliance Evidence
        </h1>
        <p style={{ fontSize: '13px', color: '#94A3B8', marginTop: '4px' }}>
          No export or filing is reported as successful unless a backend workflow confirms it.
        </p>
      </div>

      <div role="status" className="shield-card" style={{ padding: '18px', marginBottom: '16px' }}>
        <strong style={{ color: '#F59E0B' }}>Reporting workflows are not yet available</strong>
        <p style={{ color: '#94A3B8', marginTop: '6px', fontSize: '13px' }}>
          The current backend does not provide persisted tenant-scoped report generation or regulatory filing. No report has been filed or delivered by this screen.
        </p>
      </div>

      <div className="shield-card" style={{ padding: '20px' }}>
        <div style={{
          fontFamily: 'Space Grotesk, sans-serif', fontSize: '14px',
          fontWeight: 600, color: '#FFFFFF', marginBottom: '14px',
        }}>Capability status</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {REPORT_CAPABILITIES.map(item => (
            <div key={item.label} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              gap: '16px', padding: '14px', background: '#080F1A',
              border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px',
            }}>
              <div>
                <div style={{ color: '#FFFFFF', fontSize: '13px', fontWeight: 600 }}>{item.label}</div>
                <div style={{ color: '#94A3B8', fontSize: '11px', marginTop: '4px' }}>{item.detail}</div>
              </div>
              <span style={{ color: '#F59E0B', fontSize: '10px', whiteSpace: 'nowrap' }}>{item.status}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
