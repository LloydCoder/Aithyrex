'use client'

interface AlertEvent {
  id: string
  time: string
  action: string
  severity: string
  detector: string
  model: string
  mitre: string[]
  confidence: number
  blocked: boolean
}

export default function AlertsPage() {
  const alerts: AlertEvent[] = []

  return (
    <div style={{ maxWidth: '1100px' }}>
      <div style={{ marginBottom: '24px' }}>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
          color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px',
        }}>Event Feed</div>
        <h1 style={{
          fontFamily: 'Space Grotesk, sans-serif',
          fontSize: '22px', fontWeight: 700, color: '#FFFFFF',
        }}>Security Events</h1>
        <p style={{ fontSize: '13px', color: '#94A3B8', marginTop: '4px' }}>
          Events are shown only when delivered by the authenticated, tenant-scoped backend.
        </p>
      </div>

      <div role="status" className="shield-card" style={{ padding: '18px', marginBottom: '16px' }}>
        <strong style={{ color: '#F59E0B' }}>Live feed unavailable</strong>
        <p style={{ color: '#94A3B8', marginTop: '6px', fontSize: '13px' }}>
          A durable tenant-scoped event publisher and authenticated live-stream contract are not implemented yet. No sample alerts are presented as real events.
        </p>
      </div>

      <div className="shield-card" style={{ overflow: 'hidden' }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: '90px 80px 160px 1fr 130px 70px',
          padding: '10px 16px',
          background: '#080F1A',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '9px', color: '#475569',
          letterSpacing: '0.08em', textTransform: 'uppercase',
          gap: '12px',
        }}>
          <span>TIME</span><span>ACTION</span><span>DETECTOR</span><span>MODEL</span><span>SEVERITY</span><span>BLOCKED</span>
        </div>
        {alerts.length === 0 && (
          <div style={{ padding: '32px 16px', textAlign: 'center', color: '#94A3B8', fontSize: '13px' }}>
            No backend-backed events are available to display.
          </div>
        )}
      </div>
    </div>
  )
}
