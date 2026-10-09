'use client'

export default function BillingPage() {
  return (
    <div style={{ maxWidth: '1000px' }}>
      <div style={{ marginBottom: '24px' }}>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
          color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px',
        }}>// Billing</div>
        <h1 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '22px', fontWeight: 700, color: '#FFFFFF' }}>
          Billing & Entitlements
        </h1>
        <p style={{ fontSize: '13px', color: '#94A3B8', marginTop: '4px' }}>
          Plan and usage information must come from server-side billing records.
        </p>
      </div>

      <div role="status" className="shield-card" style={{ padding: '20px', marginBottom: '16px' }}>
        <strong style={{ color: '#F59E0B' }}>Billing status unavailable</strong>
        <p style={{ color: '#94A3B8', fontSize: '13px', marginTop: '8px' }}>
          The current dashboard does not yet retrieve verified subscription status, provider invoices, or tenant usage from a production billing service. No current plan, price, usage amount, or SLA is asserted by this screen.
        </p>
      </div>

      <div className="shield-card" style={{ padding: '20px' }}>
        <h2 style={{ color: '#FFFFFF', fontSize: '15px', fontWeight: 600 }}>Required before billing launch</h2>
        <ul style={{ color: '#94A3B8', fontSize: '13px', paddingLeft: '20px', marginTop: '12px', lineHeight: 1.8 }}>
          <li>Server-authoritative provider customer and subscription identifiers.</li>
          <li>Verified, replay-resistant webhook processing and idempotent entitlement updates.</li>
          <li>Atomic tenant usage accounting and plan-limit enforcement.</li>
          <li>Invoice, cancellation, refund, failed-payment and renewal reconciliation.</li>
          <li>Pricing and SLA claims approved and published only after commercial sign-off.</li>
        </ul>
      </div>
    </div>
  )
}
