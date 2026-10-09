'use client'

const PLANS = [
  {
    id: 'free', name: 'Free', price: '$0', period: '/mo',
    inferences: '500/mo', current: false,
    features: ['Prompt injection', 'Credential leak (18 patterns)', 'JSON export', '1 model'],
  },
  {
    id: 'starter', name: 'Starter', price: '$49', period: '/mo',
    inferences: '25,000/mo + $0.002 overage', current: false,
    features: ['Everything in Free', '5 models', 'Webhook alerts', 'CSV export'],
  },
  {
    id: 'pro', name: 'Pro', price: '$199', period: '/mo',
    inferences: '150,000/mo + $0.001 overage', current: true,
    features: ['Everything in Starter', 'Unlimited models', 'Block mode', 'SIEM export', 'MITRE ATLAS', '5 custom rules'],
    highlight: true,
  },
  {
    id: 'enterprise', name: 'Enterprise', price: 'Custom', period: '',
    inferences: 'Unlimited', current: false,
    features: ['Everything in Pro', 'NIS2/DORA reports', 'Air-gap deploy', 'Unlimited rules', 'SSO + SAML', '99.9% SLA'],
  },
]

export default function BillingPage() {
  return (
    <div style={{ maxWidth: '1100px' }}>
      <div style={{ marginBottom: '28px' }}>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
          color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px',
        }}>// Billing</div>
        <h1 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '22px', fontWeight: 700, color: '#FFFFFF' }}>
          Plan & Billing
        </h1>
        <p style={{ fontSize: '13px', color: '#475569', marginTop: '4px' }}>
          Managed by LemonSqueezy (global) · Paddle for EU/Enterprise · EU VAT auto-handled
        </p>
      </div>

      {/* Usage meter */}
      <div className="shield-card" style={{ padding: '20px', marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
          <span style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '13px', fontWeight: 600, color: '#FFFFFF' }}>
            This Month — Pro Plan
          </span>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#00D4FF' }}>
            14,832 / 150,000
          </span>
        </div>
        <div style={{
          height: '6px', background: 'rgba(255,255,255,0.06)',
          borderRadius: '3px', overflow: 'hidden',
        }}>
          <div style={{
            height: '100%', width: `${(14832 / 150000) * 100}%`,
            background: 'linear-gradient(90deg, #00D4FF, #0891B2)',
            borderRadius: '3px', transition: 'width 0.5s ease',
          }} />
        </div>
        <p style={{
          marginTop: '6px', fontFamily: 'JetBrains Mono, monospace',
          fontSize: '10px', color: '#475569',
        }}>9.9% of monthly limit used · No overage charges yet</p>
      </div>

      {/* Plan cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
        {PLANS.map(plan => (
          <div key={plan.id} style={{
            background: plan.highlight ? 'linear-gradient(180deg, rgba(0,212,255,0.06) 0%, #0D1B2A 100%)' : '#0D1B2A',
            border: `1px solid ${plan.highlight ? '#00D4FF' : plan.current ? 'rgba(0,212,255,0.3)' : 'rgba(255,255,255,0.06)'}`,
            borderRadius: '10px', padding: '20px',
            position: 'relative',
          }}>
            {plan.current && (
              <div style={{
                position: 'absolute', top: '-1px', left: '50%', transform: 'translateX(-50%)',
                fontFamily: 'JetBrains Mono, monospace', fontSize: '9px',
                padding: '2px 10px', background: '#00D4FF', color: '#060A14',
                fontWeight: 700, borderRadius: '0 0 5px 5px', letterSpacing: '0.05em',
              }}>CURRENT</div>
            )}

            <div style={{
              fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
              color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase',
              marginBottom: '10px', marginTop: plan.current ? '12px' : '0',
            }}>{plan.name}</div>

            <div style={{
              fontFamily: 'Space Grotesk, sans-serif', fontSize: '28px',
              fontWeight: 700, color: '#FFFFFF', lineHeight: 1, marginBottom: '4px',
            }}>
              {plan.price}
              <span style={{ fontSize: '13px', color: '#475569', fontWeight: 400 }}>{plan.period}</span>
            </div>

            <div style={{
              fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
              color: '#475569', marginBottom: '16px',
            }}>{plan.inferences}</div>

            <div style={{
              height: '1px', background: 'rgba(255,255,255,0.06)', marginBottom: '14px',
            }} />

            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {plan.features.map(f => (
                <li key={f} style={{
                  display: 'flex', gap: '7px', alignItems: 'flex-start',
                  fontSize: '12px', color: '#94A3B8',
                }}>
                  <span style={{ color: '#10B981', flexShrink: 0, marginTop: '1px' }}>✓</span>
                  {f}
                </li>
              ))}
            </ul>

            <button
              disabled={plan.current}
              style={{
                marginTop: '18px', width: '100%', padding: '10px',
                background: plan.current ? 'rgba(0,212,255,0.06)' : plan.highlight ? '#00D4FF' : 'transparent',
                border: plan.current ? '1px solid rgba(0,212,255,0.2)' : plan.highlight ? 'none' : '1px solid rgba(255,255,255,0.1)',
                color: plan.current ? '#00D4FF' : plan.highlight ? '#060A14' : '#FFFFFF',
                fontFamily: 'Space Grotesk, sans-serif', fontSize: '13px', fontWeight: 600,
                borderRadius: '7px', cursor: plan.current ? 'default' : 'pointer',
                transition: 'all 0.2s',
              }}
            >
              {plan.current ? 'Current Plan' : plan.id === 'enterprise' ? 'Contact Sales' : `Upgrade to ${plan.name}`}
            </button>
          </div>
        ))}
      </div>

      <p style={{
        marginTop: '16px', fontSize: '11px', color: '#475569',
        fontFamily: 'JetBrains Mono, monospace', textAlign: 'center',
      }}>
        Annual plans: 2 months free · Cancel anytime · Questions? nwachukwuchinaemerem8@gmail.com
      </p>
    </div>
  )
}
