'use client'

const DETECTOR_CATALOG = [
  { id: 'prompt_injection', name: 'Prompt-injection patterns', detail: 'Pattern-based detection for direct and indirect instruction overrides.' },
  { id: 'credential_leak', name: 'Credential-format patterns', detail: 'Locally maintained patterns for selected provider and token formats.' },
  { id: 'covert_channel', name: 'Encoding and covert-channel heuristics', detail: 'Encoding indicators and supplementary behavioral telemetry.' },
  { id: 'c2_behaviour', name: 'C2-behavior heuristics', detail: 'ThreatFade-derived signal; AI-text effectiveness requires separate validation.' },
  { id: 'data_poisoning', name: 'Context and data-risk heuristics', detail: 'Runtime text heuristics; not proof of offline training-data poisoning detection.' },
]

export default function RulesPage() {
  return (
    <div style={{ maxWidth: '900px' }}>
      <div style={{ marginBottom: '24px' }}>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
          color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px',
        }}>Detector Catalog</div>
        <h1 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '22px', fontWeight: 700, color: '#FFFFFF' }}>
          Detection Capabilities
        </h1>
        <p style={{ fontSize: '13px', color: '#94A3B8', marginTop: '4px' }}>
          This is a read-only code capability catalog, not a persisted rule-management interface.
        </p>
      </div>

      <div role="status" className="shield-card" style={{ padding: '16px', marginBottom: '16px', color: '#F59E0B' }}>
        Rule editing and per-tenant rule persistence are not implemented. No toggle or custom rule from this screen changes runtime enforcement.
      </div>

      <div className="shield-card" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {DETECTOR_CATALOG.map(detector => (
          <div key={detector.id} style={{
            padding: '14px', background: '#080F1A',
            border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px' }}>
              <strong style={{ color: '#FFFFFF', fontSize: '13px' }}>{detector.name}</strong>
              <span style={{ color: '#F59E0B', fontSize: '10px' }}>HEURISTIC</span>
            </div>
            <p style={{ color: '#94A3B8', fontSize: '12px', marginTop: '6px' }}>{detector.detail}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
