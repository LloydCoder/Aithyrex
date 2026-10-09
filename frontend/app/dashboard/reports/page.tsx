'use client'
import { useState } from 'react'
import { useAuth } from '@clerk/nextjs'

const EXPORT_FORMATS = [
  { id: 'json',       label: 'JSON',       plan: 'free',       icon: '{}', desc: 'Standard JSON export' },
  { id: 'csv',        label: 'CSV',        plan: 'starter',    icon: '⊞', desc: 'Spreadsheet-compatible' },
  { id: 'cef',        label: 'CEF',        plan: 'pro',        icon: '⬡', desc: 'Common Event Format' },
  { id: 'splunk_hec', label: 'Splunk HEC', plan: 'pro',        icon: '◎', desc: 'Splunk HTTP Event Collector' },
  { id: 'stix21',     label: 'STIX 2.1',  plan: 'enterprise', icon: '◈', desc: 'Structured Threat Intelligence' },
]

const PLAN_ORDER = ['free', 'starter', 'pro', 'enterprise']
const planColor: Record<string, string> = {
  free: '#94A3B8', starter: '#00D4FF', pro: '#F59E0B', enterprise: '#10B981',
}

export default function ReportsPage() {
  const { getToken } = useAuth()
  const [exporting, setExporting] = useState<string | null>(null)
  const [nis2Loading, setNis2Loading] = useState(false)
  const [nis2Done, setNis2Done] = useState(false)
  const currentPlan = 'pro'   // From Clerk metadata in production

  const canUse = (formatPlan: string) =>
    PLAN_ORDER.indexOf(currentPlan) >= PLAN_ORDER.indexOf(formatPlan)

  const handleExport = async (formatId: string) => {
    setExporting(formatId)
    await new Promise(r => setTimeout(r, 1200))
    setExporting(null)
    alert(`${formatId.toUpperCase()} export triggered. Check your SIEM or download folder.`)
  }

  const handleNIS2 = async () => {
    setNis2Loading(true)
    await new Promise(r => setTimeout(r, 2000))
    setNis2Loading(false); setNis2Done(true)
    setTimeout(() => setNis2Done(false), 4000)
  }

  return (
    <div style={{ maxWidth: '1100px' }}>
      <div style={{ marginBottom: '24px' }}>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
          color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px',
        }}>// Reports</div>
        <h1 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '22px', fontWeight: 700, color: '#FFFFFF' }}>
          Export & Compliance
        </h1>
        <p style={{ fontSize: '13px', color: '#475569', marginTop: '4px' }}>
          SIEM exports and NIS2/DORA compliance reports
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '16px' }}>
        {/* SIEM Exports */}
        <div className="shield-card" style={{ padding: '20px' }}>
          <div style={{
            fontFamily: 'Space Grotesk, sans-serif', fontSize: '15px',
            fontWeight: 600, color: '#FFFFFF', marginBottom: '16px',
          }}>SIEM Export Formats</div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {EXPORT_FORMATS.map(fmt => {
              const available = canUse(fmt.plan)
              const loading = exporting === fmt.id
              return (
                <div key={fmt.id} style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '14px 16px',
                  background: '#080F1A',
                  border: `1px solid ${available ? 'rgba(0,212,255,0.1)' : 'rgba(255,255,255,0.05)'}`,
                  borderRadius: '8px', opacity: available ? 1 : 0.5,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ fontSize: '18px', color: available ? '#00D4FF' : '#475569' }}>
                      {fmt.icon}
                    </span>
                    <div>
                      <div style={{
                        fontFamily: 'Space Grotesk, sans-serif',
                        fontSize: '13px', fontWeight: 600,
                        color: available ? '#FFFFFF' : '#475569',
                      }}>{fmt.label}</div>
                      <div style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '10px', color: '#475569',
                      }}>{fmt.desc}</div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{
                      fontFamily: 'JetBrains Mono, monospace', fontSize: '9px',
                      padding: '2px 6px', borderRadius: '3px',
                      background: `${planColor[fmt.plan]}18`,
                      color: planColor[fmt.plan],
                      border: `1px solid ${planColor[fmt.plan]}35`,
                      textTransform: 'uppercase',
                    }}>{fmt.plan}</span>
                    <button
                      onClick={() => available && handleExport(fmt.id)}
                      disabled={!available || !!exporting}
                      style={{
                        background: available ? 'rgba(0,212,255,0.1)' : 'rgba(255,255,255,0.04)',
                        border: `1px solid ${available ? 'rgba(0,212,255,0.25)' : 'rgba(255,255,255,0.08)'}`,
                        color: available ? '#00D4FF' : '#475569',
                        fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
                        padding: '5px 12px', borderRadius: '5px',
                        cursor: available ? 'pointer' : 'not-allowed',
                        transition: 'all 0.15s', minWidth: '70px',
                      }}
                    >
                      {loading ? '...' : available ? 'EXPORT' : 'UPGRADE'}
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* NIS2/DORA panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div className="shield-card" style={{ padding: '20px' }}>
            <div style={{ marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <span style={{ fontSize: '20px' }}>🇪🇺</span>
                <div style={{
                  fontFamily: 'Space Grotesk, sans-serif',
                  fontSize: '15px', fontWeight: 600, color: '#FFFFFF',
                }}>NIS2 / DORA</div>
                <span className="chip chip-clean" style={{ fontSize: '9px' }}>ENTERPRISE</span>
              </div>
              <p style={{ fontSize: '12px', color: '#475569', lineHeight: 1.6 }}>
                Trigger a compliance incident report. AI Shield will POST to KalevioAI
                and auto-generate the NIS2 Article 23 report for CSIRT submission.
              </p>
            </div>

            <button
              onClick={handleNIS2}
              disabled={nis2Loading || currentPlan !== 'enterprise'}
              style={{
                width: '100%', padding: '11px',
                background: nis2Done ? 'rgba(16,185,129,0.15)' : 'rgba(16,185,129,0.1)',
                border: `1px solid ${nis2Done ? 'rgba(16,185,129,0.5)' : 'rgba(16,185,129,0.25)'}`,
                color: '#10B981', fontFamily: 'Space Grotesk, sans-serif',
                fontSize: '13px', fontWeight: 600, borderRadius: '8px',
                cursor: currentPlan === 'enterprise' ? 'pointer' : 'not-allowed',
                opacity: currentPlan !== 'enterprise' ? 0.5 : 1,
                transition: 'all 0.2s',
              }}
            >
              {nis2Done ? '✓ Report Filed' : nis2Loading ? 'Filing...' : '▶ File NIS2 Incident'}
            </button>

            {currentPlan !== 'enterprise' && (
              <p style={{
                marginTop: '8px', fontSize: '11px', color: '#475569',
                fontFamily: 'JetBrains Mono, monospace', textAlign: 'center',
              }}>Enterprise plan required</p>
            )}
          </div>

          {/* Summary stats */}
          <div className="shield-card" style={{ padding: '20px' }}>
            <div style={{
              fontFamily: 'Space Grotesk, sans-serif', fontSize: '13px',
              fontWeight: 600, color: '#FFFFFF', marginBottom: '14px',
            }}>This Month</div>
            {[
              { label: 'Total Inferences', value: '14,832', color: '#00D4FF' },
              { label: 'Threats Blocked',  value: '127',    color: '#EF4444' },
              { label: 'Alerts Raised',    value: '89',     color: '#F59E0B' },
              { label: 'False Pos. Cleared', value: '23',   color: '#10B981' },
            ].map(s => (
              <div key={s.label} style={{
                display: 'flex', justifyContent: 'space-between',
                alignItems: 'center', padding: '8px 0',
                borderBottom: '1px solid rgba(255,255,255,0.04)',
              }}>
                <span style={{ fontSize: '12px', color: '#475569' }}>{s.label}</span>
                <span style={{
                  fontFamily: 'Space Grotesk, sans-serif',
                  fontSize: '15px', fontWeight: 700, color: s.color,
                }}>{s.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
