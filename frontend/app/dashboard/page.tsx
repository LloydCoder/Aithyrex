'use client'

import { useEffect, useState } from 'react'
import { useAuth } from '@clerk/nextjs'
import { api, type SummaryResponse } from '@/lib/api'
import QuickTest from '@/components/ui/QuickTest'

const STAT_CARDS = [
  { label: 'Inferences', key: 'total', color: '#00D4FF' },
  { label: 'Threats Blocked', key: 'blocked', color: '#EF4444' },
  { label: 'Alerts Raised', key: 'alerted', color: '#F59E0B' },
] as const

export default function DashboardPage() {
  const { getToken } = useAuth()
  const [summary, setSummary] = useState<SummaryResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [metricsError, setMetricsError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const token = await getToken()
        const data = await api.summary(7, token || undefined)
        if (active) setSummary(data)
      } catch {
        if (active) setMetricsError('Persisted tenant-scoped metrics are not available from the backend yet.')
      } finally {
        if (active) setLoading(false)
      }
    }
    void load()
    return () => { active = false }
  }, [getToken])

  return (
    <div style={{ maxWidth: '1100px' }}>
      <div style={{ marginBottom: '24px' }}>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '10px', color: '#475569',
          letterSpacing: '0.1em', textTransform: 'uppercase',
          marginBottom: '6px',
        }}>// Overview</div>
        <h1 style={{
          fontFamily: 'Space Grotesk, sans-serif',
          fontSize: '22px', fontWeight: 700, color: '#FFFFFF',
        }}>Security Overview</h1>
        <p style={{ fontSize: '13px', color: '#94A3B8', marginTop: '4px' }}>
          Metrics are shown only when returned by the authenticated backend.
        </p>
      </div>

      {metricsError && (
        <div role="status" className="shield-card" style={{ padding: '16px', marginBottom: '16px', color: '#F59E0B' }}>
          {metricsError}
        </div>
      )}

      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
        gap: '12px', marginBottom: '24px',
      }}>
        {STAT_CARDS.map(card => (
          <div key={card.key} className="stat-card">
            <div className="stat-num" style={{ color: card.color }}>
              {loading ? '…' : summary ? summary[card.key].toLocaleString() : 'N/A'}
            </div>
            <div className="stat-label">{card.label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 380px', gap: '16px', marginBottom: '24px' }}>
        <div className="shield-card" style={{ padding: '20px' }}>
          <div style={{
            fontFamily: 'Space Grotesk, sans-serif',
            fontSize: '14px', fontWeight: 600, color: '#FFFFFF',
            marginBottom: '12px',
          }}>Detection Activity</div>
          <p style={{ color: '#94A3B8', fontSize: '13px' }}>
            The durable tenant-scoped activity query is not implemented yet. No synthetic chart is displayed.
          </p>
        </div>
        <QuickTest />
      </div>

      <div className="shield-card" style={{ padding: '20px' }}>
        <div style={{
          fontFamily: 'Space Grotesk, sans-serif',
          fontSize: '14px', fontWeight: 600, color: '#FFFFFF',
          marginBottom: '10px',
        }}>Parliament Ensemble</div>
        <span className="chip">STATUS NOT REPORTED</span>
        <p style={{ marginTop: '12px', fontSize: '12px', color: '#94A3B8' }}>
          External model voters are advisory only. Provider health and live voting status are not currently exposed by a verified backend endpoint.
        </p>
      </div>
    </div>
  )
}
