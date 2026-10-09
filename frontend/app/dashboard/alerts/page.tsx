'use client'
import { useEffect, useRef, useState } from 'react'
import { useAuth } from '@clerk/nextjs'

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

const DEMO_ALERTS: AlertEvent[] = [
  { id: '1', time: 'just now', action: 'block', severity: 'critical', detector: 'credential_leak', model: 'gpt-4o', mitre: ['T1552'], confidence: 0.99, blocked: true },
  { id: '2', time: '0:14 ago', action: 'block', severity: 'high', detector: 'prompt_injection', model: 'claude-sonnet-4-5', mitre: ['AML.T0051'], confidence: 0.87, blocked: true },
  { id: '3', time: '0:38 ago', action: 'alert', severity: 'high', detector: 'covert_channel', model: 'gpt-4o-mini', mitre: ['AML.T0048'], confidence: 0.71, blocked: false },
  { id: '4', time: '1:12 ago', action: 'block', severity: 'critical', detector: 'prompt_injection', model: 'llama-3.3-70b', mitre: ['AML.T0051'], confidence: 0.92, blocked: true },
  { id: '5', time: '2:04 ago', action: 'alert', severity: 'medium', detector: 'c2_behaviour', model: 'gpt-4o', mitre: ['T1071.001'], confidence: 0.61, blocked: false },
]

const actionColor: Record<string, string> = {
  block: '#EF4444', alert: '#F59E0B', log: '#94A3B8', pass: '#10B981',
}
const severityColor: Record<string, string> = {
  critical: '#EF4444', high: '#F59E0B', medium: '#8B5CF6', low: '#94A3B8', clean: '#10B981',
}

export default function AlertsPage() {
  const { getToken } = useAuth()
  const [alerts, setAlerts] = useState<AlertEvent[]>(DEMO_ALERTS)
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8002'
    try {
      const ws = new WebSocket(`${wsUrl}/monitor/stream`)
      wsRef.current = ws
      ws.onopen = () => setWsStatus('connected')
      ws.onclose = () => setWsStatus('disconnected')
      ws.onerror = () => setWsStatus('disconnected')
      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data.action && data.severity) {
            const newAlert: AlertEvent = {
              id: Date.now().toString(),
              time: 'just now',
              action: data.action,
              severity: data.severity,
              detector: data.detections?.[0]?.detector || 'unknown',
              model: data.model || 'unknown',
              mitre: data.detections?.[0]?.mitre_atlas || [],
              confidence: data.detections?.[0]?.confidence || 0,
              blocked: data.blocked,
            }
            setAlerts(prev => [newAlert, ...prev].slice(0, 50))
          }
        } catch {}
      }
    } catch {
      setWsStatus('disconnected')
    }
    return () => wsRef.current?.close()
  }, [])

  return (
    <div style={{ maxWidth: '1100px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <div style={{
            fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
            color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px',
          }}>// Live Feed</div>
          <h1 style={{
            fontFamily: 'Space Grotesk, sans-serif',
            fontSize: '22px', fontWeight: 700, color: '#FFFFFF',
          }}>Alert Feed</h1>
        </div>
        <div style={{
          display: 'flex', alignItems: 'center', gap: '6px',
          fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
        }}>
          <span style={{
            width: '7px', height: '7px', borderRadius: '50%',
            background: wsStatus === 'connected' ? '#EF4444' : '#475569',
            display: 'inline-block',
            boxShadow: wsStatus === 'connected' ? '0 0 6px #EF4444' : 'none',
            animation: wsStatus === 'connected' ? 'pulse-red 1.5s infinite' : 'none',
          }} />
          <span style={{ color: wsStatus === 'connected' ? '#EF4444' : '#475569' }}>
            {wsStatus === 'connected' ? 'LIVE' : wsStatus.toUpperCase()}
          </span>
          <span style={{ color: '#475569', marginLeft: '8px' }}>{alerts.length} events</span>
        </div>
      </div>

      {/* Feed table */}
      <div className="shield-card" style={{ overflow: 'hidden' }}>
        {/* Table header */}
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
          <span>TIME</span><span>ACTION</span><span>DETECTOR</span>
          <span>MODEL</span><span>MITRE</span><span>CONF.</span>
        </div>

        {/* Rows */}
        {alerts.map((alert, i) => (
          <div
            key={alert.id}
            style={{
              display: 'grid',
              gridTemplateColumns: '90px 80px 160px 1fr 130px 70px',
              padding: '11px 16px',
              borderBottom: i < alerts.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
              alignItems: 'center', gap: '12px',
              transition: 'background 0.15s',
              cursor: 'default',
              background: i === 0 && alerts[0].id === alert.id ? 'rgba(0,212,255,0.02)' : 'transparent',
            }}
            onMouseOver={e => e.currentTarget.style.background = 'rgba(0,212,255,0.02)'}
            onMouseOut={e => e.currentTarget.style.background = 'transparent'}
          >
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#475569' }}>
              {alert.time}
            </span>
            <span className={`chip chip-${alert.action}`}>{alert.action.toUpperCase()}</span>
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#E2E8F0' }}>
              {alert.detector}
            </span>
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#00D4FF' }}>
              {alert.model}
            </span>
            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
              {alert.mitre.map(m => (
                <span key={m} style={{
                  fontFamily: 'JetBrains Mono, monospace', fontSize: '9px',
                  padding: '1px 5px', background: 'rgba(139,92,246,0.12)',
                  color: '#A78BFA', borderRadius: '3px',
                  border: '1px solid rgba(139,92,246,0.2)',
                }}>{m}</span>
              ))}
            </div>
            <span style={{
              fontFamily: 'JetBrains Mono, monospace', fontSize: '11px',
              color: severityColor[alert.severity] || '#94A3B8',
            }}>
              {Math.round(alert.confidence * 100)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
