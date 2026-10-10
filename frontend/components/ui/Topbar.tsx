'use client'
import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { useAuth } from '@clerk/nextjs'

export default function Topbar() {
  const { getToken } = useAuth()
  const [health, setHealth] = useState<string>('checking')

  useEffect(() => {
    const check = async () => {
      try {
        const token = await getToken()
        const h = await api.health(token || undefined)
        setHealth(h.status)
      } catch {
        setHealth('unreachable')
      }
    }
    check()
    const interval = setInterval(check, 30_000)
    return () => clearInterval(interval)
  }, [getToken])

  const statusColor = health === 'ok' ? '#10B981' : health === 'degraded' ? '#F59E0B' : '#EF4444'

  return (
    <header style={{
      height: '52px', flexShrink: 0,
      background: 'rgba(8,15,26,0.9)',
      backdropFilter: 'blur(12px)',
      borderBottom: '1px solid rgba(255,255,255,0.06)',
      display: 'flex', alignItems: 'center',
      padding: '0 24px',
      justifyContent: 'space-between',
      position: 'sticky', top: 0, zIndex: 50,
    }}>
      {/* Left */}
      <div style={{
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: '11px', color: '#475569',
        letterSpacing: '0.06em',
      }}>
        AI SHIELD DASHBOARD
      </div>

      {/* Right */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        {/* Health */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: '6px',
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '10px', color: statusColor,
        }}>
          <span style={{
            width: '6px', height: '6px',
            background: statusColor, borderRadius: '50%',
            display: 'inline-block',
            boxShadow: health === 'ok' ? `0 0 6px ${statusColor}` : 'none',
          }} />
          AITHYREX {health.toUpperCase()}
        </div>

        {/* Docs link */}
        <a
          href="https://github.com/Tinlance/ai-shield"
          target="_blank"
          rel="noopener noreferrer"
          style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '10px', color: '#475569',
            textDecoration: 'none', letterSpacing: '0.05em',
            transition: 'color 0.15s',
          }}
          onMouseOver={e => (e.currentTarget.style.color = '#00D4FF')}
          onMouseOut={e => (e.currentTarget.style.color = '#475569')}
        >
          GITHUB ↗
        </a>
      </div>
    </header>
  )
}
