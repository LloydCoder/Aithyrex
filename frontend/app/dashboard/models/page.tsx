'use client'
import { useState, useEffect } from 'react'
import { useAuth } from '@clerk/nextjs'
import { api, type BlockedItem } from '@/lib/api'

const DEMO_MODELS = [
  { id: 'gpt-4o',             provider: 'OpenAI',    status: 'monitored', inferences: 4821, blocked_count: 23 },
  { id: 'claude-sonnet-4-5',  provider: 'Anthropic', status: 'monitored', inferences: 2103, blocked_count: 7  },
  { id: 'gpt-4o-mini',        provider: 'OpenAI',    status: 'monitored', inferences: 8741, blocked_count: 41 },
  { id: 'llama-3.3-70b',      provider: 'Groq',      status: 'monitored', inferences: 1209, blocked_count: 3  },
  { id: 'gemini-2.5-flash',   provider: 'Google',    status: 'monitored', inferences: 521,  blocked_count: 1  },
]

export default function ModelsPage() {
  const { getToken } = useAuth()
  const [blockedItems, setBlockedItems] = useState<BlockedItem[]>([])
  const [blocking, setBlocking] = useState<string | null>(null)
  const [reason, setReason] = useState('')

  useEffect(() => {
    const load = async () => {
      try {
        const token = await getToken()
        const data = await api.listBlocked(token || undefined)
        setBlockedItems(data.blocked || [])
      } catch {}
    }
    load()
  }, [getToken])

  const isBlocked = (modelId: string) =>
    blockedItems.some(b => b.type === 'model' && b.id === modelId)

  const handleBlock = async (modelId: string) => {
    try {
      const token = await getToken()
      await api.blockModel(modelId, reason || 'Blocked by admin', token || undefined)
      setBlockedItems(prev => [...prev, {
        type: 'model', id: modelId,
        reason: reason || 'Blocked by admin',
        expires_in_seconds: 86400,
      }])
      setBlocking(null); setReason('')
    } catch (e: any) {
      alert(e.message)
    }
  }

  const handleUnblock = async (modelId: string) => {
    try {
      const token = await getToken()
      await api.unblockModel(modelId, token || undefined)
      setBlockedItems(prev => prev.filter(b => !(b.type === 'model' && b.id === modelId)))
    } catch (e: any) {
      alert(e.message)
    }
  }

  return (
    <div style={{ maxWidth: '1100px' }}>
      <div style={{ marginBottom: '24px' }}>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
          color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px',
        }}>// Models</div>
        <h1 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '22px', fontWeight: 700, color: '#FFFFFF' }}>
          Monitored Models
        </h1>
        <p style={{ fontSize: '13px', color: '#475569', marginTop: '4px' }}>
          All LLM models currently monitored by AI Shield
        </p>
      </div>

      <div className="shield-card" style={{ overflow: 'hidden' }}>
        {/* Header */}
        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 120px 110px 110px 130px',
          padding: '10px 18px',
          background: '#080F1A', borderBottom: '1px solid rgba(255,255,255,0.06)',
          fontFamily: 'JetBrains Mono, monospace', fontSize: '9px',
          color: '#475569', letterSpacing: '0.08em', textTransform: 'uppercase', gap: '12px',
        }}>
          <span>MODEL</span><span>PROVIDER</span>
          <span>INFERENCES</span><span>BLOCKED</span><span>ACTION</span>
        </div>

        {DEMO_MODELS.map((model, i) => {
          const blocked = isBlocked(model.id)
          return (
            <div key={model.id} style={{
              display: 'grid', gridTemplateColumns: '1fr 120px 110px 110px 130px',
              padding: '14px 18px', gap: '12px',
              borderBottom: i < DEMO_MODELS.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
              alignItems: 'center',
              background: blocked ? 'rgba(239,68,68,0.03)' : 'transparent',
            }}>
              <div>
                <div style={{
                  fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: '#E2E8F0',
                }}>{model.id}</div>
                {blocked && (
                  <div style={{
                    fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: '#EF4444',
                    marginTop: '2px',
                  }}>● BLOCKED</div>
                )}
              </div>
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#00D4FF' }}>
                {model.provider}
              </span>
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#94A3B8' }}>
                {model.inferences.toLocaleString()}
              </span>
              <span style={{
                fontFamily: 'JetBrains Mono, monospace', fontSize: '11px',
                color: model.blocked_count > 20 ? '#EF4444' : '#94A3B8',
              }}>
                {model.blocked_count}
              </span>
              <div>
                {blocking === model.id ? (
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <input
                      type="text"
                      placeholder="reason"
                      value={reason}
                      onChange={e => setReason(e.target.value)}
                      style={{
                        background: '#080F1A', border: '1px solid rgba(239,68,68,0.3)',
                        borderRadius: '5px', padding: '4px 8px', fontSize: '11px',
                        color: '#E2E8F0', fontFamily: 'JetBrains Mono, monospace',
                        width: '80px', outline: 'none',
                      }}
                    />
                    <button onClick={() => handleBlock(model.id)} style={{
                      background: '#EF4444', border: 'none', color: '#FFF',
                      fontSize: '10px', padding: '4px 8px', borderRadius: '5px', cursor: 'pointer',
                      fontFamily: 'JetBrains Mono, monospace',
                    }}>BLOCK</button>
                    <button onClick={() => { setBlocking(null); setReason('') }} style={{
                      background: 'transparent', border: '1px solid rgba(255,255,255,0.1)',
                      color: '#94A3B8', fontSize: '10px', padding: '4px 8px',
                      borderRadius: '5px', cursor: 'pointer',
                      fontFamily: 'JetBrains Mono, monospace',
                    }}>✕</button>
                  </div>
                ) : blocked ? (
                  <button onClick={() => handleUnblock(model.id)} style={{
                    background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.25)',
                    color: '#10B981', fontSize: '10px', padding: '5px 10px',
                    borderRadius: '5px', cursor: 'pointer',
                    fontFamily: 'JetBrains Mono, monospace',
                  }}>UNBLOCK</button>
                ) : (
                  <button onClick={() => setBlocking(model.id)} style={{
                    background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
                    color: '#EF4444', fontSize: '10px', padding: '5px 10px',
                    borderRadius: '5px', cursor: 'pointer',
                    fontFamily: 'JetBrains Mono, monospace', transition: 'all 0.15s',
                  }}>BLOCK</button>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
