'use client'

import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '@clerk/nextjs'
import { api, type BlockedItem } from '@/lib/api'

export default function ModelsPage() {
  const { getToken } = useAuth()
  const [blockedItems, setBlockedItems] = useState<BlockedItem[]>([])
  const [modelId, setModelId] = useState('')
  const [reason, setReason] = useState('')
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const loadBlocked = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const token = await getToken()
      const data = await api.listBlocked(token || undefined)
      setBlockedItems(data.blocked || [])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load server-side block state')
    } finally {
      setLoading(false)
    }
  }, [getToken])

  useEffect(() => { void loadBlocked() }, [loadBlocked])

  const handleBlock = async () => {
    if (!modelId.trim() || !reason.trim()) return
    setBusyId(modelId)
    setError(null)
    try {
      const token = await getToken()
      await api.blockModel(modelId.trim(), reason.trim(), token || undefined)
      setModelId('')
      setReason('')
      await loadBlocked()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Block request failed')
    } finally {
      setBusyId(null)
    }
  }

  const handleUnblock = async (item: BlockedItem) => {
    setBusyId(item.id)
    setError(null)
    try {
      const token = await getToken()
      await api.unblockModel(item.id, token || undefined)
      await loadBlocked()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unblock request failed')
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div style={{ maxWidth: '1000px' }}>
      <div style={{ marginBottom: '24px' }}>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
          color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px',
        }}>// Enforcement State</div>
        <h1 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '22px', fontWeight: 700, color: '#FFFFFF' }}>
          Model Blocklist
        </h1>
        <p style={{ fontSize: '13px', color: '#94A3B8', marginTop: '4px' }}>
          The model inventory and per-model inference counts are not available. This page shows only backend-confirmed block state.
        </p>
      </div>

      {error && (
        <div role="alert" className="shield-card" style={{ padding: '12px', marginBottom: '16px', color: '#EF4444' }}>
          {error}
        </div>
      )}

      <div className="shield-card" style={{ padding: '18px', marginBottom: '18px' }}>
        <h2 style={{ color: '#FFFFFF', fontSize: '14px', fontWeight: 600, marginBottom: '12px' }}>Block a model identifier</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr) auto', gap: '10px' }}>
          <input
            value={modelId}
            onChange={event => setModelId(event.target.value)}
            placeholder="Exact model identifier"
            aria-label="Model identifier"
            style={{ background: '#080F1A', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', padding: '9px 12px', color: '#E2E8F0' }}
          />
          <input
            value={reason}
            onChange={event => setReason(event.target.value)}
            placeholder="Reason (required for audit)"
            aria-label="Block reason"
            style={{ background: '#080F1A', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', padding: '9px 12px', color: '#E2E8F0' }}
          />
          <button onClick={() => void handleBlock()} disabled={!modelId.trim() || !reason.trim() || busyId !== null} className="btn-primary">
            {busyId === modelId ? 'Working…' : 'Block'}
          </button>
        </div>
        <p style={{ color: '#94A3B8', fontSize: '11px', marginTop: '10px' }}>
          The server confirms the block operation. If block-state storage is unavailable, the request returns an error and no success is shown.
        </p>
      </div>

      <div className="shield-card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid rgba(255,255,255,0.06)', color: '#FFFFFF', fontWeight: 600 }}>
          Active model blocks
        </div>
        {loading ? (
          <div style={{ padding: '24px', color: '#94A3B8' }}>Loading backend-confirmed state…</div>
        ) : blockedItems.filter(item => item.type === 'model').length === 0 ? (
          <div style={{ padding: '24px', color: '#94A3B8' }}>No active model blocks were returned by the backend.</div>
        ) : (
          blockedItems.filter(item => item.type === 'model').map(item => (
            <div key={item.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '16px', padding: '14px 18px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <div>
                <div style={{ color: '#FFFFFF', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>{item.id}</div>
                <div style={{ color: '#94A3B8', fontSize: '11px', marginTop: '4px' }}>{item.reason}</div>
                <div style={{ color: '#64748B', fontSize: '10px', marginTop: '4px' }}>Expires in {Math.max(0, item.expires_in_seconds)} seconds</div>
              </div>
              <button onClick={() => void handleUnblock(item)} disabled={busyId !== null} className="btn-ghost">
                {busyId === item.id ? 'Working…' : 'Unblock'}
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
