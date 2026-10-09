'use client'
import { useState } from 'react'

const BUILT_IN_RULES = [
  { id: 'PI-D-001', name: 'System Prompt Override',    severity: 'high',     active: true,  type: 'built-in' },
  { id: 'PI-D-002', name: 'Persona Hijack',            severity: 'high',     active: true,  type: 'built-in' },
  { id: 'PI-D-003', name: 'Jailbreak Attempt',         severity: 'critical', active: true,  type: 'built-in' },
  { id: 'PI-D-004', name: 'System Tag Injection',      severity: 'high',     active: true,  type: 'built-in' },
  { id: 'PI-I-001', name: 'Hidden Instruction in Doc', severity: 'critical', active: true,  type: 'built-in' },
  { id: 'PI-I-002', name: 'Zero-width Steganography',  severity: 'high',     active: true,  type: 'built-in' },
  { id: 'CRED-AI-001', name: 'Anthropic API Key',      severity: 'critical', active: true,  type: 'built-in' },
  { id: 'CRED-NG-001', name: 'Paystack Secret Key',    severity: 'critical', active: true,  type: 'built-in' },
  { id: 'CRED-NG-003', name: 'Flutterwave Secret Key', severity: 'critical', active: true,  type: 'built-in' },
]

const severityColor: Record<string, string> = {
  critical: '#EF4444', high: '#F59E0B', medium: '#8B5CF6',
}

export default function RulesPage() {
  const [rules, setRules] = useState(BUILT_IN_RULES)
  const [customRule, setCustomRule] = useState({ name: '', pattern: '', severity: 'medium' })
  const [adding, setAdding] = useState(false)

  const toggle = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, active: !r.active } : r))
  }

  const addRule = () => {
    if (!customRule.name || !customRule.pattern) return
    setRules(prev => [...prev, {
      id: `CUSTOM-${Date.now()}`,
      name: customRule.name,
      severity: customRule.severity,
      active: true,
      type: 'custom',
    }])
    setCustomRule({ name: '', pattern: '', severity: 'medium' })
    setAdding(false)
  }

  return (
    <div style={{ maxWidth: '900px' }}>
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <div style={{
            fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
            color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px',
          }}>// Detection Rules</div>
          <h1 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '22px', fontWeight: 700, color: '#FFFFFF' }}>
            Detection Rules
          </h1>
        </div>
        <button onClick={() => setAdding(true)} className="btn-primary">
          + Add Custom Rule
        </button>
      </div>

      {adding && (
        <div className="shield-card" style={{ padding: '18px', marginBottom: '16px', borderColor: 'rgba(0,212,255,0.2)' }}>
          <div style={{
            fontFamily: 'Space Grotesk, sans-serif', fontSize: '13px',
            fontWeight: 600, color: '#FFFFFF', marginBottom: '12px',
          }}>New Custom Rule</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 120px', gap: '10px', marginBottom: '10px' }}>
            <input
              placeholder="Rule name"
              value={customRule.name}
              onChange={e => setCustomRule(p => ({ ...p, name: e.target.value }))}
              style={{
                background: '#080F1A', border: '1px solid rgba(0,212,255,0.15)',
                borderRadius: '6px', padding: '8px 12px', color: '#E2E8F0',
                fontSize: '12px', fontFamily: 'JetBrains Mono, monospace', outline: 'none',
              }}
            />
            <input
              placeholder="Regex pattern"
              value={customRule.pattern}
              onChange={e => setCustomRule(p => ({ ...p, pattern: e.target.value }))}
              style={{
                background: '#080F1A', border: '1px solid rgba(0,212,255,0.15)',
                borderRadius: '6px', padding: '8px 12px', color: '#E2E8F0',
                fontSize: '12px', fontFamily: 'JetBrains Mono, monospace', outline: 'none',
              }}
            />
            <select
              value={customRule.severity}
              onChange={e => setCustomRule(p => ({ ...p, severity: e.target.value }))}
              style={{
                background: '#080F1A', border: '1px solid rgba(0,212,255,0.15)',
                borderRadius: '6px', padding: '8px 12px', color: '#E2E8F0',
                fontSize: '12px', fontFamily: 'JetBrains Mono, monospace', outline: 'none',
              }}
            >
              <option value="medium">MEDIUM</option>
              <option value="high">HIGH</option>
              <option value="critical">CRITICAL</option>
            </select>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button onClick={addRule} className="btn-primary" style={{ fontSize: '12px', padding: '7px 16px' }}>Save Rule</button>
            <button onClick={() => setAdding(false)} className="btn-ghost" style={{ fontSize: '12px', padding: '7px 16px' }}>Cancel</button>
          </div>
        </div>
      )}

      <div className="shield-card" style={{ overflow: 'hidden' }}>
        <div style={{
          display: 'grid', gridTemplateColumns: '90px 1fr 90px 80px 70px',
          padding: '10px 18px',
          background: '#080F1A', borderBottom: '1px solid rgba(255,255,255,0.06)',
          fontFamily: 'JetBrains Mono, monospace', fontSize: '9px',
          color: '#475569', letterSpacing: '0.08em', textTransform: 'uppercase', gap: '12px',
        }}>
          <span>ID</span><span>RULE NAME</span><span>SEVERITY</span><span>TYPE</span><span>ACTIVE</span>
        </div>

        {rules.map((rule, i) => (
          <div key={rule.id} style={{
            display: 'grid', gridTemplateColumns: '90px 1fr 90px 80px 70px',
            padding: '12px 18px', gap: '12px',
            borderBottom: i < rules.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
            alignItems: 'center',
            opacity: rule.active ? 1 : 0.45,
          }}>
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: '#475569' }}>
              {rule.id}
            </span>
            <span style={{ fontFamily: 'Inter, sans-serif', fontSize: '13px', color: '#E2E8F0' }}>
              {rule.name}
            </span>
            <span className={`chip chip-${rule.severity}`}>{rule.severity.toUpperCase()}</span>
            <span style={{
              fontFamily: 'JetBrains Mono, monospace', fontSize: '10px',
              color: rule.type === 'custom' ? '#00D4FF' : '#475569',
            }}>{rule.type}</span>
            <button
              onClick={() => toggle(rule.id)}
              style={{
                width: '38px', height: '20px', borderRadius: '10px',
                background: rule.active ? 'rgba(0,212,255,0.2)' : 'rgba(255,255,255,0.08)',
                border: `1px solid ${rule.active ? 'rgba(0,212,255,0.4)' : 'rgba(255,255,255,0.1)'}`,
                cursor: 'pointer', position: 'relative', transition: 'all 0.2s',
              }}
            >
              <span style={{
                position: 'absolute', top: '2px',
                left: rule.active ? '18px' : '2px',
                width: '14px', height: '14px', borderRadius: '50%',
                background: rule.active ? '#00D4FF' : '#475569',
                transition: 'left 0.2s',
              }} />
            </button>
          </div>
        ))}
      </div>

      <p style={{
        marginTop: '12px', fontSize: '11px', color: '#475569',
        fontFamily: 'JetBrains Mono, monospace',
      }}>
        {rules.filter(r => r.active).length} rules active · {rules.filter(r => r.type === 'custom').length} custom rules
        · Custom rules require Pro plan
      </p>
    </div>
  )
}
