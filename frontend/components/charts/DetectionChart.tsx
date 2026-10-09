'use client'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend,
} from 'recharts'

// Mock 7-day data — replace with API data in production
const DATA = [
  { day: 'Mon', blocked: 12, alerted: 8,  passed: 243 },
  { day: 'Tue', blocked: 19, alerted: 14, passed: 381 },
  { day: 'Wed', blocked: 7,  alerted: 11, passed: 294 },
  { day: 'Thu', blocked: 23, alerted: 17, passed: 412 },
  { day: 'Fri', blocked: 31, alerted: 22, passed: 511 },
  { day: 'Sat', blocked: 9,  alerted: 6,  passed: 178 },
  { day: 'Sun', blocked: 14, alerted: 9,  passed: 267 },
]

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload) return null
  return (
    <div style={{
      background: '#0D1B2A', border: '1px solid rgba(0,212,255,0.2)',
      borderRadius: '8px', padding: '10px 14px',
      fontFamily: 'JetBrains Mono, monospace', fontSize: '11px',
    }}>
      <div style={{ color: '#94A3B8', marginBottom: '6px' }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} style={{ color: p.color, marginBottom: '2px' }}>
          {p.name}: {p.value}
        </div>
      ))}
    </div>
  )
}

export default function DetectionChart() {
  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={DATA} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
        <defs>
          <linearGradient id="blocked" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#EF4444" stopOpacity={0.3}/>
            <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="alerted" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#F59E0B" stopOpacity={0.25}/>
            <stop offset="95%" stopColor="#F59E0B" stopOpacity={0}/>
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
        <XAxis
          dataKey="day"
          tick={{ fill: '#475569', fontFamily: 'JetBrains Mono', fontSize: 10 }}
          axisLine={false} tickLine={false}
        />
        <YAxis
          tick={{ fill: '#475569', fontFamily: 'JetBrains Mono', fontSize: 10 }}
          axisLine={false} tickLine={false}
        />
        <Tooltip content={<CustomTooltip />} />
        <Area
          type="monotone" dataKey="blocked" name="Blocked"
          stroke="#EF4444" fill="url(#blocked)" strokeWidth={2}
        />
        <Area
          type="monotone" dataKey="alerted" name="Alerted"
          stroke="#F59E0B" fill="url(#alerted)" strokeWidth={2}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
