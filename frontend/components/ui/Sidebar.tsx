'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { UserButton } from '@clerk/nextjs'

const NAV = [
  { href: '/dashboard',         label: 'Overview',     icon: '⬡' },
  { href: '/dashboard/alerts',  label: 'Alerts',       icon: '◈', badge: 'LIVE' },
  { href: '/dashboard/models',  label: 'Models',       icon: '◎' },
  { href: '/dashboard/rules',   label: 'Rules',        icon: '◧' },
  { href: '/dashboard/reports', label: 'Reports',      icon: '◫' },
  { href: '/dashboard/billing', label: 'Billing',      icon: '◉' },
]

export default function Sidebar() {
  const path = usePathname()

  return (
    <aside style={{
      width: '220px', flexShrink: 0,
      background: '#080F1A',
      borderRight: '1px solid rgba(255,255,255,0.06)',
      display: 'flex', flexDirection: 'column',
      padding: '0',
    }}>
      {/* Logo */}
      <div style={{
        padding: '20px 20px 16px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <svg width="24" height="24" viewBox="0 0 28 28" fill="none">
            <path d="M14 2L4 7V14C4 19.5 8.5 24.5 14 26C19.5 24.5 24 19.5 24 14V7L14 2Z"
              fill="rgba(0,212,255,0.12)" stroke="#00D4FF" strokeWidth="1.5"/>
            <path d="M10 14L13 17L18 11" stroke="#00D4FF" strokeWidth="1.5"
              strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <span style={{
            fontFamily: 'Space Grotesk, sans-serif',
            fontWeight: 700, fontSize: '16px', color: '#FFFFFF',
          }}>AI Shield</span>
        </div>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '9px', color: '#475569',
          letterSpacing: '0.1em', marginTop: '4px',
          textTransform: 'uppercase',
        }}>v0.1.0 · Tinlance</div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '12px 10px' }}>
        {NAV.map(item => {
          const active = path === item.href ||
            (item.href !== '/dashboard' && path.startsWith(item.href))
          return (
            <Link key={item.href} href={item.href} style={{ textDecoration: 'none' }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: '10px',
                padding: '8px 10px', borderRadius: '7px',
                marginBottom: '2px',
                background: active ? 'rgba(0,212,255,0.08)' : 'transparent',
                border: active ? '1px solid rgba(0,212,255,0.15)' : '1px solid transparent',
                color: active ? '#00D4FF' : '#94A3B8',
                transition: 'all 0.15s',
                cursor: 'pointer',
              }}>
                <span style={{ fontSize: '14px', width: '18px', textAlign: 'center' }}>
                  {item.icon}
                </span>
                <span style={{
                  fontFamily: 'Inter, sans-serif',
                  fontSize: '13px', fontWeight: active ? 600 : 400,
                  flex: 1,
                }}>{item.label}</span>
                {item.badge && (
                  <span style={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '9px', padding: '1px 5px',
                    background: 'rgba(239,68,68,0.15)',
                    color: '#EF4444', borderRadius: '3px',
                    border: '1px solid rgba(239,68,68,0.25)',
                  }}>{item.badge}</span>
                )}
              </div>
            </Link>
          )
        })}
      </nav>

      {/* User */}
      <div style={{
        padding: '14px 16px',
        borderTop: '1px solid rgba(255,255,255,0.06)',
        display: 'flex', alignItems: 'center', gap: '10px',
      }}>
        <UserButton afterSignOutUrl="/auth/sign-in" />
        <div>
          <div style={{ fontSize: '12px', color: '#E2E8F0', fontWeight: 500 }}>
            Account
          </div>
          <div style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '10px', color: '#475569',
          }}>Pro plan</div>
        </div>
      </div>
    </aside>
  )
}
