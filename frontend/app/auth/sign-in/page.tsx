'use client'
import { SignIn } from '@clerk/nextjs'

export default function SignInPage() {
  return (
    <div style={{
      minHeight: '100vh', display: 'flex',
      flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', padding: '24px',
    }}>
      {/* Logo */}
      <div style={{ marginBottom: '32px', textAlign: 'center' }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: '10px',
          justifyContent: 'center', marginBottom: '8px',
        }}>
          <svg width="32" height="32" viewBox="0 0 28 28" fill="none">
            <path d="M14 2L4 7V14C4 19.5 8.5 24.5 14 26C19.5 24.5 24 19.5 24 14V7L14 2Z"
              fill="rgba(0,212,255,0.12)" stroke="#00D4FF" strokeWidth="1.5"/>
            <path d="M10 14L13 17L18 11" stroke="#00D4FF" strokeWidth="1.5"
              strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <span style={{
            fontFamily: 'Space Grotesk, sans-serif',
            fontWeight: 700, fontSize: '22px', color: '#FFFFFF',
          }}>Aithyrex</span>
        </div>
        <p style={{
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '11px', color: '#475569',
          letterSpacing: '0.08em', textTransform: 'uppercase',
        }}>Agentic AI Runtime Security</p>
      </div>

      <SignIn
        appearance={{
          variables: {
            colorBackground: '#0D1B2A',
            colorText: '#E2E8F0',
            colorPrimary: '#00D4FF',
            colorInputBackground: '#060A14',
            colorInputText: '#FFFFFF',
            borderRadius: '8px',
            fontFamily: 'Inter, sans-serif',
          },
          elements: {
            card: { border: '1px solid rgba(0,212,255,0.15)', boxShadow: 'none' },
            headerTitle: { fontFamily: 'Space Grotesk, sans-serif', color: '#FFFFFF' },
          },
        }}
        redirectUrl="/dashboard"
      />
    </div>
  )
}
