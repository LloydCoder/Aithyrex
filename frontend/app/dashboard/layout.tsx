import { OrganizationSwitcher } from '@clerk/nextjs'
import { auth } from '@clerk/nextjs/server'
import { redirect } from 'next/navigation'
import Sidebar from '@/components/ui/Sidebar'
import Topbar from '@/components/ui/Topbar'

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { userId, orgId } = await auth()

  if (!userId) redirect('/auth/sign-in')

  if (!orgId) {
    return (
      <main style={{
        minHeight: '100vh', display: 'grid', placeItems: 'center',
        background: '#0B0F19', color: '#FFFFFF', padding: '24px',
      }}>
        <section style={{
          width: 'min(520px, 100%)', padding: '28px',
          border: '1px solid rgba(255,255,255,0.12)', borderRadius: '12px',
          background: '#111827',
        }}>
          <h1 style={{ fontSize: '20px', fontWeight: 700 }}>Select an organization</h1>
          <p style={{ color: '#94A3B8', fontSize: '13px', marginTop: '10px', marginBottom: '20px' }}>
            Aithyrex API access is tenant-scoped. Choose an organization to continue. If it has not been provisioned in Aithyrex, contact your administrator.
          </p>
          <OrganizationSwitcher
            afterSelectOrganizationUrl="/dashboard"
            afterCreateOrganizationUrl="/dashboard"
            hidePersonal
          />
        </section>
      </main>
    )
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#0B0F19' }}>
      <Sidebar />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <Topbar />
        <main style={{ flex: 1, padding: '28px 32px', overflowY: 'auto' }}>
          {children}
        </main>
      </div>
    </div>
  )
}
