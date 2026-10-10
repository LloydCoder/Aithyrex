import type { Metadata } from 'next'
import { ClerkProvider } from '@clerk/nextjs'
import '@/styles/globals.css'

export const metadata: Metadata = {
  title: 'Aithyrex — Runtime AI Security',
  description: 'Aithyrex is Tinlance’s engineering project for AI interaction threat detection.',
  icons: { icon: '/favicon.ico' },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <ClerkProvider>
      <html lang="en">
        <body>
          <div className="grid-bg" />
          {children}
        </body>
      </html>
    </ClerkProvider>
  )
}
