import React from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/hooks/useAuth'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { Loader2 } from 'lucide-react'

export function AppLayout({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth()
  const location = useLocation()

  if (isLoading) return (
    <div className="flex h-screen items-center justify-center bg-sentinel-bg">
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="h-8 w-8 animate-spin text-sentinel-cyan" />
        <span className="text-sm text-muted-foreground font-mono">Authenticating...</span>
      </div>
    </div>
  )

  if (!user) return <Navigate to="/login" state={{ from: location }} replace />

  return (
    <div className="flex h-screen overflow-hidden bg-sentinel-bg cyber-grid">
      <Sidebar />
      <div className="flex flex-col flex-1 overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
