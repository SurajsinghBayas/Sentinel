import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'sonner'
import { AuthProvider } from '@/hooks/useAuth'
import { AppLayout } from '@/components/layout/AppLayout'
import Landing from '@/pages/Landing'
import Login from '@/pages/Login'
import Signup from '@/pages/Signup'
import Dashboard from '@/pages/Dashboard'
import LogStream from '@/pages/LogStream'
import LogUpload from '@/pages/LogUpload'
import Detections from '@/pages/Detections'
import Timeline from '@/pages/Timeline'
import Reports from '@/pages/Reports'
import Profile from '@/pages/Profile'
import Settings from '@/pages/Settings'

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Toaster
          theme="dark"
          position="top-right"
          toastOptions={{
            style: {
              background: '#0d1526',
              border: '1px solid #1e3a5f',
              color: '#e2e8f0',
              fontFamily: 'Inter, sans-serif',
            },
          }}
        />
        <Routes>
          {/* Public routes */}
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />

          {/* Protected routes */}
          <Route path="/dashboard" element={<AppLayout><Dashboard /></AppLayout>} />
          <Route path="/stream" element={<AppLayout><LogStream /></AppLayout>} />
          <Route path="/upload" element={<AppLayout><LogUpload /></AppLayout>} />
          <Route path="/detections" element={<AppLayout><Detections /></AppLayout>} />
          <Route path="/timeline" element={<AppLayout><Timeline /></AppLayout>} />
          <Route path="/reports" element={<AppLayout><Reports /></AppLayout>} />
          <Route path="/profile" element={<AppLayout><Profile /></AppLayout>} />
          <Route path="/settings" element={<AppLayout><Settings /></AppLayout>} />

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
