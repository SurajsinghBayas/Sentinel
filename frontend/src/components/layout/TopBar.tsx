import React from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Bell, LogOut, User, Settings } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { motion } from 'framer-motion'

export function TopBar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => { logout(); navigate('/login') }

  return (
    <header className="h-14 flex items-center justify-between px-6 border-b border-sentinel-border flex-shrink-0"
      style={{ background: 'rgba(13,21,38,0.8)', backdropFilter: 'blur(12px)' }}>
      <div className="flex items-center gap-2">
        <span className="text-xs font-mono text-slate-400">ANBU SENTINEL</span>
        <span className="text-slate-500">/</span>
        <span className="text-xs font-mono text-sentinel-cyan">v2.0.0</span>
      </div>

      <div className="flex items-center gap-3">
        <button className="relative p-2 rounded-lg hover:bg-sentinel-surface transition-colors">
          <Bell className="h-4 w-4 text-slate-400" />
          <span className="absolute top-1.5 right-1.5 h-1.5 w-1.5 rounded-full bg-sentinel-red animate-pulse" />
        </button>

        <Link to="/profile" className="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-sentinel-surface transition-colors"
          style={{ background: 'rgba(30,58,95,0.4)', border: '1px solid rgba(30,58,95,0.8)' }}>
          <div className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold text-sentinel-bg"
            style={{ background: 'linear-gradient(135deg, #00d4ff, #0099cc)' }}>
            {user?.avatar_initials || user?.name?.[0] || 'A'}
          </div>
          <div className="hidden sm:block">
            <p className="text-xs font-semibold text-white leading-tight">{user?.name}</p>
            <p className="text-xs text-slate-400 leading-tight capitalize">{user?.role}</p>
          </div>
        </Link>

        <Link to="/settings"
          className="p-2 rounded-lg text-slate-400 hover:text-sentinel-cyan hover:bg-sentinel-surface transition-colors">
          <Settings className="h-4 w-4" />
        </Link>

        <button onClick={handleLogout}
          className="p-2 rounded-lg text-slate-400 hover:text-sentinel-red hover:bg-red-500/10 transition-colors">
          <LogOut className="h-4 w-4" />
        </button>
      </div>
    </header>
  )
}
