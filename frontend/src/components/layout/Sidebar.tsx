import React, { useState } from 'react'
import { NavLink } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LayoutDashboard, Shield, Activity,
  FileText, Clock, Radio, ChevronRight,
  ChevronLeft, Settings, User, Wifi
} from 'lucide-react'
import { useStream } from '@/contexts/StreamContext'

const NAV_ITEMS = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/detections', icon: Shield, label: 'Detections' },
  { to: '/stream', icon: Radio, label: 'Live Stream' },
  { to: '/timeline', icon: Clock, label: 'Timeline' },
  { to: '/reports', icon: FileText, label: 'Reports' },
]

const BOTTOM_ITEMS = [
  { to: '/profile', icon: User, label: 'Profile' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const { connected: streaming } = useStream()

  return (
    <motion.aside
      animate={{ width: collapsed ? 64 : 256 }}
      transition={{ duration: 0.3, ease: 'easeInOut' }}
      className="flex-shrink-0 flex flex-col border-r border-sentinel-border relative overflow-hidden"
      style={{ background: 'linear-gradient(180deg, #0d1526 0%, #060b18 100%)' }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-sentinel-border flex-shrink-0 overflow-hidden">
        <div className="relative h-9 w-9 min-w-[36px] rounded-lg flex items-center justify-center animate-pulse-glow"
          style={{ background: 'linear-gradient(135deg, #00d4ff22, #00d4ff44)', border: '1px solid #00d4ff55' }}>
          <Shield className="h-5 w-5 text-sentinel-cyan" />
        </div>
        <AnimatePresence>
          {!collapsed && (
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.2 }}
              className="overflow-hidden whitespace-nowrap"
            >
              <p className="text-sm font-bold text-white tracking-wide">ANBU</p>
              <p className="text-xs text-sentinel-cyan font-mono tracking-widest">SENTINEL</p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Toggle Button */}
      <button
        onClick={() => setCollapsed(c => !c)}
        className="absolute top-[62px] -right-3.5 z-10 h-7 w-7 rounded-full flex items-center justify-center
          border border-sentinel-border text-muted-foreground hover:text-sentinel-cyan hover:border-sentinel-cyan
          transition-all duration-200"
        style={{ background: '#0d1526' }}
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed
          ? <ChevronRight className="h-3.5 w-3.5" />
          : <ChevronLeft className="h-3.5 w-3.5" />
        }
      </button>

      {/* Nav */}
      <nav className="flex-1 px-2 py-4 space-y-1 overflow-hidden">
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} className={({ isActive }) =>
            `nav-link ${isActive ? 'active' : ''} ${collapsed ? 'justify-center px-0' : ''}`
          }
            title={collapsed ? label : undefined}
          >
            {({ isActive }) => (
              <>
                <span className="relative">
                  <Icon className={`h-4 w-4 flex-shrink-0 ${isActive ? 'text-sentinel-cyan' : ''}`} />
                  {/* Streaming pulse on Live Stream icon */}
                  {to === '/stream' && streaming && (
                    <span className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-sentinel-green animate-ping" />
                  )}
                </span>
                <AnimatePresence>
                  {!collapsed && (
                    <motion.span
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="flex-1 whitespace-nowrap overflow-hidden"
                    >{label}</motion.span>
                  )}
                </AnimatePresence>
                {!collapsed && streaming && to === '/stream' && (
                  <span className="text-xs font-mono text-sentinel-green bg-sentinel-green/10 px-1.5 py-0.5 rounded flex-shrink-0">
                    live
                  </span>
                )}
                {!collapsed && isActive && !streaming && <ChevronRight className="h-3 w-3 text-sentinel-cyan flex-shrink-0" />}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Bottom Nav */}
      <div className="px-2 pb-2 space-y-1 border-t border-sentinel-border pt-2">
        {BOTTOM_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} className={({ isActive }) =>
            `nav-link ${isActive ? 'active' : ''} ${collapsed ? 'justify-center px-0' : ''}`
          }
            title={collapsed ? label : undefined}
          >
            {({ isActive }) => (
              <>
                <Icon className={`h-4 w-4 flex-shrink-0 ${isActive ? 'text-sentinel-cyan' : ''}`} />
                <AnimatePresence>
                  {!collapsed && (
                    <motion.span
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="flex-1 whitespace-nowrap overflow-hidden"
                    >{label}</motion.span>
                  )}
                </AnimatePresence>
              </>
            )}
          </NavLink>
        ))}
      </div>

      {/* Status bar */}
      <div className="px-4 py-3 border-t border-sentinel-border">
        <div className={`flex items-center gap-2 text-xs text-muted-foreground ${collapsed ? 'justify-center' : ''}`}>
          <span className={`h-2 w-2 min-w-[8px] rounded-full animate-pulse ${streaming ? 'bg-yellow-400' : 'bg-sentinel-green'}`} />
          <AnimatePresence>
            {!collapsed && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="font-mono whitespace-nowrap"
              >{streaming ? 'Stream Active' : 'System Operational'}</motion.span>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.aside>
  )
}
