import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { User, Mail, Shield, Key, Camera, CheckCircle, Edit2, Save, X } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { toast } from 'sonner'

export default function Profile() {
  const { user } = useAuth()
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState({
    name: user?.name || '',
    email: user?.email || '',
  })

  const handleSave = () => {
    toast.success('Profile updated successfully')
    setEditing(false)
  }

  const stats = [
    { label: 'Threats Analyzed', value: '1,284', icon: Shield, color: '#f43f5e' },
    { label: 'Reports Generated', value: '47', icon: CheckCircle, color: '#22c55e' },
    { label: 'Sessions', value: '312', icon: Key, color: '#00d4ff' },
  ]

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Profile</h1>
        <p className="text-sm text-slate-400 mt-0.5">Manage your account details and preferences</p>
      </div>

      {/* Profile Card */}
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
        className="glass-card p-6">
        <div className="flex items-start gap-6">
          {/* Avatar */}
          <div className="relative flex-shrink-0">
            <div className="h-20 w-20 rounded-2xl flex items-center justify-center text-2xl font-bold text-sentinel-bg"
              style={{ background: 'linear-gradient(135deg, #00d4ff, #0099cc)' }}>
              {user?.avatar_initials || user?.name?.[0] || 'A'}
            </div>
            <button className="absolute -bottom-2 -right-2 h-7 w-7 rounded-full bg-sentinel-surface border border-sentinel-border
              flex items-center justify-center text-slate-400 hover:text-sentinel-cyan transition-colors">
              <Camera className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* Info */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-bold text-white">{user?.name}</h2>
                <p className="text-sm text-slate-400">{user?.email}</p>
              </div>
              {!editing ? (
                <button onClick={() => setEditing(true)}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm text-slate-300 hover:text-sentinel-cyan
                    border border-sentinel-border hover:border-sentinel-cyan transition-all">
                  <Edit2 className="h-3.5 w-3.5" /> Edit
                </button>
              ) : (
                <div className="flex gap-2">
                  <button onClick={handleSave} className="btn-primary text-xs px-3 py-1.5">
                    <Save className="h-3.5 w-3.5" /> Save
                  </button>
                  <button onClick={() => setEditing(false)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-400
                      border border-sentinel-border hover:text-slate-300 transition-colors">
                    <X className="h-3.5 w-3.5" /> Cancel
                  </button>
                </div>
              )}
            </div>

            {editing ? (
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-slate-400 mb-1 block">Display Name</label>
                  <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-2 text-sm text-white
                      focus:outline-none focus:border-sentinel-cyan transition-colors" />
                </div>
                <div>
                  <label className="text-xs text-slate-400 mb-1 block">Email Address</label>
                  <input value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
                    className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-2 text-sm text-white
                      focus:outline-none focus:border-sentinel-cyan transition-colors" />
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm">
                  <User className="h-3.5 w-3.5 text-slate-500" />
                  <span className="text-slate-300">{user?.name}</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <Mail className="h-3.5 w-3.5 text-slate-500" />
                  <span className="text-slate-300">{user?.email}</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <Shield className="h-3.5 w-3.5 text-sentinel-cyan" />
                  <span className="text-sentinel-cyan capitalize font-medium">{user?.role || 'analyst'}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </motion.div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {stats.map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.07 }} className="glass-card p-4 text-center">
            <div className="h-10 w-10 rounded-xl flex items-center justify-center mx-auto mb-3"
              style={{ background: `${s.color}18`, border: `1px solid ${s.color}44` }}>
              <s.icon className="h-5 w-5" style={{ color: s.color }} />
            </div>
            <p className="text-2xl font-bold text-white font-mono">{s.value}</p>
            <p className="text-xs text-slate-400 mt-1">{s.label}</p>
          </motion.div>
        ))}
      </div>

      {/* Security Section */}
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
        className="glass-card p-6">
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Key className="h-4 w-4 text-sentinel-cyan" /> Security
        </h3>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 rounded-lg"
            style={{ background: 'rgba(30,58,95,0.3)', border: '1px solid rgba(30,58,95,0.5)' }}>
            <div>
              <p className="text-sm font-medium text-white">Password</p>
              <p className="text-xs text-slate-400">Last changed 30 days ago</p>
            </div>
            <button className="text-xs text-sentinel-cyan hover:underline">Change</button>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg"
            style={{ background: 'rgba(30,58,95,0.3)', border: '1px solid rgba(30,58,95,0.5)' }}>
            <div>
              <p className="text-sm font-medium text-white">Two-Factor Auth</p>
              <p className="text-xs text-slate-400">Add an extra layer of security</p>
            </div>
            <button className="text-xs px-3 py-1 rounded-full bg-sentinel-cyan/10 text-sentinel-cyan border border-sentinel-cyan/30">
              Enable
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  )
}
