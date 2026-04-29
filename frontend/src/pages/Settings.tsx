import React, { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Bell, Shield, Cpu, Globe, Sliders, ToggleLeft, ToggleRight,
  Save, AlertTriangle, Wifi, Volume2
} from 'lucide-react'
import { toast } from 'sonner'

interface ToggleProps {
  enabled: boolean
  onChange: (v: boolean) => void
}

function Toggle({ enabled, onChange }: ToggleProps) {
  return (
    <button onClick={() => onChange(!enabled)}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200 focus:outline-none
        ${enabled ? 'bg-sentinel-cyan' : 'bg-sentinel-surface border border-sentinel-border'}`}>
      <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform duration-200
        ${enabled ? 'translate-x-4' : 'translate-x-1'}`} />
    </button>
  )
}

export default function Settings() {
  const [settings, setSettings] = useState({
    realtimeAlerts: true,
    soundAlerts: false,
    emailNotify: true,
    autoNarrate: true,
    bedrockStreaming: true,
    darkMode: true,
    compactView: false,
    autoRefresh: true,
    refreshInterval: '30',
    aiModel: 'claude-3-5-sonnet',
    wsReconnect: true,
  })

  const set = (key: keyof typeof settings) => (val: boolean | string) =>
    setSettings(s => ({ ...s, [key]: val }))

  const handleSave = () => toast.success('Settings saved successfully')

  const sections = [
    {
      title: 'Notifications',
      icon: Bell,
      color: '#eab308',
      rows: [
        { key: 'realtimeAlerts', label: 'Real-time Threat Alerts', desc: 'Show popup alerts for new threats' },
        { key: 'soundAlerts', label: 'Sound Alerts', desc: 'Play audio when critical threat detected' },
        { key: 'emailNotify', label: 'Email Notifications', desc: 'Receive daily threat digest via email' },
      ],
    },
    {
      title: 'AI & Intelligence',
      icon: Cpu,
      color: '#a855f7',
      rows: [
        { key: 'autoNarrate', label: 'Auto-Narrate Threats', desc: 'Automatically generate AI narration for detected threats' },
        { key: 'bedrockStreaming', label: 'Bedrock Streaming', desc: 'Use streaming API for faster AI responses' },
      ],
    },
    {
      title: 'Log Streaming',
      icon: Wifi,
      color: '#00d4ff',
      rows: [
        { key: 'wsReconnect', label: 'Auto-Reconnect WebSocket', desc: 'Automatically reconnect if stream drops' },
        { key: 'autoRefresh', label: 'Auto-Refresh Dashboard', desc: 'Periodically refresh dashboard stats' },
      ],
    },
    {
      title: 'Interface',
      icon: Sliders,
      color: '#22c55e',
      rows: [
        { key: 'darkMode', label: 'Dark Mode', desc: 'Use dark cyber theme (recommended)' },
        { key: 'compactView', label: 'Compact View', desc: 'Reduce spacing for more data density' },
      ],
    },
  ]

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <p className="text-sm text-slate-400 mt-0.5">Configure your ANBU Sentinel experience</p>
        </div>
        <button onClick={handleSave} className="btn-primary">
          <Save className="h-4 w-4" /> Save Changes
        </button>
      </div>

      {/* AI Model Select */}
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
        className="glass-card p-5">
        <div className="flex items-center gap-2 mb-4">
          <div className="h-8 w-8 rounded-lg flex items-center justify-center"
            style={{ background: '#a855f718', border: '1px solid #a855f744' }}>
            <Cpu className="h-4 w-4 text-purple-400" />
          </div>
          <h3 className="text-sm font-semibold text-white">AI Model Configuration</h3>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-slate-400 mb-1.5 block">Bedrock Model</label>
            <select value={settings.aiModel} onChange={e => set('aiModel')(e.target.value)}
              className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-2 text-sm text-white
                focus:outline-none focus:border-sentinel-cyan">
              <option value="claude-3-5-sonnet">Claude 3.5 Sonnet (Recommended)</option>
              <option value="claude-3-haiku">Claude 3 Haiku (Faster)</option>
              <option value="claude-3-opus">Claude 3 Opus (Most Capable)</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-slate-400 mb-1.5 block">Refresh Interval</label>
            <select value={settings.refreshInterval} onChange={e => set('refreshInterval')(e.target.value)}
              className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-2 text-sm text-white
                focus:outline-none focus:border-sentinel-cyan">
              <option value="10">Every 10 seconds</option>
              <option value="30">Every 30 seconds</option>
              <option value="60">Every minute</option>
              <option value="300">Every 5 minutes</option>
            </select>
          </div>
        </div>
      </motion.div>

      {/* Toggle sections */}
      {sections.map((section, si) => (
        <motion.div key={section.title}
          initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: si * 0.06 }}
          className="glass-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <div className="h-8 w-8 rounded-lg flex items-center justify-center"
              style={{ background: `${section.color}18`, border: `1px solid ${section.color}44` }}>
              <section.icon className="h-4 w-4" style={{ color: section.color }} />
            </div>
            <h3 className="text-sm font-semibold text-white">{section.title}</h3>
          </div>
          <div className="space-y-3">
            {section.rows.map(row => (
              <div key={row.key} className="flex items-center justify-between py-2 border-b border-sentinel-border last:border-0">
                <div>
                  <p className="text-sm font-medium text-slate-200">{row.label}</p>
                  <p className="text-xs text-slate-500">{row.desc}</p>
                </div>
                <Toggle
                  enabled={settings[row.key as keyof typeof settings] as boolean}
                  onChange={val => set(row.key as keyof typeof settings)(val)}
                />
              </div>
            ))}
          </div>
        </motion.div>
      ))}

      {/* Danger Zone */}
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="glass-card p-5 border-sentinel-red/30">
        <div className="flex items-center gap-2 mb-4">
          <div className="h-8 w-8 rounded-lg flex items-center justify-center"
            style={{ background: '#f43f5e18', border: '1px solid #f43f5e44' }}>
            <AlertTriangle className="h-4 w-4 text-sentinel-red" />
          </div>
          <h3 className="text-sm font-semibold text-white">Danger Zone</h3>
        </div>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 rounded-lg"
            style={{ background: 'rgba(244,63,94,0.05)', border: '1px solid rgba(244,63,94,0.2)' }}>
            <div>
              <p className="text-sm font-medium text-slate-200">Clear All Detections</p>
              <p className="text-xs text-slate-500">Permanently delete all threat detection records</p>
            </div>
            <button className="btn-danger text-xs py-1.5 px-3">Clear</button>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg"
            style={{ background: 'rgba(244,63,94,0.05)', border: '1px solid rgba(244,63,94,0.2)' }}>
            <div>
              <p className="text-sm font-medium text-slate-200">Reset to Defaults</p>
              <p className="text-xs text-slate-500">Restore all settings to factory defaults</p>
            </div>
            <button className="btn-danger text-xs py-1.5 px-3">Reset</button>
          </div>
        </div>
      </motion.div>
    </div>
  )
}
