import React, { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Clock, Shield, AlertTriangle } from 'lucide-react'
import api from '@/lib/api'
import { ATTACK_TYPE_LABELS, SEVERITY_COLORS } from '@/lib/utils'

const SEVERITY_ICONS: Record<string, any> = {
  CRITICAL: { icon: Shield, color: '#f43f5e' },
  HIGH: { icon: AlertTriangle, color: '#ff6b35' },
  MEDIUM: { icon: AlertTriangle, color: '#eab308' },
  LOW: { icon: Clock, color: '#22c55e' },
}

export default function Timeline() {
  const [threats, setThreats] = useState<any[]>([])
  useEffect(() => { api.get('/detections', { params: { limit: 50 } }).then(r => setThreats(r.data.threats || [])) }, [])

  const sorted = [...threats].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Attack Timeline</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Chronological view of all detected threats</p>
      </div>

      {sorted.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <Clock className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground">No events yet. Upload a log file to populate the timeline.</p>
        </div>
      ) : (
        <div className="relative">
          <div className="absolute left-6 top-0 bottom-0 w-px bg-sentinel-border" />
          <div className="space-y-4">
            {sorted.map((t, i) => {
              const cfg = SEVERITY_ICONS[t.severity] || SEVERITY_ICONS.LOW
              const Icon = cfg.icon
              return (
                <motion.div key={t.id} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}
                  className="relative flex items-start gap-4 pl-12">
                  <div className="absolute left-3.5 -translate-x-1/2 h-5 w-5 rounded-full flex items-center justify-center z-10"
                    style={{ background: `${cfg.color}22`, border: `2px solid ${cfg.color}` }}>
                    <Icon className="h-2.5 w-2.5" style={{ color: cfg.color }} />
                  </div>
                  <div className="glass-card-hover p-4 flex-1">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <span className={`badge-${t.severity?.toLowerCase()}`}>{t.severity}</span>
                        <h3 className="text-sm font-semibold text-foreground mt-1">{ATTACK_TYPE_LABELS[t.attack_type] || t.attack_type}</h3>
                        <p className="text-xs text-muted-foreground font-mono">{t.source_ip}</p>
                      </div>
                      <p className="text-xs text-muted-foreground font-mono flex-shrink-0">
                        {new Date(t.timestamp).toLocaleString()}
                      </p>
                    </div>
                    {t.evidence?.length > 0 && (
                      <p className="text-xs text-muted-foreground mt-2 border-t border-sentinel-border pt-2">{t.evidence[0]}</p>
                    )}
                  </div>
                </motion.div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
