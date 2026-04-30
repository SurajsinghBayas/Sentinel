import React, { useEffect, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Clock, Shield, AlertTriangle, RefreshCw, Radio } from 'lucide-react'
import api from '@/lib/api'
import { ATTACK_TYPE_LABELS, SEVERITY_COLORS } from '@/lib/utils'
import { useStreamRefresh, useThreatDetected, useStream } from '@/contexts/StreamContext'

const SEVERITY_CFG: Record<string, { color: string; icon: any }> = {
  CRITICAL: { color: '#f43f5e', icon: Shield },
  HIGH:     { color: '#ff6b35', icon: AlertTriangle },
  MEDIUM:   { color: '#eab308', icon: AlertTriangle },
  LOW:      { color: '#22c55e', icon: Clock },
}

export default function Timeline() {
  const [threats, setThreats]       = useState<any[]>([])
  const [loading, setLoading]       = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const { connected: streaming }    = useStream()

  const fetchThreats = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    else setRefreshing(true)
    try {
      const r = await api.get('/detections', { params: { limit: 100 } })
      setThreats(r.data.threats || [])
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  // Initial load
  useEffect(() => { fetchThreats() }, [fetchThreats])

  // Full refresh when stream finishes (fires even if page mounted after stream)
  useStreamRefresh(() => { fetchThreats(true) })

  // Live-append threats one by one as they arrive during streaming
  useThreatDetected((payload: Record<string, unknown>) => {
    setThreats(prev => {
      if (prev.some((t: any) => t.id === payload.id)) return prev
      return [...prev, payload as any]
    })
  })

  // Sort chronologically for the timeline
  const sorted = [...threats].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  )

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Attack Timeline</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Chronological view of all detected threats
            {streaming && <span className="ml-2 text-sentinel-green font-mono">● Live</span>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {streaming && (
            <span className="flex items-center gap-1.5 text-xs font-mono bg-sentinel-green/10 border border-sentinel-green/30 text-sentinel-green px-2 py-1 rounded-full">
              <Radio className="h-3 w-3 animate-pulse" /> Updating live
            </span>
          )}
          {refreshing
            ? <RefreshCw className="h-4 w-4 text-sentinel-cyan animate-spin" />
            : <button onClick={() => fetchThreats(true)} title="Refresh"
                className="text-slate-400 hover:text-sentinel-cyan transition-colors p-1">
                <RefreshCw className="h-4 w-4" />
              </button>
          }
          <span className="text-xs font-mono text-slate-400">{sorted.length} events</span>
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-20">
          <RefreshCw className="h-6 w-6 text-sentinel-cyan animate-spin" />
        </div>
      ) : sorted.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <Clock className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground">No events yet. Start a live stream to populate the timeline.</p>
        </div>
      ) : (
        <div className="relative">
          {/* Vertical spine */}
          <div className="absolute left-6 top-0 bottom-0 w-px bg-sentinel-border" />
          <div className="space-y-4">
            <AnimatePresence initial={false}>
              {sorted.map((t, i) => {
                const cfg = SEVERITY_CFG[t.severity] || SEVERITY_CFG.LOW
                const Icon = cfg.icon
                return (
                  <motion.div key={t.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.3 }}
                    className="relative flex items-start gap-4 pl-12"
                  >
                    {/* Spine dot */}
                    <div
                      className="absolute left-3.5 -translate-x-1/2 h-5 w-5 rounded-full flex items-center justify-center z-10"
                      style={{ background: `${cfg.color}22`, border: `2px solid ${cfg.color}` }}
                    >
                      <Icon className="h-2.5 w-2.5" style={{ color: cfg.color }} />
                    </div>

                    <div className="glass-card-hover p-4 flex-1">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <span className={`badge-${t.severity?.toLowerCase()}`}>{t.severity}</span>
                          <h3 className="text-sm font-semibold text-foreground mt-1">
                            {ATTACK_TYPE_LABELS[t.attack_type] || t.attack_type}
                          </h3>
                          <p className="text-xs text-muted-foreground font-mono">{t.source_ip}</p>
                        </div>
                        <div className="text-right flex-shrink-0">
                          <p className="text-xs text-muted-foreground font-mono">
                            {new Date(t.timestamp).toLocaleTimeString()}
                          </p>
                          <p className="text-xs text-slate-500 font-mono">
                            {new Date(t.timestamp).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                      {t.evidence?.length > 0 && (
                        <p className="text-xs text-muted-foreground mt-2 border-t border-sentinel-border pt-2 font-mono">
                          {t.evidence[0]}
                        </p>
                      )}
                      {t.request_count && (
                        <div className="flex items-center gap-3 mt-2 text-xs text-slate-500">
                          <span>{t.request_count} requests</span>
                          {t.confidence && <span>{Math.round(t.confidence * 100)}% confidence</span>}
                          {t.rule_name && <span className="font-mono">{t.rule_name}</span>}
                        </div>
                      )}
                    </div>
                  </motion.div>
                )
              })}
            </AnimatePresence>
          </div>
        </div>
      )}
    </div>
  )
}
