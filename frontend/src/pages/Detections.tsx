import React, { useEffect, useState, useCallback } from 'react'
import { toast } from 'sonner'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, ChevronDown, ChevronUp, Loader2, Zap, RefreshCw, Bell, AlertCircle } from 'lucide-react'
import api from '@/lib/api'
import { ATTACK_TYPE_LABELS, SEVERITY_COLORS, formatRelativeTime } from '@/lib/utils'
import { useStreamRefresh, useThreatDetected, useStream } from '@/contexts/StreamContext'

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function Detections() {
  const [threats, setThreats]       = useState<any[]>([])
  const [loading, setLoading]       = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError]           = useState<string | null>(null)
  const [filter, setFilter]         = useState('ALL')
  const [expanded, setExpanded]     = useState<string | null>(null)
  const [narrating, setNarrating]   = useState<string | null>(null)
  const [narrations, setNarrations] = useState<Record<string, any>>({})
  const [newCount, setNewCount]     = useState(0)
  const { connected: streaming }    = useStream()

  const fetchThreats = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const params: any = { limit: 200 }
      if (filter !== 'ALL') params.severity = filter
      const r = await api.get('/detections', { params })
      const list = r.data.threats || []
      setThreats(list)
      setNewCount(0)
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err.message || 'Failed to load threats'
      setError(msg)
      console.error('[Detections] fetchThreats error:', err)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [filter])

  // Initial load + re-fetch when filter changes
  useEffect(() => { fetchThreats() }, [fetchThreats])

  // Re-fetch when stream finishes
  useStreamRefresh(() => {
    fetchThreats(true)
    toast.success('Stream complete — threat detections updated')
  })

  // Live-append each detected threat as it arrives during streaming
  useThreatDetected((payload: Record<string, unknown>) => {
    const sev = (payload.severity as string || '').toUpperCase()
    if (filter !== 'ALL' && sev !== filter) return
    setThreats(prev => {
      if (prev.some((t: any) => t.id === payload.id)) return prev
      setNewCount(n => n + 1)
      return [payload as any, ...prev]
    })
  })

  const handleNarrate = async (threatId: string) => {
    if (narrations[threatId]) return
    setNarrating(threatId)
    try {
      const { data } = await api.post(`/logs/narrate/${threatId}`)
      setNarrations(prev => ({ ...prev, [threatId]: data.narration }))
      toast.success('AI narration generated')
    } catch (err: any) {
      toast.error('Narration failed: ' + (err?.response?.data?.detail || err.message))
    } finally {
      setNarrating(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Detections</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            {threats.length} threats detected
            {streaming && <span className="ml-2 text-sentinel-green">● Live</span>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {newCount > 0 && (
            <button onClick={() => fetchThreats(true)}
              className="flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-semibold bg-sentinel-red/10 border border-sentinel-red/30 text-sentinel-red animate-pulse">
              <Bell className="h-3 w-3" /> {newCount} new
            </button>
          )}
          {refreshing
            ? <RefreshCw className="h-4 w-4 text-sentinel-cyan animate-spin" />
            : <button onClick={() => fetchThreats(true)} title="Refresh"
                className="text-slate-400 hover:text-sentinel-cyan transition-colors p-1">
                <RefreshCw className="h-4 w-4" />
              </button>
          }
          <div className="flex gap-1.5">
            {SEVERITIES.map(s => (
              <button key={s} onClick={() => setFilter(s)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${filter === s
                  ? 'bg-sentinel-cyan text-sentinel-bg'
                  : 'text-muted-foreground hover:text-foreground border border-sentinel-border'}`}>
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="glass-card p-4 border border-sentinel-red/30 flex items-center gap-3">
          <AlertCircle className="h-5 w-5 text-sentinel-red flex-shrink-0" />
          <div className="flex-1">
            <p className="text-sm text-sentinel-red font-semibold">Failed to load detections</p>
            <p className="text-xs text-slate-400 mt-0.5">{error}</p>
          </div>
          <button onClick={() => fetchThreats()} className="text-xs text-sentinel-cyan hover:underline">Retry</button>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center h-40"><Loader2 className="h-6 w-6 animate-spin text-sentinel-cyan" /></div>
      ) : threats.length === 0 && !error ? (
        <div className="glass-card p-12 text-center">
          <Shield className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground">No threats detected yet. Start a live stream to begin analysis.</p>
        </div>
      ) : (
        <div className="space-y-3">
          <AnimatePresence initial={false}>
            {threats.map((t, i) => (
              <motion.div key={t.id}
                initial={{ opacity: 0, x: -20, height: 0 }}
                animate={{ opacity: 1, x: 0, height: 'auto' }}
                transition={{ delay: i < 5 ? i * 0.04 : 0 }}
                className="glass-card overflow-hidden">
                <button className="w-full flex items-center gap-4 p-4 text-left hover:bg-white/[0.02] transition-colors"
                  onClick={() => { setExpanded(expanded === t.id ? null : t.id); if (expanded !== t.id) handleNarrate(t.id) }}>
                  <span className={`badge-${t.severity?.toLowerCase()}`}>{t.severity}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-white">{ATTACK_TYPE_LABELS[t.attack_type] || t.attack_type}</p>
                    <p className="text-xs text-slate-400 font-mono truncate">{t.source_ip} — {t.rule_name}</p>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <p className="text-xs text-slate-300">{Math.round(t.confidence * 100)}% conf</p>
                    <p className="text-xs text-slate-400">{formatRelativeTime(t.timestamp)}</p>
                  </div>
                  {expanded === t.id ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </button>

                {expanded === t.id && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
                    className="border-t border-sentinel-border px-4 pb-4 pt-3 space-y-3">
                    {/* Evidence */}
                    <div>
                      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Evidence</p>
                      {(t.evidence || []).map((e: string, i: number) => (
                        <p key={i} className="text-xs text-foreground font-mono bg-sentinel-surface px-2 py-1 rounded">{e}</p>
                      ))}
                    </div>
                    {/* AI Narration */}
                    <div>
                      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                        <Zap className="h-3 w-3 text-sentinel-purple" /> AI Narration
                      </p>
                      {narrating === t.id ? (
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                          <Loader2 className="h-3 w-3 animate-spin text-sentinel-cyan" /> Generating AI narration via Bedrock...
                        </div>
                      ) : narrations[t.id] ? (
                        <div className="space-y-2">
                          <p className="text-sm text-slate-200 leading-relaxed">{narrations[t.id].executive_summary}</p>
                          {narrations[t.id].mitigation_steps?.length > 0 && (
                            <div>
                              <p className="text-xs font-semibold text-slate-400 mb-1">Mitigation Steps:</p>
                              <ul className="space-y-1">
                                {narrations[t.id].mitigation_steps.map((s: string, i: number) => (
                                  <li key={i} className="text-xs text-slate-300 flex items-start gap-2">
                                    <span className="text-sentinel-cyan mt-0.5">•</span>{s}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      ) : <p className="text-xs text-slate-500">Expanding generates AI narration...</p>}
                    </div>
                    {/* Raw log sample */}
                    {t.raw_entries?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Sample Entries</p>
                        <div className="bg-sentinel-surface rounded-lg p-2 space-y-0.5">
                          {t.raw_entries.slice(0, 3).map((l: string, i: number) => (
                            <p key={i} className="text-xs font-mono text-muted-foreground truncate">{l}</p>
                          ))}
                        </div>
                      </div>
                    )}
                  </motion.div>
                )}
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      )}
    </div>
  )
}
