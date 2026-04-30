import React, { useEffect, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FileText, Download, Loader2, Shield, RefreshCw,
  Clock, AlertTriangle, CheckCircle2, Database,
  Zap, ChevronRight, History, Radio, X
} from 'lucide-react'
import { PDFDownloadLink } from '@react-pdf/renderer'
import api from '@/lib/api'
import { IncidentReportPDF } from '@/components/reports/PDFReport'
import { ATTACK_TYPE_LABELS } from '@/lib/utils'
import { useStreamRefresh, useStream } from '@/contexts/StreamContext'

type Session = {
  session_id: string
  filename:   string
  log_format: string
  total_lines: number
  threats_found: number
  uploaded_at: string
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'text-sentinel-red',
  HIGH:     'text-orange-400',
  MEDIUM:   'text-yellow-400',
  LOW:      'text-sentinel-green',
}

export default function Reports() {
  const [sessions, setSessions]               = useState<Session[]>([])
  const [loadingSessions, setLoadingSessions] = useState(true)
  const [refreshingSessions, setRefreshingSessions] = useState(false)
  const [selectedSession, setSelectedSession] = useState<string>('all')
  const [loading, setLoading]                 = useState(false)
  const [reportData, setReportData]           = useState<any>(null)
  const [title, setTitle]                     = useState('ANBU Sentinel Incident Report')
  const [classification, setClassification]   = useState('CONFIDENTIAL')
  const [history, setHistory]                 = useState<any[]>([])
  const [showHistory, setShowHistory]         = useState(false)
  const [loadingHistory, setLoadingHistory]   = useState(false)
  const [newSessionId, setNewSessionId]       = useState<string | null>(null) // just-streamed

  const { connected: streaming } = useStream()

  // ── Fetch sessions ─────────────────────────────────────────────────────
  const fetchSessions = useCallback(async (quiet = false) => {
    if (!quiet) setLoadingSessions(true)
    else setRefreshingSessions(true)
    try {
      const r = await api.get('/logs/sessions')
      setSessions(r.data || [])
    } catch {
      setSessions([])
    } finally {
      setLoadingSessions(false)
      setRefreshingSessions(false)
    }
  }, [])

  useEffect(() => { fetchSessions() }, [fetchSessions])

  // Auto-refresh sessions + auto-select when stream finishes
  const { lastStreamPayload } = useStream()
  useStreamRefresh(() => {
    fetchSessions(true)
    const sid = lastStreamPayload?.session_id as string | undefined
    if (sid) {
      setNewSessionId(sid)
      setTimeout(() => setSelectedSession(sid), 1000)
    }
  })

  // ── Load report history ────────────────────────────────────────────────
  const fetchHistory = useCallback(async () => {
    setLoadingHistory(true)
    try {
      const r = await api.get('/reports/history')
      setHistory(r.data || [])
    } finally {
      setLoadingHistory(false)
    }
  }, [])

  useEffect(() => {
    if (showHistory) fetchHistory()
  }, [showHistory, fetchHistory])

  const selectedSessionData = sessions.find(s => s.session_id === selectedSession)
  const totalThreats = sessions.reduce((s, sess) => s + sess.threats_found, 0)

  // ── Generate report ────────────────────────────────────────────────────
  const generate = async () => {
    setLoading(true)
    setReportData(null)
    try {
      const payload: any = { title, classification }
      if (selectedSession !== 'all') payload.session_id = selectedSession
      const { data } = await api.post('/reports/generate', payload)
      setReportData(data)
      // Refresh history silently
      fetchHistory()
    } finally {
      setLoading(false)
    }
  }

  // ── Severity bar component ─────────────────────────────────────────────
  const SevBar = ({ sess }: { sess: Session }) => {
    const total = sess.threats_found || 1
    return (
      <div className="flex gap-0.5 h-1 w-full rounded-full overflow-hidden mt-1.5">
        {[
          { k: 'CRITICAL', color: 'bg-sentinel-red', n: 0 },
          { k: 'HIGH',     color: 'bg-orange-400',   n: 0 },
          { k: 'MEDIUM',   color: 'bg-yellow-400',   n: 0 },
          { k: 'LOW',      color: 'bg-sentinel-green', n: sess.threats_found },
        ].map(({ k, color, n }) => (
          <div key={k} className={`${color} h-full`} style={{ width: `${(n / total) * 100}%` }} />
        ))}
      </div>
    )
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Incident Reports</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Generate AI-narrated PDF reports scoped to a specific log session
            {streaming && <span className="ml-2 text-sentinel-green font-mono">● Stream Active</span>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {streaming && (
            <span className="flex items-center gap-1.5 text-xs font-mono bg-sentinel-green/10 border border-sentinel-green/30 text-sentinel-green px-2 py-1 rounded-full">
              <Radio className="h-3 w-3 animate-pulse" /> Live
            </span>
          )}
          <button onClick={() => setShowHistory(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
              showHistory ? 'bg-sentinel-cyan/10 border-sentinel-cyan/30 text-sentinel-cyan' : 'border-sentinel-border text-slate-400 hover:text-white'
            }`}>
            <History className="h-3.5 w-3.5" /> History {history.length > 0 && `(${history.length})`}
          </button>
        </div>
      </div>

      {/* ── Report History panel ─────────────────────────────────────────── */}
      <AnimatePresence>
        {showHistory && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
            className="glass-card p-4 space-y-3 overflow-hidden">
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-white flex items-center gap-2">
                <History className="h-4 w-4 text-sentinel-cyan" /> Previously Generated Reports
              </p>
              {loadingHistory && <RefreshCw className="h-3.5 w-3.5 text-sentinel-cyan animate-spin" />}
            </div>
            {history.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-4">No reports generated yet.</p>
            ) : (
              <div className="space-y-2 max-h-56 overflow-y-auto">
                {history.map(r => (
                  <div key={r.id}
                    className="flex items-center gap-3 p-2.5 rounded-lg bg-sentinel-surface border border-sentinel-border text-xs">
                    <FileText className="h-4 w-4 text-sentinel-cyan flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-semibold truncate">{r.title}</p>
                      <p className="text-slate-400">{new Date(r.generated_at).toLocaleString()}</p>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <p className="text-sentinel-red font-mono font-bold">{r.critical_count + r.high_count}</p>
                      <p className="text-slate-500">C+H threats</p>
                    </div>
                    <span className="text-xs border border-sentinel-border px-1.5 py-0.5 rounded text-slate-400">{r.classification}</span>
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Session Selector ─────────────────────────────────────────────── */}
      <div className="glass-card p-6 space-y-5">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-white flex items-center gap-2">
            <Database className="h-4 w-4 text-sentinel-cyan" /> Select Log Session
          </h3>
          <button onClick={() => fetchSessions(true)}
            className="text-slate-400 hover:text-sentinel-cyan transition-colors p-1" title="Refresh sessions">
            <RefreshCw className={`h-4 w-4 ${refreshingSessions ? 'animate-spin text-sentinel-cyan' : ''}`} />
          </button>
        </div>

        {loadingSessions ? (
          <div className="flex items-center gap-2 text-sm text-slate-400 py-4">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading sessions...
          </div>
        ) : (
          <div className="space-y-2 max-h-72 overflow-y-auto pr-1">

            {/* All sessions */}
            <label className={`flex items-center gap-4 p-3 rounded-lg cursor-pointer border transition-all ${
              selectedSession === 'all'
                ? 'border-sentinel-cyan bg-sentinel-cyan/5'
                : 'border-sentinel-border hover:border-slate-600'
            }`}>
              <input type="radio" name="session" value="all"
                checked={selectedSession === 'all'}
                onChange={() => setSelectedSession('all')}
                className="accent-sentinel-cyan" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-white">All Sessions</p>
                <p className="text-xs text-slate-400">Combine threats from all {sessions.length} log files</p>
              </div>
              <span className="text-xs font-mono font-bold text-sentinel-red">{totalThreats} threats</span>
            </label>

            {/* Individual sessions */}
            {sessions.length === 0 ? (
              <div className="text-center py-8 text-slate-500 text-sm">
                <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-40" />
                No log sessions yet. Start a Live Stream to generate one.
              </div>
            ) : sessions.map(s => (
              <motion.label key={s.session_id}
                initial={s.session_id === newSessionId ? { opacity: 0, x: -10 } : false}
                animate={{ opacity: 1, x: 0 }}
                className={`flex items-center gap-4 p-3 rounded-lg cursor-pointer border transition-all relative ${
                  selectedSession === s.session_id
                    ? 'border-sentinel-cyan bg-sentinel-cyan/5'
                    : 'border-sentinel-border hover:border-slate-600'
                }`}>
                {/* "New" badge for just-streamed session */}
                {s.session_id === newSessionId && (
                  <span className="absolute top-1.5 right-1.5 text-xs bg-sentinel-green/20 border border-sentinel-green/40 text-sentinel-green px-1.5 py-0.5 rounded-full font-mono">
                    new
                  </span>
                )}
                <input type="radio" name="session" value={s.session_id}
                  checked={selectedSession === s.session_id}
                  onChange={() => setSelectedSession(s.session_id)}
                  className="accent-sentinel-cyan" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-white font-mono truncate">{s.filename}</p>
                  <p className="text-xs text-slate-400 flex items-center gap-2 mt-0.5">
                    <Clock className="h-3 w-3" />
                    {new Date(s.uploaded_at).toLocaleString()} · {s.total_lines.toLocaleString()} lines · {s.log_format}
                  </p>
                  <div className="w-full bg-sentinel-surface h-1 rounded-full mt-1.5 overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-sentinel-red via-orange-400 to-sentinel-green rounded-full transition-all"
                      style={{ width: s.threats_found > 0 ? '100%' : '0%' }} />
                  </div>
                </div>
                <div className="text-right flex-shrink-0">
                  <p className={`text-sm font-bold font-mono ${s.threats_found > 0 ? 'text-sentinel-red' : 'text-sentinel-green'}`}>
                    {s.threats_found}
                  </p>
                  <p className="text-xs text-slate-500">threats</p>
                </div>
              </motion.label>
            ))}
          </div>
        )}

        {/* Report config */}
        <div className="border-t border-sentinel-border pt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-slate-400 uppercase tracking-wider">Report Title</label>
            <input value={title} onChange={e => setTitle(e.target.value)}
              className="mt-1.5 w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-sentinel-cyan" />
          </div>
          <div>
            <label className="text-xs text-slate-400 uppercase tracking-wider">Classification</label>
            <select value={classification} onChange={e => setClassification(e.target.value)}
              className="mt-1.5 w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-sentinel-cyan">
              <option value="CONFIDENTIAL">CONFIDENTIAL</option>
              <option value="SECRET">SECRET</option>
              <option value="INTERNAL">INTERNAL</option>
              <option value="PUBLIC">PUBLIC</option>
            </select>
          </div>
        </div>

        {/* Scope banner */}
        {selectedSession !== 'all' && selectedSessionData && (
          <div className="flex items-center gap-2 text-xs text-sentinel-cyan bg-sentinel-cyan/5 border border-sentinel-cyan/20 rounded-lg px-3 py-2">
            <CheckCircle2 className="h-3.5 w-3.5 flex-shrink-0" />
            <span>Report scoped to <strong className="font-mono">{selectedSessionData.filename}</strong>
            &nbsp;— {selectedSessionData.threats_found} threats · {selectedSessionData.total_lines.toLocaleString()} lines</span>
          </div>
        )}

        <button onClick={generate} disabled={loading} className="btn-primary disabled:opacity-50 w-full justify-center">
          {loading
            ? <><Loader2 className="h-4 w-4 animate-spin" /> Generating AI Report via Nova...</>
            : <><Zap className="h-4 w-4" /> Generate AI Report</>}
        </button>
      </div>

      {/* ── Report Preview + Download ────────────────────────────────────── */}
      <AnimatePresence>
        {reportData && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }} className="space-y-4">
            <div className="glass-card p-6">

              {/* Header row */}
              <div className="flex items-start justify-between mb-5 gap-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs border border-sentinel-border px-2 py-0.5 rounded text-slate-400 font-mono">
                      {reportData.classification}
                    </span>
                    <CheckCircle2 className="h-4 w-4 text-sentinel-green" />
                    <span className="text-xs text-sentinel-green">Generated</span>
                  </div>
                  <h3 className="font-semibold text-white">{reportData.title}</h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {new Date(reportData.generated_at).toLocaleString()}
                    {reportData.analyst_name && ` · ${reportData.analyst_name}`}
                  </p>
                </div>
                <PDFDownloadLink
                  document={<IncidentReportPDF data={reportData} />}
                  fileName={`sentinel-report-${Date.now()}.pdf`}>
                  {(({ loading: pdfLoading }: { loading: boolean }) => (
                    <button className="btn-primary flex-shrink-0" disabled={pdfLoading}>
                      {pdfLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                      {pdfLoading ? 'Building PDF...' : 'Download PDF'}
                    </button>
                  )) as any}
                </PDFDownloadLink>
              </div>

              {/* Stats grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
                {[
                  { label: 'Total Threats', value: reportData.stats?.total_threats ?? reportData.total_events, color: 'text-white' },
                  { label: 'Critical',      value: reportData.stats?.critical ?? 0, color: 'text-sentinel-red' },
                  { label: 'High',          value: reportData.stats?.high ?? 0,     color: 'text-orange-400' },
                  { label: 'Medium',        value: reportData.stats?.medium ?? 0,   color: 'text-yellow-400' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="text-center p-3 rounded-lg bg-sentinel-surface">
                    <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
                    <p className="text-xs text-slate-400 mt-0.5">{label}</p>
                  </div>
                ))}
              </div>

              {/* AI Executive Summary */}
              <div className="p-4 rounded-lg bg-sentinel-surface border border-sentinel-border mb-4">
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Shield className="h-3 w-3 text-sentinel-cyan" /> AI Executive Summary
                </p>
                <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-line">
                  {reportData.summary_narration}
                </p>
              </div>

              {/* Recommendations */}
              <div className="mb-1">
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                  <Zap className="h-3 w-3 text-sentinel-amber" /> AI Recommendations
                </p>
                <ul className="space-y-2">
                  {reportData.recommendations?.map((r: string, i: number) => (
                    <li key={i} className="flex items-start gap-3 text-sm text-slate-300">
                      <span className="text-sentinel-cyan font-mono text-xs mt-0.5 flex-shrink-0 bg-sentinel-cyan/10 border border-sentinel-cyan/20 px-1.5 py-0.5 rounded">
                        {String(i + 1).padStart(2, '0')}
                      </span>
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Threat table */}
            {reportData.threats?.length > 0 && (
              <div className="glass-card p-5">
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                  <Shield className="h-3.5 w-3.5 text-sentinel-red" />
                  Threats in Report ({reportData.threats.length})
                </p>
                <div className="space-y-1.5 max-h-72 overflow-y-auto">
                  {reportData.threats.slice(0, 30).map((t: any, i: number) => (
                    <div key={i}
                      className="flex items-center gap-3 text-xs py-2 px-3 rounded-lg bg-sentinel-surface border border-sentinel-border/50">
                      <span className={`badge-${t.severity?.toLowerCase()} flex-shrink-0`}>{t.severity}</span>
                      <span className="text-white font-semibold flex-1 truncate">
                        {ATTACK_TYPE_LABELS[t.attack_type] || t.attack_type?.replace(/_/g, ' ')}
                      </span>
                      <span className="font-mono text-slate-400 flex-shrink-0">{t.source_ip}</span>
                      <span className="text-slate-500 flex-shrink-0">{Math.round((t.confidence || 0) * 100)}%</span>
                    </div>
                  ))}
                  {reportData.threats.length > 30 && (
                    <p className="text-xs text-slate-500 text-center py-2">
                      + {reportData.threats.length - 30} more threats in PDF
                    </p>
                  )}
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
