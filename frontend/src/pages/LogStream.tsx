import React, { useEffect, useRef, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Radio, Square, Trash2, AlertCircle, CheckCircle2,
  ChevronRight, FileText, Wifi, Upload, FolderOpen,
  Shield, Zap, X, File,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { useStream } from '@/contexts/StreamContext'
import { SEVERITY_COLORS, ATTACK_TYPE_LABELS } from '@/lib/utils'
import { api } from '@/lib/api'

// ── Sample log files available on the server ──────────────────────────────
const SAMPLE_FILES = [
  { name: 'apache_access.log',  label: 'Apache Access',  desc: 'SQLi, XSS, brute force',        icon: '🌐' },
  { name: 'nginx_access.log',   label: 'Nginx Access',   desc: 'DDoS, credential stuffing',      icon: '⚡' },
  { name: 'nginx_error.log',    label: 'Nginx Error',    desc: 'Dir traversal, injection',        icon: '🔴' },
  { name: 'syslog.log',         label: 'Syslog',         desc: 'SSH brute force, port scan',      icon: '🖥️'  },
  { name: 'auth.log',           label: 'Auth Log',       desc: 'Root auth, priv escalation',      icon: '🔐' },
  { name: 'zeek_conn.csv',      label: 'Zeek Network',   desc: 'Data exfil, port scan',           icon: '📡' },
]

// ── Upload a custom file and get a temp session key back ──────────────────
async function uploadFileToServer(file: File): Promise<string> {
  const form = new FormData()
  form.append('file', file)
  const resp = await fetch('/api/logs/upload-stream', {
    method: 'POST',
    headers: { Authorization: `Bearer ${localStorage.getItem('access_token') || ''}` },
    body: form,
  })
  if (!resp.ok) throw new Error(`Upload failed: ${resp.statusText}`)
  const data = await resp.json()
  return data.session_key
}

type FileMode = 'sample' | 'custom'

export default function LogStream() {
  const {
    messages, connected, status, selectedFile, streamDone,
    setSelectedFile, connect, disconnect, clearMessages,
  } = useStream()

  const bottomRef      = useRef<HTMLDivElement>(null)
  const fileInputRef   = useRef<HTMLInputElement>(null)
  const [fileMode, setFileMode]         = useState<FileMode>('sample')
  const [uploadedFile, setUploadedFile] = useState<File | null>(null)
  const [uploading, setUploading]       = useState(false)
  const [uploadErr, setUploadErr]       = useState<string | null>(null)
  const [dragOver, setDragOver]         = useState(false)

  const detectedThreats = messages.filter(m => m.type === 'threat_detected')
  const logLines        = messages.filter(m => m.type === 'log_line')

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages.length])

  // ── Drag-and-drop handlers ──────────────────────────────────────────────
  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFileSelect(file)
  }, [])

  const handleFileSelect = (file: File) => {
    setUploadedFile(file)
    setUploadErr(null)
    setFileMode('custom')
    // Auto-set selectedFile so the WS label updates
    setSelectedFile(file.name)
  }

  // Upload to server and start streaming
  const handleStartCustom = async () => {
    if (!uploadedFile) return
    setUploading(true)
    setUploadErr(null)
    try {
      const key = await uploadFileToServer(uploadedFile)
      setSelectedFile(`__upload__${key}`)   // StreamContext uses this key
      connect()
    } catch (err: any) {
      setUploadErr(err.message || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  const handleStartSample = () => {
    setFileMode('sample')
    connect()
  }

  const clearUpload = () => {
    setUploadedFile(null)
    setUploadErr(null)
    if (!connected) setSelectedFile('apache_access.log')
    setFileMode('sample')
  }

  // ── Colour coding ───────────────────────────────────────────────────────
  const getLineClass = (line: string) => {
    if (/401|403|failed|BLOCK/i.test(line)) return 'log-high'
    if (/500|error|critical/i.test(line))  return 'log-critical'
    if (/warn|404/i.test(line))            return 'log-medium'
    return 'log-normal'
  }

  // ── Summary stats ───────────────────────────────────────────────────────
  const severityGroups = detectedThreats.reduce((acc: Record<string, number>, m) => {
    const sev = ((m.payload as any).severity || 'LOW').toUpperCase()
    acc[sev] = (acc[sev] || 0) + 1
    return acc
  }, {})

  const attackGroups = detectedThreats.reduce((acc: Record<string, number>, m) => {
    const type = (m.payload as any).attack_type || 'UNKNOWN'
    acc[type] = (acc[type] || 0) + 1
    return acc
  }, {})

  const topIPs = Object.entries(
    detectedThreats.reduce((acc: Record<string, number>, m) => {
      const ip = (m.payload as any).source_ip || '?'
      acc[ip] = (acc[ip] || 0) + 1
      return acc
    }, {})
  ).sort((a, b) => b[1] - a[1]).slice(0, 5)

  const displayName = uploadedFile?.name || selectedFile

  return (
    <div className="space-y-5">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Live Log Stream</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Select a sample file or upload your own — stream, analyse, and report
          </p>
        </div>
        <div className="flex items-center gap-2">
          {connected && (
            <span className="flex items-center gap-1.5 text-xs font-mono bg-sentinel-green/10 border border-sentinel-green/30 text-sentinel-green px-2 py-1 rounded-full">
              <Wifi className="h-3 w-3 animate-pulse" /> Streaming
            </span>
          )}
          <span className={`h-2 w-2 rounded-full ${
            connected ? 'bg-sentinel-green animate-pulse' :
            status === 'connecting' ? 'bg-yellow-400 animate-pulse' : 'bg-sentinel-red'
          }`} />
          <span className={`text-xs font-mono capitalize ${
            connected ? 'text-sentinel-green' :
            status === 'connecting' ? 'text-yellow-400' : 'text-slate-400'
          }`}>{status}</span>
        </div>
      </div>

      {/* ── File Selection Panel ────────────────────────────────────────── */}
      {!connected && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-5 space-y-5"
        >
          {/* Tab switcher */}
          <div className="flex items-center gap-1 bg-sentinel-surface rounded-lg p-1 w-fit">
            <button
              onClick={() => { setFileMode('sample'); clearUpload() }}
              className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-semibold transition-all ${
                fileMode === 'sample'
                  ? 'bg-sentinel-cyan/20 text-sentinel-cyan border border-sentinel-cyan/30'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <FolderOpen className="h-3.5 w-3.5" /> Sample Files
            </button>
            <button
              onClick={() => setFileMode('custom')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-semibold transition-all ${
                fileMode === 'custom'
                  ? 'bg-sentinel-cyan/20 text-sentinel-cyan border border-sentinel-cyan/30'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Upload className="h-3.5 w-3.5" /> Upload File
            </button>
          </div>

          {/* Sample files grid */}
          {fileMode === 'sample' && (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {SAMPLE_FILES.map(f => (
                <button
                  key={f.name}
                  onClick={() => setSelectedFile(f.name)}
                  className={`text-left p-3 rounded-lg border transition-all ${
                    selectedFile === f.name && !uploadedFile
                      ? 'border-sentinel-cyan bg-sentinel-cyan/10 text-white'
                      : 'border-sentinel-border bg-sentinel-surface hover:border-sentinel-cyan/50 text-slate-300'
                  }`}
                >
                  <div className="text-lg mb-1">{f.icon}</div>
                  <p className="text-xs font-semibold">{f.label}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{f.desc}</p>
                  <p className="text-xs font-mono text-slate-600 mt-1 truncate">{f.name}</p>
                </button>
              ))}
            </div>
          )}

          {/* Custom file upload */}
          {fileMode === 'custom' && (
            <div className="space-y-3">
              {!uploadedFile ? (
                <div
                  onDrop={onDrop}
                  onDragOver={e => { e.preventDefault(); setDragOver(true) }}
                  onDragLeave={() => setDragOver(false)}
                  onClick={() => fileInputRef.current?.click()}
                  className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                    dragOver
                      ? 'border-sentinel-cyan bg-sentinel-cyan/10'
                      : 'border-sentinel-border hover:border-sentinel-cyan/50 hover:bg-sentinel-surface'
                  }`}
                >
                  <Upload className={`h-8 w-8 mx-auto mb-3 ${dragOver ? 'text-sentinel-cyan' : 'text-slate-500'}`} />
                  <p className="text-sm font-semibold text-white mb-1">Drop your log file here</p>
                  <p className="text-xs text-slate-400">or click to browse — supports .log, .txt, .csv</p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".log,.txt,.csv"
                    className="hidden"
                    onChange={e => {
                      const f = e.target.files?.[0]
                      if (f) handleFileSelect(f)
                    }}
                  />
                </div>
              ) : (
                <div className="flex items-center gap-3 p-3 bg-sentinel-surface rounded-lg border border-sentinel-cyan/30">
                  <File className="h-8 w-8 text-sentinel-cyan flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-white truncate">{uploadedFile.name}</p>
                    <p className="text-xs text-slate-400">{(uploadedFile.size / 1024).toFixed(1)} KB</p>
                  </div>
                  <button
                    onClick={clearUpload}
                    className="text-slate-400 hover:text-white p-1 rounded transition-colors"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              )}
              {uploadErr && (
                <p className="text-xs text-sentinel-red flex items-center gap-1">
                  <AlertCircle className="h-3.5 w-3.5" /> {uploadErr}
                </p>
              )}
            </div>
          )}

          {/* Start / action row */}
          <div className="flex items-center gap-3 pt-1 border-t border-sentinel-border">
            {fileMode === 'sample' ? (
              <button
                onClick={handleStartSample}
                disabled={!selectedFile}
                className="btn-primary"
              >
                <Radio className="h-4 w-4" /> Start Streaming
              </button>
            ) : (
              <button
                onClick={handleStartCustom}
                disabled={!uploadedFile || uploading}
                className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {uploading
                  ? <><span className="animate-spin h-4 w-4 border-2 border-white/30 border-t-white rounded-full" /> Uploading…</>
                  : <><Upload className="h-4 w-4" /> Upload &amp; Stream</>
                }
              </button>
            )}

            <button
              onClick={clearMessages}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-slate-400 hover:text-white hover:bg-sentinel-surface transition-colors border border-sentinel-border"
            >
              <Trash2 className="h-4 w-4" /> Clear
            </button>

            <div className="ml-auto text-xs font-mono text-slate-500">
              Selected: <span className="text-slate-300">{displayName}</span>
            </div>
          </div>
        </motion.div>
      )}

      {/* Controls bar when streaming */}
      {connected && (
        <div className="glass-card p-3 flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span className="h-2 w-2 bg-sentinel-green rounded-full animate-pulse" />
            Streaming: <span className="text-white">{displayName}</span>
          </div>
          <div className="ml-auto flex items-center gap-4">
            <span className="text-xs font-mono text-slate-400">{logLines.length} lines</span>
            {detectedThreats.length > 0 && (
              <span className="text-xs font-mono text-sentinel-red font-semibold">{detectedThreats.length} threats</span>
            )}
            <button onClick={disconnect} className="btn-danger text-xs py-1.5 px-3">
              <Square className="h-3.5 w-3.5" /> Stop
            </button>
            <button
              onClick={clearMessages}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white hover:bg-sentinel-surface transition-colors border border-sentinel-border"
            >
              <Trash2 className="h-3.5 w-3.5" /> Clear
            </button>
          </div>
        </div>
      )}

      {/* ── Live threat alerts (last 3) ─────────────────────────────────── */}
      <AnimatePresence>
        {detectedThreats.slice(-3).map((m, i) => (
          <motion.div key={`threat-${i}`}
            initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }}
            className="glass-card p-3 flex items-center gap-3 border-l-4 border-sentinel-red animate-threat-pulse"
          >
            <AlertCircle className="h-5 w-5 text-sentinel-red flex-shrink-0" />
            <div className="text-sm flex-1 min-w-0">
              <span className="font-semibold text-sentinel-red">
                {ATTACK_TYPE_LABELS[(m.payload as any).attack_type] || 'THREAT'}
              </span>
              <span className="text-slate-400 ml-2">from {(m.payload as any).source_ip}</span>
              {(m.payload as any).confidence && (
                <span className="text-slate-500 ml-2 text-xs">
                  {Math.round(((m.payload as any).confidence as number) * 100)}% conf
                </span>
              )}
            </div>
            <span className={`badge-${((m.payload as any).severity || 'low').toLowerCase()} ml-auto flex-shrink-0`}>
              {(m.payload as any).severity}
            </span>
          </motion.div>
        ))}
      </AnimatePresence>

      {/* ── Post-Stream Summary ─────────────────────────────────────────── */}
      <AnimatePresence>
        {streamDone && detectedThreats.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="glass-card p-5 border border-sentinel-cyan/20"
          >
            <div className="flex items-center gap-2 mb-4">
              <CheckCircle2 className="h-5 w-5 text-sentinel-green" />
              <h2 className="text-sm font-bold text-white">Stream Complete — Threat Summary</h2>
              <span className="ml-auto text-xs text-slate-400 font-mono">{displayName}</span>
            </div>

            {/* Severity grid */}
            <div className="grid grid-cols-4 gap-2 mb-4">
              {(['CRITICAL','HIGH','MEDIUM','LOW'] as const).map(sev => (
                <div key={sev} className="text-center p-3 rounded-lg bg-sentinel-surface">
                  <p className={`text-2xl font-black font-mono ${
                    sev === 'CRITICAL' ? 'text-sentinel-red' :
                    sev === 'HIGH'     ? 'text-orange-400' :
                    sev === 'MEDIUM'   ? 'text-yellow-400' : 'text-sentinel-green'
                  }`}>{severityGroups[sev] || 0}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{sev}</p>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Attack Types Detected</p>
                <div className="space-y-1.5">
                  {Object.entries(attackGroups).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between text-xs">
                      <span className="flex items-center gap-1.5 text-slate-300">
                        <Shield className="h-3 w-3 text-sentinel-cyan" />
                        {ATTACK_TYPE_LABELS[type] || type}
                      </span>
                      <span className="font-mono text-sentinel-cyan font-semibold">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Top Attacking IPs</p>
                <div className="space-y-1.5">
                  {topIPs.map(([ip, count]) => (
                    <div key={ip} className="flex items-center justify-between text-xs">
                      <span className="font-mono text-slate-300">{ip}</span>
                      <span className="font-mono text-sentinel-red font-semibold">{count} threats</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-4 pt-3 border-t border-sentinel-border">
              <Link to="/detections"
                className="flex items-center gap-2 text-xs text-sentinel-cyan hover:text-white transition-colors font-semibold"
              >
                <Shield className="h-3.5 w-3.5" /> View All Detections <ChevronRight className="h-3 w-3" />
              </Link>
              <Link to="/reports"
                className="flex items-center gap-2 text-xs text-slate-400 hover:text-white transition-colors"
              >
                <FileText className="h-3.5 w-3.5" /> Generate AI Report
              </Link>
              <button
                onClick={() => { clearMessages(); setUploadedFile(null); setFileMode('sample') }}
                className="ml-auto flex items-center gap-2 text-xs text-slate-400 hover:text-white transition-colors"
              >
                <Zap className="h-3.5 w-3.5" /> New Stream
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Terminal feed ───────────────────────────────────────────────── */}
      <div className="glass-card overflow-hidden flex flex-col scan-overlay" style={{ height: '420px' }}>
        <div className="flex items-center gap-2 px-4 py-2 border-b border-sentinel-border flex-shrink-0">
          <div className="flex gap-1.5">
            <span className="h-3 w-3 rounded-full bg-red-500/60" />
            <span className="h-3 w-3 rounded-full bg-yellow-500/60" />
            <span className="h-3 w-3 rounded-full bg-green-500/60" />
          </div>
          <span className="text-xs font-mono text-slate-400 ml-2">sentinel@system — {displayName}</span>
          {streamDone && (
            <span className="ml-auto text-xs text-sentinel-green font-mono flex items-center gap-1">
              <CheckCircle2 className="h-3 w-3" /> done
            </span>
          )}
          {connected && (
            <span className="ml-auto text-xs text-sentinel-green font-mono flex items-center gap-1 animate-pulse">
              ● live
            </span>
          )}
        </div>
        <div className="flex-1 overflow-y-auto p-3 space-y-0.5 font-mono text-xs">
          {logLines.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 gap-3">
              <Radio className="h-8 w-8 opacity-30" />
              <p>{connected ? 'Streaming…' : 'Select a file above and click Start Streaming'}</p>
            </div>
          ) : logLines.map((m, i) => (
            <div key={i} className={getLineClass(String((m.payload as any).raw_line || ''))}>
              <span className="text-slate-600 mr-2">
                {String((m.payload as any).line_number || i + 1).padStart(4, '0')}
              </span>
              {String((m.payload as any).raw_line || '')}
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  )
}
