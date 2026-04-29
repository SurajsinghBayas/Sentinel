import React, { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Radio, Square, Trash2, AlertCircle } from 'lucide-react'
import { useWebSocket } from '@/hooks/useWebSocket'
import { SEVERITY_COLORS, ATTACK_TYPE_LABELS } from '@/lib/utils'

const SAMPLE_FILES = ['apache_access.log', 'syslog.log', 'nginx_error.log']

export default function LogStream() {
  const [selectedFile, setSelectedFile] = useState(SAMPLE_FILES[0])
  const { messages, connected, status, connect, disconnect, clearMessages } = useWebSocket(
    `/api/logs/simulate/${selectedFile}`, false
  )
  const bottomRef = useRef<HTMLDivElement>(null)
  const detectedThreats = messages.filter(m => m.type === 'threat_detected')
  const logLines = messages.filter(m => m.type === 'log_line')

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages.length])

  const getLineClass = (line: string) => {
    if (/401|403|failed|BLOCK/i.test(line)) return 'log-high'
    if (/500|error|critical/i.test(line)) return 'log-critical'
    if (/warn|404/i.test(line)) return 'log-medium'
    return 'log-normal'
  }

  return (
    <div className="h-full flex flex-col gap-4">
      <div className="flex items-center justify-between flex-shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-white">Live Log Stream</h1>
          <p className="text-sm text-slate-400 mt-0.5">Real-time log ingestion via WebSocket</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${connected ? 'bg-sentinel-green animate-pulse' : status === 'connecting' ? 'bg-yellow-400 animate-pulse' : 'bg-sentinel-red'}`} />
          <span className={`text-xs font-mono capitalize ${connected ? 'text-sentinel-green' : status === 'connecting' ? 'text-yellow-400' : 'text-slate-400'}`}>{status}</span>
        </div>
      </div>

      {/* Controls */}
      <div className="glass-card p-4 flex flex-wrap items-center gap-3 flex-shrink-0">
        <select value={selectedFile} onChange={e => { setSelectedFile(e.target.value); disconnect(); clearMessages() }}
          className="bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-sentinel-cyan">
          {SAMPLE_FILES.map(f => <option key={f} value={f}>{f}</option>)}
        </select>
        {!connected ? (
          <button onClick={connect} className="btn-primary">
            <Radio className="h-4 w-4" /> Start Streaming
          </button>
        ) : (
          <button onClick={disconnect} className="btn-danger">
            <Square className="h-4 w-4" /> Stop
          </button>
        )}
        <button onClick={clearMessages}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-muted-foreground hover:text-foreground hover:bg-sentinel-surface transition-colors border border-sentinel-border">
          <Trash2 className="h-4 w-4" /> Clear
        </button>
        <span className="text-xs font-mono text-muted-foreground ml-auto">{logLines.length} lines</span>
      </div>

      {/* Threat alerts */}
      <AnimatePresence>
        {detectedThreats.map((m, i) => (
          <motion.div key={i} initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }}
            className="glass-card p-3 flex items-center gap-3 border-l-4 border-sentinel-red animate-threat-pulse flex-shrink-0">
            <AlertCircle className="h-5 w-5 text-sentinel-red flex-shrink-0" />
            <div className="text-sm">
              <span className="font-semibold text-sentinel-red">{ATTACK_TYPE_LABELS[(m.payload as any).attack_type] || 'THREAT'}</span>
              <span className="text-muted-foreground ml-2">from {(m.payload as any).source_ip}</span>
            </div>
            <span className={`badge-${((m.payload as any).severity || 'low').toLowerCase()} ml-auto`}>
              {(m.payload as any).severity}
            </span>
          </motion.div>
        ))}
      </AnimatePresence>

      {/* Log feed terminal */}
      <div className="glass-card flex-1 overflow-hidden flex flex-col min-h-0 scan-overlay">
        <div className="flex items-center gap-2 px-4 py-2 border-b border-sentinel-border flex-shrink-0">
          <div className="flex gap-1.5">
            <span className="h-3 w-3 rounded-full bg-red-500/60" />
            <span className="h-3 w-3 rounded-full bg-yellow-500/60" />
            <span className="h-3 w-3 rounded-full bg-green-500/60" />
          </div>
          <span className="text-xs font-mono text-muted-foreground ml-2">sentinel@system — {selectedFile}</span>
        </div>
        <div className="flex-1 overflow-y-auto p-3 space-y-0.5 font-mono text-xs">
          {logLines.length === 0 ? (
            <p className="text-muted-foreground p-4 text-center">
              {connected ? 'Streaming...' : 'Select a sample file and click Start Streaming'}
            </p>
          ) : logLines.map((m, i) => (
            <div key={i} className={getLineClass(String((m.payload as any).raw_line || ''))}>
              <span className="text-muted-foreground mr-2">{String((m.payload as any).line_number || i + 1).padStart(4, '0')}</span>
              {String((m.payload as any).raw_line || '')}
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  )
}
