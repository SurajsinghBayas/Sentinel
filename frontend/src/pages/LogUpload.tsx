import React, { useCallback, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, FileText, CheckCircle, AlertCircle, Loader2, Shield } from 'lucide-react'
import api from '@/lib/api'
import { ATTACK_TYPE_LABELS, SEVERITY_COLORS } from '@/lib/utils'

export default function LogUpload() {
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState('')
  const [format, setFormat] = useState('auto')

  const onDrop = useCallback(async (files: File[]) => {
    if (!files[0]) return
    setUploading(true); setError(''); setResult(null)
    const form = new FormData()
    form.append('file', files[0])
    form.append('log_format', format)
    try {
      const { data } = await api.post('/logs/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } })
      setResult(data)
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }, [format])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop, accept: { 'text/*': ['.log', '.csv', '.txt'] } })

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Log Upload</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Upload log files for threat analysis</p>
      </div>

      <div className="glass-card p-4 flex items-center gap-4">
        <label className="text-sm font-medium text-foreground">Format:</label>
        <select value={format} onChange={e => setFormat(e.target.value)}
          className="bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-1.5 text-sm text-foreground focus:outline-none focus:border-sentinel-cyan">
          <option value="auto">Auto-detect</option>
          <option value="apache">Apache / Nginx Combined</option>
          <option value="syslog">Syslog RFC 3164</option>
          <option value="zeek_csv">Zeek CSV</option>
          <option value="nginx_error">Nginx Error Log</option>
        </select>
      </div>

      <div {...getRootProps()}
        className={`glass-card p-12 text-center cursor-pointer transition-all duration-300 border-2 border-dashed
          ${isDragActive ? 'border-sentinel-cyan bg-cyan-500/5' : 'border-sentinel-border hover:border-sentinel-cyan/50'}`}>
        <input {...getInputProps()} />
        {uploading ? (
          <div className="flex flex-col items-center gap-3">
            <Loader2 className="h-10 w-10 text-sentinel-cyan animate-spin" />
            <p className="text-sm text-muted-foreground">Analyzing log file...</p>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3">
            <Upload className={`h-10 w-10 ${isDragActive ? 'text-sentinel-cyan' : 'text-muted-foreground'}`} />
            <div>
              <p className="text-base font-semibold text-foreground">Drop log file here or click to browse</p>
              <p className="text-sm text-muted-foreground mt-1">Supports: .log, .csv, .txt — Apache, Syslog, Zeek, Nginx</p>
            </div>
          </div>
        )}
      </div>

      <AnimatePresence>
        {error && (
          <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
            className="glass-card p-4 flex items-center gap-3 border-l-4 border-sentinel-red">
            <AlertCircle className="h-5 w-5 text-sentinel-red" />
            <span className="text-sm text-sentinel-red">{error}</span>
          </motion.div>
        )}

        {result && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
            <div className="glass-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <CheckCircle className="h-5 w-5 text-sentinel-green" />
                <h3 className="font-semibold text-foreground">Analysis Complete</h3>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                  { label: 'Lines Parsed', value: result.parsed_count },
                  { label: 'Total Lines', value: result.total_lines },
                  { label: 'Threats Found', value: result.threats_found },
                  { label: 'Format', value: result.log_format },
                ].map(({ label, value }) => (
                  <div key={label} className="text-center p-3 rounded-lg" style={{ background: 'rgba(30,58,95,0.3)' }}>
                    <p className="text-2xl font-bold font-mono text-foreground">{value}</p>
                    <p className="text-xs text-muted-foreground mt-1">{label}</p>
                  </div>
                ))}
              </div>
            </div>

            {result.threats?.length > 0 && (
              <div className="glass-card p-5">
                <h3 className="font-semibold text-foreground mb-3 flex items-center gap-2">
                  <Shield className="h-4 w-4 text-sentinel-red" /> Detected Threats
                </h3>
                <div className="space-y-2">
                  {result.threats.map((t: any) => (
                    <div key={t.id} className="flex items-center justify-between p-3 rounded-lg"
                      style={{ background: 'rgba(244,63,94,0.05)', border: '1px solid rgba(244,63,94,0.2)' }}>
                      <div className="flex items-center gap-3">
                        <span className={`badge-${t.severity?.toLowerCase()}`}>{t.severity}</span>
                        <div>
                          <p className="text-sm font-medium text-foreground">{ATTACK_TYPE_LABELS[t.attack_type] || t.attack_type}</p>
                          <p className="text-xs text-muted-foreground font-mono">{t.source_ip} — {t.rule_name}</p>
                        </div>
                      </div>
                      <span className="text-xs text-muted-foreground">{Math.round(t.confidence * 100)}% conf.</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
