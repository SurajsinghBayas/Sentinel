import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { FileText, Download, Loader2, Shield, AlertTriangle } from 'lucide-react'
import { PDFDownloadLink } from '@react-pdf/renderer'
import api from '@/lib/api'
import { IncidentReportPDF } from '@/components/reports/PDFReport'

export default function Reports() {
  const [loading, setLoading] = useState(false)
  const [reportData, setReportData] = useState<any>(null)
  const [title, setTitle] = useState('ANBU Sentinel Incident Report')
  const [classification, setClassification] = useState('CONFIDENTIAL')

  const generate = async () => {
    setLoading(true)
    try {
      const { data } = await api.post('/reports/generate', { title, classification })
      setReportData(data)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Incident Reports</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Generate AI-narrated PDF incident reports</p>
      </div>

      {/* Config */}
      <div className="glass-card p-6 space-y-4">
        <h3 className="font-semibold text-foreground">Report Configuration</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-muted-foreground uppercase tracking-wider">Report Title</label>
            <input value={title} onChange={e => setTitle(e.target.value)}
              className="mt-1.5 w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-sentinel-cyan" />
          </div>
          <div>
            <label className="text-xs text-muted-foreground uppercase tracking-wider">Classification</label>
            <select value={classification} onChange={e => setClassification(e.target.value)}
              className="mt-1.5 w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-sentinel-cyan">
              <option value="CONFIDENTIAL">CONFIDENTIAL</option>
              <option value="SECRET">SECRET</option>
              <option value="INTERNAL">INTERNAL</option>
              <option value="PUBLIC">PUBLIC</option>
            </select>
          </div>
        </div>
        <button onClick={generate} disabled={loading} className="btn-primary disabled:opacity-50">
          {loading ? <><Loader2 className="h-4 w-4 animate-spin" /> Generating...</> : <><FileText className="h-4 w-4" /> Generate Report</>}
        </button>
      </div>

      {/* Report Preview + Download */}
      {reportData && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
          <div className="glass-card p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-foreground">{reportData.title}</h3>
              <PDFDownloadLink document={<IncidentReportPDF data={reportData} />} fileName={`sentinel-report-${Date.now()}.pdf`}>
                {(({ loading: pdfLoading }: { loading: boolean }) => (
                  <button className="btn-primary" disabled={pdfLoading}>
                    {pdfLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                    {pdfLoading ? 'Building PDF...' : 'Download PDF'}
                  </button>
                )) as any}
              </PDFDownloadLink>
            </div>

            <div className="space-y-4 text-sm">
              <div className="p-4 rounded-lg bg-sentinel-surface border border-sentinel-border">
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Executive Summary (AI-Generated)</p>
                <p className="text-foreground leading-relaxed">{reportData.summary_narration}</p>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                  { label: 'Total Threats', value: reportData.stats?.total_threats ?? reportData.total_events },
                  { label: 'Critical', value: reportData.stats?.critical ?? 0 },
                  { label: 'High', value: reportData.stats?.high ?? 0 },
                  { label: 'Medium', value: reportData.stats?.medium ?? 0 },
                ].map(({ label, value }) => (
                  <div key={label} className="text-center p-3 rounded-lg bg-sentinel-surface">
                    <p className="text-xl font-bold font-mono text-foreground">{value}</p>
                    <p className="text-xs text-muted-foreground">{label}</p>
                  </div>
                ))}
              </div>

              <div>
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                  <Shield className="inline h-3 w-3 mr-1" />Recommendations
                </p>
                <ul className="space-y-2">
                  {reportData.recommendations?.slice(0, 5).map((r: string, i: number) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-foreground">
                      <span className="text-sentinel-cyan mt-0.5 font-mono text-xs">{String(i + 1).padStart(2, '0')}.</span>
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  )
}
