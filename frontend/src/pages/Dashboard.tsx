import React, { useEffect, useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { Shield, AlertTriangle, Activity, Eye, TrendingUp, Zap, RefreshCw } from 'lucide-react'
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import api from '@/lib/api'
import { SEVERITY_COLORS, ATTACK_TYPE_LABELS, formatRelativeTime } from '@/lib/utils'
import { useStreamRefresh, useStream } from '@/contexts/StreamContext'

const CARD_VARIANTS = {
  hidden: { opacity: 0, y: 20 },
  visible: (i: number) => ({ opacity: 1, y: 0, transition: { delay: i * 0.07, duration: 0.4 } }),
}

function StatCard({ icon: Icon, label, value, color, index }: any) {
  return (
    <motion.div custom={index} variants={CARD_VARIANTS} initial="hidden" animate="visible"
      className="stat-card glass-card-hover">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-400 uppercase tracking-wider font-medium">{label}</span>
        <div className="h-8 w-8 rounded-lg flex items-center justify-center" style={{ background: `${color}18`, border: `1px solid ${color}44` }}>
          <Icon className="h-4 w-4" style={{ color }} />
        </div>
      </div>
      <div className="text-3xl font-bold text-white font-mono">{value}</div>
    </motion.div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const { connected: streaming } = useStream()

  const fetchStats = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    else setRefreshing(true)
    try {
      const r = await api.get('/dashboard/stats')
      setStats(r.data)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  // Initial load
  useEffect(() => { fetchStats() }, [fetchStats])

  // Re-fetch whenever a stream finishes (fires even if page mounted after stream)
  useStreamRefresh(() => { fetchStats(true) })

  // Poll every 30s while streaming is active
  useEffect(() => {
    if (!streaming) return
    const id = setInterval(() => fetchStats(true), 30_000)
    return () => clearInterval(id)
  }, [streaming, fetchStats])


  const pieData = stats ? Object.entries(stats.attack_type_breakdown || {}).map(([k, v]) => ({
    name: ATTACK_TYPE_LABELS[k] || k, value: v as number
  })) : []

  const PIE_COLORS = ['#f43f5e','#ff6b35','#eab308','#22c55e','#a855f7','#00d4ff']

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-sm text-slate-400 mt-0.5">Real-time threat intelligence overview</p>
        </div>
        <div className="flex items-center gap-2">
          {refreshing && <RefreshCw className="h-3.5 w-3.5 text-sentinel-cyan animate-spin" />}
          {streaming && (
            <span className="text-xs font-mono bg-sentinel-green/10 border border-sentinel-green/30 text-sentinel-green px-2 py-1 rounded-full">
              ● Stream Active
            </span>
          )}
          <button onClick={() => fetchStats(true)} title="Refresh stats"
            className="text-slate-400 hover:text-sentinel-cyan transition-colors">
            <RefreshCw className="h-4 w-4" />
          </button>
          <span className="h-2 w-2 rounded-full bg-sentinel-green animate-pulse" />
          <span className="text-xs text-slate-300 font-mono">LIVE</span>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {[
          { icon: Activity, label: 'Logs Analyzed', value: stats?.total_logs_analyzed ?? 0, color: '#00d4ff' },
          { icon: Shield, label: 'Total Threats', value: stats?.total_threats ?? 0, color: '#a855f7' },
          { icon: Zap, label: 'Critical', value: stats?.critical_count ?? 0, color: '#f43f5e' },
          { icon: AlertTriangle, label: 'High', value: stats?.high_count ?? 0, color: '#ff6b35' },
          { icon: Eye, label: 'Medium', value: stats?.medium_count ?? 0, color: '#eab308' },
          { icon: TrendingUp, label: 'Low', value: stats?.low_count ?? 0, color: '#22c55e' },
        ].map((card, i) => <StatCard key={card.label} {...card} index={i} />)}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Traffic Over Time */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}
          className="glass-card p-5 lg:col-span-2">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Activity className="h-4 w-4 text-sentinel-cyan" /> Traffic Timeline
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={stats?.requests_over_time || []}>
              <defs>
                <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="#334155" tick={{ fill: '#64748b', fontSize: 10 }} />
              <YAxis stroke="#334155" tick={{ fill: '#64748b', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', color: '#e2e8f0' }} />
              <Area type="monotone" dataKey="requests" stroke="#00d4ff" fill="url(#cyanGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Attack Type Breakdown */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4 }}
          className="glass-card p-5">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Shield className="h-4 w-4 text-sentinel-amber" /> Attack Types
          </h3>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value">
                {pieData.map((_, idx) => <Cell key={idx} fill={PIE_COLORS[idx % PIE_COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', color: '#e2e8f0' }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="mt-2 space-y-1">
            {pieData.slice(0, 4).map((d, i) => (
              <div key={d.name} className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span className="h-2 w-2 rounded-full" style={{ background: PIE_COLORS[i % PIE_COLORS.length] }} />{d.name}
                </span>
                <span className="text-white font-mono">{d.value}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Top IPs + Recent Threats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top IPs */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }}
          className="glass-card p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Top Attacking IPs</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={(stats?.top_attacking_ips || []).slice(0, 6)} layout="vertical">
              <XAxis type="number" stroke="#334155" tick={{ fill: '#64748b', fontSize: 10 }} />
              <YAxis type="category" dataKey="ip" stroke="#334155" tick={{ fill: '#64748b', fontSize: 10 }} width={110} />
              <Tooltip contentStyle={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', color: '#e2e8f0' }} />
              <Bar dataKey="count" fill="#f43f5e" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Recent Threats */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6 }}
          className="glass-card p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Recent Threats</h3>
          <div className="space-y-2">
            {(stats?.recent_threats || []).length === 0 ? (
              <p className="text-sm text-slate-400 text-center py-8">No threats detected yet. Upload a log file to begin.</p>
            ) : (stats.recent_threats || []).map((t: any) => (
              <div key={t.id} className="flex items-center justify-between p-3 rounded-lg"
                style={{ background: 'rgba(30,58,95,0.3)', border: '1px solid rgba(30,58,95,0.6)' }}>
                <div className="flex items-center gap-3">
                  <span className={`badge-${t.severity?.toLowerCase()}`}>
                    {t.severity}
                  </span>
                  <div>
                    <p className="text-xs font-semibold text-slate-200">{ATTACK_TYPE_LABELS[t.attack_type] || t.attack_type}</p>
                    <p className="text-xs text-slate-400 font-mono">{t.source_ip}</p>
                  </div>
                </div>
                <span className="text-xs text-slate-400">{formatRelativeTime(t.timestamp)}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  )
}
