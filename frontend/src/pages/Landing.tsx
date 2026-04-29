import React, { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Shield, Zap, Eye, Brain, ChevronRight, Radio, Activity,
  Lock, AlertTriangle, Globe, ArrowRight, Star
} from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'

// ── Animated Background ───────────────────────────────────────────────────────
function CyberBackground() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      <div className="absolute inset-0"
        style={{
          backgroundImage: `
            linear-gradient(rgba(0,212,255,0.04) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,212,255,0.04) 1px, transparent 1px)
          `,
          backgroundSize: '60px 60px',
        }} />
      {/* Glowing orbs */}
      <div className="absolute top-1/4 left-1/4 h-96 w-96 rounded-full opacity-10 blur-3xl"
        style={{ background: 'radial-gradient(circle, #00d4ff, transparent)' }} />
      <div className="absolute bottom-1/4 right-1/4 h-64 w-64 rounded-full opacity-8 blur-3xl"
        style={{ background: 'radial-gradient(circle, #a855f7, transparent)' }} />
      <div className="absolute top-3/4 left-1/2 h-48 w-48 rounded-full opacity-6 blur-3xl"
        style={{ background: 'radial-gradient(circle, #f43f5e, transparent)' }} />
    </div>
  )
}

// ── Live Threat Ticker ────────────────────────────────────────────────────────
const MOCK_THREATS = [
  { ip: '192.168.1.45', type: 'Brute Force', sev: 'HIGH' },
  { ip: '10.0.0.23', type: 'SQL Injection', sev: 'CRITICAL' },
  { ip: '172.16.5.8', type: 'DDoS', sev: 'CRITICAL' },
  { ip: '203.45.78.1', type: 'XSS Attack', sev: 'MEDIUM' },
  { ip: '192.168.50.12', type: 'Port Scan', sev: 'LOW' },
]

function ThreatTicker() {
  const [idx, setIdx] = useState(0)
  useEffect(() => {
    const t = setInterval(() => setIdx(i => (i + 1) % MOCK_THREATS.length), 2500)
    return () => clearInterval(t)
  }, [])

  const threat = MOCK_THREATS[idx]
  const sevColor: Record<string, string> = {
    CRITICAL: '#f43f5e', HIGH: '#ff6b35', MEDIUM: '#eab308', LOW: '#22c55e',
  }

  return (
    <motion.div key={idx} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
      className="flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-mono"
      style={{ background: 'rgba(13,21,38,0.9)', border: '1px solid rgba(0,212,255,0.2)' }}>
      <span className="h-2 w-2 rounded-full animate-pulse" style={{ background: sevColor[threat.sev] }} />
      <span className="text-slate-400">THREAT DETECTED</span>
      <span className="text-white">{threat.ip}</span>
      <span className="text-slate-500">→</span>
      <span style={{ color: sevColor[threat.sev] }}>{threat.type}</span>
      <span className="ml-auto px-2 py-0.5 rounded-full text-xs font-bold"
        style={{ background: `${sevColor[threat.sev]}18`, color: sevColor[threat.sev], border: `1px solid ${sevColor[threat.sev]}44` }}>
        {threat.sev}
      </span>
    </motion.div>
  )
}

// ── Feature Cards ─────────────────────────────────────────────────────────────
const FEATURES = [
  {
    icon: Brain,
    color: '#a855f7',
    title: 'AI-Powered Narration',
    desc: 'Claude 3.5 via AWS Bedrock translates raw threat data into actionable, plain-English security briefings — instantly.',
  },
  {
    icon: Radio,
    color: '#00d4ff',
    title: 'Live WebSocket Streaming',
    desc: 'Real-time log ingestion with zero latency. Watch threats surface and get classified as your logs stream in.',
  },
  {
    icon: Eye,
    color: '#f43f5e',
    title: 'Multi-Vector Detection',
    desc: 'Detects brute-force, SQL injection, DDoS, XSS, path traversal, and more — with rule-based + ML confidence scoring.',
  },
  {
    icon: Activity,
    color: '#22c55e',
    title: 'Threat Intelligence Dashboard',
    desc: 'Beautiful visualizations of attack patterns, top offenders, and temporal threat distributions.',
  },
  {
    icon: Globe,
    color: '#eab308',
    title: 'Multi-Format Log Support',
    desc: 'Ingests Apache, Nginx, syslog, and custom log formats. Auto-detects format on upload.',
  },
  {
    icon: Lock,
    color: '#ff6b35',
    title: 'Secure JWT Auth',
    desc: 'Enterprise-grade authentication with rotating refresh tokens and role-based access control.',
  },
]

const STATS = [
  { value: '99.7%', label: 'Detection Accuracy' },
  { value: '<50ms', label: 'Real-time Latency' },
  { value: '6+', label: 'Attack Vectors' },
  { value: '∞', label: 'Log Scale' },
]

export default function Landing() {
  const { user } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    if (user) navigate('/dashboard', { replace: true })
  }, [user, navigate])

  return (
    <div className="min-h-screen text-white overflow-x-hidden"
      style={{ background: 'radial-gradient(ellipse at top left, #0a1628 0%, #060b18 50%, #020508 100%)' }}>
      <CyberBackground />

      {/* ── Navbar ──────────────────────────────────────────── */}
      <nav className="relative z-10 flex items-center justify-between px-8 py-5 border-b border-white/5"
        style={{ backdropFilter: 'blur(12px)' }}>
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg flex items-center justify-center"
            style={{ background: 'linear-gradient(135deg, #00d4ff22, #00d4ff44)', border: '1px solid #00d4ff55' }}>
            <Shield className="h-5 w-5 text-sentinel-cyan" />
          </div>
          <div>
            <p className="text-sm font-bold tracking-wide leading-tight">ANBU</p>
            <p className="text-xs text-sentinel-cyan font-mono tracking-widest leading-tight">SENTINEL</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <Link to="/login"
            className="text-sm text-slate-400 hover:text-white transition-colors px-4 py-2">
            Sign In
          </Link>
          <Link to="/signup" className="btn-primary text-sm">
            Get Started <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </nav>

      {/* ── Hero ─────────────────────────────────────────────── */}
      <section className="relative z-10 text-center px-6 pt-24 pb-16">
        {/* Badge */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full mb-8 text-xs font-semibold"
          style={{
            background: 'rgba(0,212,255,0.08)',
            border: '1px solid rgba(0,212,255,0.25)',
            color: '#00d4ff',
          }}>
          <Zap className="h-3.5 w-3.5" /> AI-Powered Network Security Intelligence
        </motion.div>

        <motion.h1 initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="text-5xl md:text-7xl font-black mb-6 leading-tight">
          <span className="text-white">Detect Threats</span>
          <br />
          <span style={{
            background: 'linear-gradient(135deg, #00d4ff, #a855f7)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}>Before They Strike</span>
        </motion.h1>

        <motion.p initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="text-lg text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed">
          ANBU Sentinel is an AI-powered network anomaly detection system that streams your logs in real-time,
          detects threats instantly, and narrates incidents in plain English using AWS Bedrock's Claude.
        </motion.p>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="flex items-center justify-center gap-4 flex-wrap">
          <Link to="/signup" className="btn-primary text-base px-8 py-3">
            Start Monitoring Free <ChevronRight className="h-5 w-5" />
          </Link>
          <Link to="/login"
            className="flex items-center gap-2 px-8 py-3 rounded-lg text-base text-slate-300 border border-sentinel-border hover:border-sentinel-cyan hover:text-white transition-all">
            Sign In
          </Link>
        </motion.div>

        {/* Live threat ticker */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }}
          className="mt-12 max-w-lg mx-auto">
          <p className="text-xs text-slate-500 font-mono mb-2 text-left">▶ LIVE THREAT FEED</p>
          <ThreatTicker />
        </motion.div>
      </section>

      {/* ── Stats ────────────────────────────────────────────── */}
      <section className="relative z-10 py-16 px-6">
        <div className="max-w-4xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-4">
          {STATS.map((s, i) => (
            <motion.div key={s.label}
              initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08 }}
              className="text-center p-6 rounded-2xl"
              style={{
                background: 'linear-gradient(135deg, rgba(13,21,38,0.9), rgba(17,30,53,0.7))',
                border: '1px solid rgba(0,212,255,0.12)',
              }}>
              <p className="text-3xl font-black text-white font-mono mb-1">{s.value}</p>
              <p className="text-xs text-slate-400">{s.label}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ── Features ──────────────────────────────────────────── */}
      <section className="relative z-10 py-16 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-3">Everything You Need</h2>
            <p className="text-slate-400">Enterprise-grade security intelligence, beautifully packaged.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {FEATURES.map((f, i) => (
              <motion.div key={f.title}
                initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.07 }}
                className="p-6 rounded-2xl group hover:-translate-y-1 transition-all duration-300"
                style={{
                  background: 'linear-gradient(135deg, rgba(13,21,38,0.95), rgba(17,30,53,0.8))',
                  border: '1px solid rgba(30,58,95,0.6)',
                }}>
                <div className="h-11 w-11 rounded-xl flex items-center justify-center mb-4"
                  style={{ background: `${f.color}18`, border: `1px solid ${f.color}44` }}>
                  <f.icon className="h-5 w-5" style={{ color: f.color }} />
                </div>
                <h3 className="text-sm font-bold text-white mb-2">{f.title}</h3>
                <p className="text-xs text-slate-400 leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ──────────────────────────────────────────────── */}
      <section className="relative z-10 py-24 px-6">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="max-w-2xl mx-auto text-center p-12 rounded-3xl"
          style={{
            background: 'linear-gradient(135deg, rgba(0,212,255,0.08), rgba(168,85,247,0.06))',
            border: '1px solid rgba(0,212,255,0.2)',
          }}>
          <Shield className="h-12 w-12 text-sentinel-cyan mx-auto mb-4 opacity-80" />
          <h2 className="text-3xl font-bold text-white mb-3">Ready to Secure Your Network?</h2>
          <p className="text-slate-400 mb-8">
            Start detecting threats in minutes. No credit card required.
          </p>
          <Link to="/signup" className="btn-primary text-base px-10 py-3.5">
            Launch ANBU Sentinel <ArrowRight className="h-5 w-5" />
          </Link>
        </motion.div>
      </section>

      {/* ── Footer ───────────────────────────────────────────── */}
      <footer className="relative z-10 border-t border-white/5 py-8 px-6 text-center">
        <div className="flex items-center justify-center gap-2 mb-2">
          <Shield className="h-4 w-4 text-sentinel-cyan" />
          <span className="text-sm font-bold text-white">ANBU SENTINEL</span>
        </div>
        <p className="text-xs text-slate-500">
          AI-Powered Network Anomaly Detection & Incident Intelligence
        </p>
      </footer>
    </div>
  )
}
