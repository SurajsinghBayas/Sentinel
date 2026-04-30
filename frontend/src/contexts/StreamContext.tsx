/**
 * StreamContext — Global WebSocket stream state
 * Persists across navigation (lives at the App root).
 *
 * Key design: exposes `lastStreamAt` (a timestamp number) that increments
 * each time a stream finishes. Pages subscribe via useEffect([lastStreamAt])
 * — this fires even if the page mounted AFTER the stream completed.
 *
 * DOM events (sentinel:stream_complete / sentinel:threat_detected) are
 * kept as a secondary, real-time channel for pages that ARE mounted.
 */
import React, {
  createContext, useContext, useRef, useState, useCallback, useEffect
} from 'react'

export interface WSMessage {
  type: string
  payload: Record<string, unknown>
  timestamp?: string
}

interface StreamState {
  messages: WSMessage[]
  connected: boolean
  status: 'idle' | 'connecting' | 'connected' | 'disconnected'
  selectedFile: string
  streamDone: boolean
  lastStreamAt: number           // increments on every stream_complete
  lastStreamPayload: Record<string, unknown> | null
  setSelectedFile: (f: string) => void
  connect: () => void
  disconnect: () => void
  clearMessages: () => void
}

const StreamContext = createContext<StreamState | null>(null)

const MAX_MESSAGES = 1000

// ── DOM events (secondary, real-time channel) ─────────────────────────────────
export const STREAM_COMPLETE_EVENT = 'sentinel:stream_complete'
export const THREAT_DETECTED_EVENT  = 'sentinel:threat_detected'

function fireEvent(name: string, payload: Record<string, unknown>) {
  window.dispatchEvent(new CustomEvent(name, { detail: payload }))
}

// ── useStreamRefresh ─ the PRIMARY hook pages should use ─────────────────────
/**
 * Calls `cb` whenever a stream finishes — including if the component
 * mounted AFTER the stream completed (because it reads from context state,
 * not a DOM event).
 *
 * Usage:  useStreamRefresh(() => fetchData())
 */
export function useStreamRefresh(cb: () => void) {
  const { lastStreamAt } = useStream()
  const firstRun = useRef(true)
  useEffect(() => {
    // Skip the very first mount (lastStreamAt = 0 means no stream yet)
    if (firstRun.current) {
      firstRun.current = false
      if (lastStreamAt === 0) return
    }
    cb()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastStreamAt])
}

// ── useThreatDetected ─ real-time per-threat updates while streaming ─────────
export function useThreatDetected(cb: (payload: Record<string, unknown>) => void) {
  const cbRef = useRef(cb)
  cbRef.current = cb
  useEffect(() => {
    const handler = (e: Event) => cbRef.current((e as CustomEvent).detail)
    window.addEventListener(THREAT_DETECTED_EVENT, handler)
    return () => window.removeEventListener(THREAT_DETECTED_EVENT, handler)
  }, []) // stable — never re-registers
}

// ── legacy alias (kept for backward compat) ───────────────────────────────────
export function useStreamComplete(cb: (detail: Record<string, unknown>) => void) {
  const cbRef = useRef(cb)
  cbRef.current = cb
  useEffect(() => {
    const handler = (e: Event) => cbRef.current((e as CustomEvent).detail)
    window.addEventListener(STREAM_COMPLETE_EVENT, handler)
    return () => window.removeEventListener(STREAM_COMPLETE_EVENT, handler)
  }, [])
}

// ── Provider ──────────────────────────────────────────────────────────────────
export function StreamProvider({ children }: { children: React.ReactNode }) {
  const [messages, setMessages]       = useState<WSMessage[]>([])
  const [connected, setConnected]     = useState(false)
  const [status, setStatus]           = useState<StreamState['status']>('idle')
  const [selectedFile, _setFile]      = useState('apache_access.log')
  const [streamDone, setStreamDone]   = useState(false)
  const [lastStreamAt, setLastStreamAt]       = useState(0)
  const [lastStreamPayload, setLastPayload]   = useState<Record<string, unknown> | null>(null)
  const ws = useRef<WebSocket | null>(null)
  // Track whether stream_complete message was received (to avoid double-emit on close)
  const gotCompleteMsg = useRef(false)

  const buildUrl = (file: string) => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    return `${proto}://${window.location.host}/api/logs/simulate/${file}`
  }

  const onStreamComplete = useCallback((payload: Record<string, unknown>) => {
    setStreamDone(true)
    setLastStreamAt(Date.now())
    setLastPayload(payload)
    fireEvent(STREAM_COMPLETE_EVENT, payload)
  }, [])

  const connect = useCallback(() => {
    if (ws.current?.readyState === WebSocket.OPEN) return
    setStatus('connecting')
    setStreamDone(false)
    gotCompleteMsg.current = false
    const url = buildUrl(selectedFile)
    ws.current = new WebSocket(url)

    ws.current.onopen = () => {
      setConnected(true)
      setStatus('connected')
    }

    ws.current.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data) as WSMessage
        setMessages(prev => {
          const next = [...prev, msg]
          return next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next
        })
        if (msg.type === 'stream_complete') {
          gotCompleteMsg.current = true
          onStreamComplete(msg.payload)
        }
        if (msg.type === 'threat_detected') {
          fireEvent(THREAT_DETECTED_EVENT, msg.payload)
        }
      } catch { /* ignore */ }
    }

    ws.current.onclose = () => {
      setConnected(false)
      setStatus('disconnected')
      // Fallback: if close fires but we never got stream_complete msg, emit now
      if (!gotCompleteMsg.current) {
        // The WS closed (stream finished) but the message was dropped
        // Emit with minimal payload so pages still refresh
        onStreamComplete({ session_id: null, threats_found: 0, fallback: true })
      }
    }

    ws.current.onerror = () => {
      setConnected(false)
      setStatus('disconnected')
    }
  }, [selectedFile, onStreamComplete])

  const disconnect = useCallback(() => {
    ws.current?.close()
    ws.current = null
    setConnected(false)
    setStatus('disconnected')
  }, [])

  const clearMessages = useCallback(() => {
    setMessages([])
    setStreamDone(false)
  }, [])

  const setSelectedFile = useCallback((f: string) => {
    // Always update the file, even if it's the same (allow re-streaming same file)
    disconnect()
    clearMessages()
    _setFile(f)
  }, [disconnect, clearMessages])

  return (
    <StreamContext.Provider value={{
      messages, connected, status, selectedFile, streamDone,
      lastStreamAt, lastStreamPayload,
      setSelectedFile, connect, disconnect, clearMessages,
    }}>
      {children}
    </StreamContext.Provider>
  )
}

export function useStream(): StreamState {
  const ctx = useContext(StreamContext)
  if (!ctx) throw new Error('useStream must be inside <StreamProvider>')
  return ctx
}
