import { useState, useEffect, useRef, useCallback } from 'react'

export interface WSLogLine {
  type: string
  payload: Record<string, unknown>
  timestamp?: string
}

export function useWebSocket(path: string, autoConnect = false) {
  const [messages, setMessages] = useState<WSLogLine[]>([])
  const [connected, setConnected] = useState(false)
  const [status, setStatus] = useState<'idle' | 'connecting' | 'connected' | 'disconnected'>('idle')
  const ws = useRef<WebSocket | null>(null)

  const connect = useCallback(() => {
    if (ws.current?.readyState === WebSocket.OPEN) return
    setStatus('connecting')
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    // Use current host (port 5173 in dev, which Vite proxies to backend 8000)
    const host = window.location.host
    const url = `${protocol}://${host}${path}`
    console.log('[WS] Connecting to:', url)
    ws.current = new WebSocket(url)

    ws.current.onopen = () => {
      console.log('[WS] Connected')
      setConnected(true)
      setStatus('connected')
    }
    ws.current.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data) as WSLogLine
        setMessages(prev => [...prev.slice(-500), msg])  // keep last 500
      } catch { /* ignore */ }
    }
    ws.current.onclose = (e) => {
      console.log('[WS] Closed:', e.code, e.reason)
      setConnected(false)
      setStatus('disconnected')
    }
    ws.current.onerror = (e) => {
      console.error('[WS] Error:', e)
      setConnected(false)
      setStatus('disconnected')
    }
  }, [path])

  const disconnect = useCallback(() => {
    ws.current?.close()
    ws.current = null
    setConnected(false)
    setStatus('disconnected')
  }, [])

  const send = useCallback((data: string) => {
    if (ws.current?.readyState === WebSocket.OPEN) ws.current.send(data)
  }, [])

  const clearMessages = useCallback(() => setMessages([]), [])

  useEffect(() => {
    if (autoConnect) connect()
    return () => { ws.current?.close() }
  }, [autoConnect, connect])

  return { messages, connected, status, connect, disconnect, send, clearMessages }
}
