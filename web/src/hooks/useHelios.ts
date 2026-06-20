import { useCallback, useEffect, useRef, useState } from 'react'
import { createWebSocket, fetchStatus, tunnelStart, tunnelStop } from '../api'
import type { DisplayEvent, HeliosEvent, Status, TelemetrySample, TunnelState } from '../types'

const MAX_EVENTS = 100
const MAX_TELEMETRY = 60

export type WsStatus = 'connecting' | 'connected' | 'disconnected'

export function useHelios() {
  const [status, setStatus] = useState<Status | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [events, setEvents] = useState<Array<DisplayEvent & { ts: string }>>([])
  const [telemetry, setTelemetry] = useState<TelemetrySample[]>([])
  const [wsStatus, setWsStatus] = useState<WsStatus>('connecting')
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const backoffRef = useRef(1000)

  const pushEvent = useCallback((ev: DisplayEvent) => {
    const ts = new Date().toLocaleTimeString('fr-FR', { hour12: false })
    setEvents(prev => [{ ...ev, ts }, ...prev].slice(0, MAX_EVENTS))
  }, [])

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    setWsStatus('connecting')

    const ws = createWebSocket()
    wsRef.current = ws

    ws.onopen = () => {
      setWsStatus('connected')
      backoffRef.current = 1000
    }

    ws.onmessage = (e: MessageEvent) => {
      const ev: HeliosEvent = JSON.parse(e.data as string)
      if (ev.type === 'state_changed') {
        setStatus(s => s ? { ...s, state: ev.state } : s)
      } else if (ev.type === 'telemetry') {
        setTelemetry(prev => [...prev.slice(-(MAX_TELEMETRY - 1)), {
          rx_bps: ev.rx_bps, tx_bps: ev.tx_bps, rx_pps: ev.rx_pps, tx_pps: ev.tx_pps,
        }])
        return
      }
      pushEvent(ev)
    }

    ws.onclose = () => {
      setWsStatus('disconnected')
      // Reconnexion automatique avec backoff exponentiel (max 30s)
      const delay = Math.min(backoffRef.current, 30_000)
      backoffRef.current = delay * 2
      reconnectRef.current = setTimeout(() => connect(), delay)
    }

    ws.onerror = () => ws.close()
  }, [pushEvent])

  useEffect(() => {
    fetchStatus()
      .then(s => { setStatus(s); setError(null) })
      .catch(() => setError('Impossible de joindre le daemon — vérifiez que heliosd tourne sur :8080'))
    connect()
    return () => {
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  const handleConnect = async () => {
    await tunnelStart()
  }

  const handleDisconnect = async () => {
    await tunnelStop()
  }

  const currentState: TunnelState = status?.state ?? 'down'

  return { status, error, events, telemetry, wsStatus, currentState, connect: handleConnect, disconnect: handleDisconnect }
}
