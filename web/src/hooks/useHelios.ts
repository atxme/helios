import { useCallback, useEffect, useRef, useState } from 'react'
import {
  createWebSocket,
  fetchStatus,
  releaseCaptivePortal,
  setSplitTunnel,
  tunnelStart,
  tunnelStop,
} from '../api'
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
  const [tunnelUpSince, setTunnelUpSince] = useState<Date | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const backoffRef = useRef(1000)
  // Set on unmount so that a socket closing afterwards cannot schedule a
  // reconnection behind the hook's back.
  const stoppedRef = useRef(false)

  const pushEvent = useCallback((event: DisplayEvent) => {
    const ts = new Date().toLocaleTimeString('fr-FR', {
      hour12: false,
      timeZone: 'Europe/Paris',
    })
    setEvents(previous => [{ ...event, ts }, ...previous].slice(0, MAX_EVENTS))
  }, [])

  const refresh = useCallback(async () => {
    const next = await fetchStatus()
    setStatus(next)
    setError(null)
    return next
  }, [])

  const connectWebSocket = useCallback(() => {
    if (stoppedRef.current) return
    const readyState = wsRef.current?.readyState
    if (readyState === WebSocket.OPEN || readyState === WebSocket.CONNECTING) return
    if (reconnectRef.current) {
      clearTimeout(reconnectRef.current)
      reconnectRef.current = null
    }
    setWsStatus('connecting')

    const ws = createWebSocket()
    wsRef.current = ws
    // Events from a socket that is no longer the current one (replaced, or
    // closed on unmount) must not touch state nor schedule a reconnection.
    const isCurrent = () => !stoppedRef.current && wsRef.current === ws

    ws.onopen = () => {
      if (!isCurrent()) return
      setWsStatus('connected')
      backoffRef.current = 1000
    }

    ws.onmessage = (message: MessageEvent) => {
      if (!isCurrent()) return
      const event: HeliosEvent = JSON.parse(message.data as string)
      if (event.type === 'state_changed') {
        setStatus(current => current ? { ...current, state: event.state } : current)
        if (event.state === 'up') setTunnelUpSince(current => current ?? new Date())
        else setTunnelUpSince(null)
      } else if (event.type === 'telemetry') {
        setTelemetry(previous => [...previous.slice(-(MAX_TELEMETRY - 1)), {
          rx_bps: event.rx_bps,
          tx_bps: event.tx_bps,
          rx_pps: event.rx_pps,
          tx_pps: event.tx_pps,
        }])
        return
      } else if (event.type === 'split_tunnel_changed') {
        setStatus(current => current ? { ...current, split_tunnel_cidrs: event.cidrs } : current)
      } else if (event.type === 'mtu_discovered') {
        setStatus(current => current ? { ...current, mss_clamp: event.mss } : current)
      } else if (event.type === 'captive_portal_detected') {
        setStatus(current => current ? { ...current, captive_portal_gateway: event.gateway } : current)
      }
      pushEvent(event)
    }

    ws.onclose = () => {
      if (!isCurrent()) return
      wsRef.current = null
      setWsStatus('disconnected')
      const delay = Math.min(backoffRef.current, 30_000)
      backoffRef.current = delay * 2
      reconnectRef.current = setTimeout(() => {
        reconnectRef.current = null
        connectWebSocket()
      }, delay)
    }
    ws.onerror = () => ws.close()
  }, [pushEvent])

  useEffect(() => {
    refresh().catch(() => setError('Impossible de joindre heliosd sur son adresse d’administration'))
    stoppedRef.current = false
    connectWebSocket()
    return () => {
      stoppedRef.current = true
      if (reconnectRef.current) {
        clearTimeout(reconnectRef.current)
        reconnectRef.current = null
      }
      // Closing a socket still in CONNECTING aborts the handshake; its close
      // event is then ignored by the guard above.
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [connectWebSocket, refresh])

  const run = async (action: () => Promise<void>) => {
    setError(null)
    try {
      await action()
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
      throw cause
    }
  }

  const currentState: TunnelState = status?.state ?? 'down'

  return {
    status,
    error,
    events,
    telemetry,
    wsStatus,
    currentState,
    tunnelUpSince,
    refresh,
    connect: () => run(tunnelStart),
    disconnect: () => run(tunnelStop),
    releaseCaptivePortal: () => run(releaseCaptivePortal),
    updateSplitTunnel: (cidrs: string[]) => run(() => setSplitTunnel(cidrs)),
  }
}
