import { useEffect, useRef, useState } from 'react'
import { createWebSocket, fetchStatus, tunnelStart, tunnelStop } from '../api'
import type { HeliosEvent, Status, TunnelState } from '../types'

const MAX_EVENTS = 60

export type WsStatus = 'connecting' | 'connected' | 'disconnected'

export function useHelios() {
  const [status, setStatus] = useState<Status | null>(null)
  const [events, setEvents] = useState<Array<HeliosEvent & { ts: string }>>([])
  const [wsStatus, setWsStatus] = useState<WsStatus>('connecting')
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    fetchStatus().then(setStatus).catch(console.error)

    const ws = createWebSocket()
    wsRef.current = ws

    ws.onopen = () => setWsStatus('connected')
    ws.onclose = () => setWsStatus('disconnected')
    ws.onerror = () => setWsStatus('disconnected')

    ws.onmessage = (e: MessageEvent) => {
      const event: HeliosEvent = JSON.parse(e.data as string)
      const ts = new Date().toLocaleTimeString()

      if (event.type === 'state_changed') {
        setStatus(s => s ? { ...s, state: event.state } : s)
      }
      setEvents(prev => [{ ...event, ts }, ...prev].slice(0, MAX_EVENTS))
    }

    return () => ws.close()
  }, [])

  const connect = async () => {
    await tunnelStart()
    // L'état sera mis à jour via WebSocket — pas besoin de re-fetch.
  }

  const disconnect = async () => {
    await tunnelStop()
  }

  const currentState: TunnelState = status?.state ?? 'down'

  return { status, events, wsStatus, currentState, connect, disconnect }
}
