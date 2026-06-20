// Les URLs sont relatives : en dev Vite proxy /api et /ws vers heliosd:8080,
// en prod tout vient du même serveur Axum.
import type { Status } from './types'

export async function fetchStatus(): Promise<Status> {
  const res = await fetch('/api/status')
  if (!res.ok) throw new Error(`status ${res.status}`)
  return res.json()
}

export async function tunnelStart(): Promise<void> {
  await fetch('/api/tunnel/start', { method: 'POST' })
}

export async function tunnelStop(): Promise<void> {
  await fetch('/api/tunnel/stop', { method: 'POST' })
}

export function createWebSocket(): WebSocket {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return new WebSocket(`${proto}//${window.location.host}/ws`)
}
