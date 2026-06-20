// Les URLs sont relatives : en dev Vite proxy /api et /ws vers heliosd:8080,
// en prod tout vient du même serveur Axum.
import type { Status } from './types'

export async function fetchStatus(): Promise<Status> {
  const res = await fetch('/api/status')
  if (!res.ok) throw new Error(`status ${res.status}`)
  return res.json()
}

export async function tunnelStart(profileId?: string): Promise<void> {
  await fetch('/api/tunnel/start', {
    method: 'POST',
    ...(profileId
      ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ profile: profileId }) }
      : {}),
  })
}

export async function tunnelStop(): Promise<void> {
  await fetch('/api/tunnel/stop', { method: 'POST' })
}

export async function connectionApply(ike_proposal: string, esp_proposal: string): Promise<void> {
  await fetch('/api/connections/apply', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ike_proposal, esp_proposal }),
  })
}

export async function fetchFirewallRules(): Promise<import('./types').FirewallRules> {
  const res = await fetch('/api/firewall/rules')
  if (!res.ok) throw new Error(`status ${res.status}`)
  return res.json()
}

export async function applyFirewallRules(rules: string): Promise<void> {
  await fetch('/api/firewall/rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rules }),
  })
}

export function createWebSocket(): WebSocket {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return new WebSocket(`${proto}//${window.location.host}/ws`)
}
