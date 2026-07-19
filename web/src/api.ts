// En dev, Vite proxie /api et /ws vers heliosd. En production, l'interface
// embarquée et l'API sont servies par le même processus Axum.
import type { CommandResponse, FirewallRules, Status, Trust } from './types'

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init)
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return response.json() as Promise<T>
}

async function command(url: string, body?: unknown): Promise<void> {
  const response = await json<CommandResponse>(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  })
  if (!response.ok) throw new Error(response.error ?? 'commande refusée')
}

export const fetchStatus = () => json<Status>('/api/status')
export const fetchTrust = () => json<Trust>('/api/trust')
export const tunnelStart = () => command('/api/tunnel/start')
export const tunnelStop = () => command('/api/tunnel/stop')
export const releaseCaptivePortal = () => command('/api/captive-portal/release')
export const setSplitTunnel = (cidrs: string[]) => command('/api/split-tunnel', { cidrs })

export const fetchFirewallRules = () => json<FirewallRules>('/api/firewall/rules')
export const applyFirewallRules = (rules: string) => command('/api/firewall/rules', { rules })

export function createWebSocket(): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return new WebSocket(`${protocol}//${window.location.host}/ws`)
}
