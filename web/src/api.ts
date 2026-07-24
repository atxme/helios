// In dev, Vite proxies /api and /ws to heliosd. In production, the embedded
// interface and the API are served by the same Axum process.
import type { CommandResponse, FinalizedRelease, FirewallRules, Status, Trust, UpdateStatus } from './types'

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init)
  if (!response.ok) {
    const detail = await response.text()
    throw new Error(`HTTP ${response.status}${detail ? ` — ${detail}` : ''}`)
  }
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

export const fetchUpdateStatus = () => json<UpdateStatus>('/api/update')

export async function stageUpdate(manifest: unknown): Promise<FinalizedRelease> {
  const response = await json<{ release: FinalizedRelease }>('/api/update/stage', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ manifest }),
  })
  return response.release
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  const block = 8192
  for (let offset = 0; offset < bytes.length; offset += block) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + block))
  }
  return btoa(binary)
}

export async function uploadUpdateBinary(
  releaseSequence: number,
  file: File,
  progress: (uploaded: number, total: number) => void,
): Promise<FinalizedRelease> {
  const chunkSize = 256 * 1024
  let offset = 0
  while (offset < file.size) {
    const bytes = new Uint8Array(await file.slice(offset, offset + chunkSize).arrayBuffer())
    const response = await json<{ next_offset: number }>('/api/update/chunk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        release_sequence: releaseSequence,
        offset,
        data: bytesToBase64(bytes),
      }),
    })
    offset = response.next_offset
    progress(offset, file.size)
  }
  const response = await json<{ release: FinalizedRelease }>('/api/update/finalize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ release_sequence: releaseSequence }),
  })
  return response.release
}

export async function activateUpdate(releaseSequence: number, confirmation: string): Promise<void> {
  await json('/api/update/activate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ release_sequence: releaseSequence, confirmation }),
  })
}

export function createWebSocket(): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return new WebSocket(`${protocol}//${window.location.host}/ws`)
}
