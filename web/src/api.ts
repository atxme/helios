// In dev, Vite proxies /api and /ws to heliosd. In production, the embedded
// interface and the API are served by the same Axum process.
import type {
  CertificateDomain,
  GatewayDecisionView,
  GatewayRenewalRequest,
  GatewayRenewalView,
  CommandResponse,
  FinalizedRelease,
  FirewallRules,
  Health,
  PeerAdmission,
  PeerSummary,
  Status,
  Trust,
  UpdateStatus,
} from './types'

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
export const fetchHealth = () => json<Health>('/api/health')
export const tunnelStart = () => command('/api/tunnel/start')
export const tunnelStop = () => command('/api/tunnel/stop')
export const releaseCaptivePortal = () => command('/api/captive-portal/release')
export const setSplitTunnel = (cidrs: string[]) => command('/api/split-tunnel', { cidrs })

/**
 * Admits a client, and returns it as the gateway recorded it.
 *
 * Unlike the tunnel commands this does not go through `command()`: admission
 * answers with the peer itself — most importantly the VIP the gateway derived
 * — and an operator who admitted a client needs that address to hand it over.
 */
export const admitPeer = (peer: PeerAdmission) =>
  json<PeerSummary>('/api/peers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(peer),
  })

/**
 * Removes a client from admission.
 *
 * Not a cryptographic revocation: the peer drops at its next handshake
 * attempt, there is no revocation list (ADR-004).
 */
export const revokePeer = (name: string) =>
  json<PeerSummary>('/api/peers/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })

export const fetchFirewallRules = () => json<FirewallRules>('/api/firewall/rules')
export const applyFirewallRules = (rules: string) => command('/api/firewall/rules', { rules })

export const fetchUpdateStatus = () => json<UpdateStatus>('/api/update')

/**
 * The trust domain, or `null` when this gateway has none.
 *
 * `404` is a *state*, not a failure: a gateway that has never run
 * `heliosd init-trust-domain` holds no registry, and an absent registry is not
 * an empty one — the lifecycle routes stay closed. Folding it into the error
 * path would put "le démon ne répond pas" on screen for a gateway answering
 * perfectly, and send the operator looking at the network.
 */
export async function fetchCertificateDomain(): Promise<CertificateDomain | null> {
  const response = await fetch('/api/certificates')
  if (response.status === 404) return null
  if (!response.ok) {
    const detail = await response.text()
    throw new Error(`HTTP ${response.status}${detail ? ` — ${detail}` : ''}`)
  }
  return response.json() as Promise<CertificateDomain>
}

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

/**
 * The gateway's own identity, driven from the console (spec §12.2).
 *
 * These three refuse with `409` and a reason in the body, and the reason is
 * the point: unlike the public negotiation surface — where a precise refusal
 * would be an oracle — this one is behind the admin authentication, and an
 * operator sent to the daemon logs during a renewal is sent there at the worst
 * possible moment.
 */
async function gatewayAction<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (response.ok) return response.json() as Promise<T>
  const detail = await response.text()
  throw new Error(refusalMessage(detail) ?? `HTTP ${response.status}`)
}

/** The refusal reason, whether the daemon answered JSON or plain text. */
function refusalMessage(detail: string): string | null {
  if (!detail) return null
  try {
    const parsed = JSON.parse(detail) as { message?: unknown }
    return typeof parsed.message === 'string' ? parsed.message : detail
  } catch {
    return detail
  }
}

export const prepareGatewayRenewal = (request: GatewayRenewalRequest) =>
  gatewayAction<GatewayRenewalView>('/api/certificates/gateway-renewal', request)

export const installGatewayTransition = (transition: unknown) =>
  gatewayAction<GatewayDecisionView>('/api/certificates/gateway-transition', transition)

export const abortGatewayTransition = (abort: unknown) =>
  gatewayAction<GatewayDecisionView>('/api/certificates/gateway-transition/abort', abort)
