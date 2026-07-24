import { describe, expect, it } from 'vitest'

import type { ClientProfile } from '../types'
import { elapsed, formatBps, postureMeta, protectionMeta, stateMeta } from './state'

const profile = (over: Partial<ClientProfile> = {}): ClientProfile => ({
  name: 'site-a',
  endpoint: '203.0.113.10:51820',
  private_key: '',
  peer_public_key: '',
  preshared_key: null,
  address: null,
  allowed_ips: '0.0.0.0/0',
  persistent_keepalive: 25,
  heliosd_url: null,
  ...over,
})

describe('Orion UI state', () => {
  it('only indicates active traffic on a fresh WireGuard handshake', () => {
    expect(stateMeta('up')).toMatchObject({ active: true, transitioning: false })
    for (const state of ['down', 'connecting', 'failed', 'captive_portal'] as const) {
      expect(stateMeta(state).active).toBe(false)
    }
  })

  it('only reports "exposed" if the adapter is unmounted', () => {
    // Orion's fail-open invariant (ADR-001 §3 bis): adapter mounted =
    // WireGuard drops packets, regardless of the tunnel state.
    for (const state of ['down', 'connecting', 'up', 'failed', 'captive_portal'] as const) {
      expect(postureMeta(state, false).posture).toBe('exposed')
    }
    expect(postureMeta('up', true).posture).toBe('protected')
    for (const state of ['down', 'connecting', 'failed', 'captive_portal'] as const) {
      expect(postureMeta(state, true).posture).toBe('held')
    }
  })

  it('does not confuse a static PSK with a PQC PSK', () => {
    // The same WireGuard slot, two different facts: one never rotates.
    expect(protectionMeta(profile(), 'ml_kem', 'up').tone).toBe('pqc')
    expect(protectionMeta(profile(), 'static', 'up').tone).toBe('static')
    expect(protectionMeta(profile(), 'none', 'up').tone).toBe('classic')

    const pqc = protectionMeta(profile(), 'ml_kem', 'up')
    expect(pqc.label).toContain('ML-KEM-768')
    expect(protectionMeta(profile(), 'static', 'up').label).not.toContain('ML-KEM')
  })

  it('reads the PQC PSK from the event, never from the profile', () => {
    // A perfectly established PQC tunnel shows `preshared_key: null` — the
    // secret isn't persisted. Deducing protection from the profile would
    // show "no PSK" on the best-protected case.
    const helios = profile({ heliosd_url: 'http://100.64.0.1:8080' })
    expect(protectionMeta(helios, 'ml_kem', 'up').tone).toBe('pqc')

    // And the reverse: a filled-in `preshared_key` always denotes a static one.
    const manual = profile({ preshared_key: 'cHNr' })
    expect(protectionMeta(manual, null, 'down').tone).toBe('static')
  })

  it('announces the wait rather than the acquired state while nothing is decided', () => {
    const helios = profile({ heliosd_url: 'http://100.64.0.1:8080' })
    expect(protectionMeta(helios, null, 'connecting').tone).toBe('pending')
    expect(protectionMeta(helios, null, 'down').tone).toBe('pending')
    // Without an internal URL, no negotiation will happen: nothing to wait for.
    expect(protectionMeta(profile(), null, 'down').tone).toBe('classic')
    expect(protectionMeta(null, null, 'down').tone).toBe('classic')
  })

  it('formats a duration without a negative value', () => {
    expect(elapsed(null, 1_000)).toBeNull()
    expect(elapsed(10_000, 9_000)).toBe('00:00:00')
    expect(elapsed(0, 3_661_000)).toBe('01:01:01')
  })

  it('formats throughput in the expected unit', () => {
    expect(formatBps(42)).toBe('42 B/s')
    expect(formatBps(12_500)).toBe('13 KB/s')
    expect(formatBps(1_500_000)).toBe('1.5 MB/s')
  })
})
