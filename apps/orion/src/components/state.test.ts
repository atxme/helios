import { describe, expect, it } from 'vitest'

import type { ClientProfile, ProtectionMode } from '../types'
import {
  elapsed,
  formatBps,
  modeAllowed,
  modeLevel,
  postureMeta,
  protectionMeta,
  stateMeta,
} from './state'

const profile = (over: Partial<ClientProfile> = {}): ClientProfile => ({
  name: 'site-a',
  endpoint: '203.0.113.10:51820',
  profile_type: 'classic',
  peer_public_key: '',
  public_key: null,
  has_private_key: false,
  has_static_psk: false,
  address: null,
  address_v6: null,
  allowed_ips: '0.0.0.0/0, ::/0',
  ipv6_uncaptured_full_tunnel: false,
  persistent_keepalive: 25,
  heliosd_url: null,
  ssh_target: null,
  key_negotiation: null,
  ...over,
})

const negotiating = (mode: ProtectionMode, minimum_mode: ProtectionMode = 'classic') =>
  profile({
    key_negotiation: {
      mode,
      minimum_mode,
      endpoint: '203.0.113.10:51821',
      server_name: 'vpn.example.net',
      gateway_ca_der: 'MIIB',
      gateway_pq_certificate: 'e30=',
      identity: 'orion-site-a',
    },
  })

describe('Orion UI state', () => {
  it('only indicates active traffic on a recent WireGuard handshake', () => {
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
      expect(postureMeta(state, true).posture).toBe('blocked')
    }
  })

  it('does not confuse a static PSK with a PQC PSK', () => {
    // The same WireGuard slot, two different facts: one never rotates.
    expect(protectionMeta(profile(), 'ml_kem', 'up').tone).toBe('pqc')
    expect(protectionMeta(profile(), 'static', 'up').tone).toBe('static')
    expect(protectionMeta(profile(), 'none', 'up').tone).toBe('classic')

    expect(protectionMeta(profile(), 'static', 'up').label).not.toContain('ML-KEM')
  })

  it('distinguishes a negotiated PQC PSK from one obtained after the tunnel', () => {
    // Same secret, different security property: the upgrade path let the
    // FIRST handshake happen without any PSK, which is exactly the window
    // negotiation exists to close. Showing them identically would erase the
    // only difference that matters.
    const negotiated = protectionMeta(negotiating('ml_kem'), 'ml_kem', 'up')
    const upgraded = protectionMeta(profile({ heliosd_url: 'http://100.64.0.1:8080' }), 'ml_kem', 'up')

    expect(negotiated.tone).toBe('pqc')
    expect(upgraded.tone).toBe('pqc')
    // The wording is short now, but the distinction it carries is the whole
    // point: one has protected every handshake of this tunnel, the other has
    // not. Asserting on the *fact* rather than on a phrase that will be
    // rewritten again.
    expect(negotiated.label).not.toBe(upgraded.label)
    expect(negotiated.detail).toContain('avant le premier handshake')
    expect(upgraded.detail).toContain('après le montage')
  })

  it('reads the PQC PSK from the event, never from the profile', () => {
    // A perfectly established PQC tunnel shows `preshared_key: null` — the
    // secret isn't persisted. Deducing protection from the profile would
    // show "no PSK" on the best-protected case.
    const helios = profile({ heliosd_url: 'http://100.64.0.1:8080' })
    expect(protectionMeta(helios, 'ml_kem', 'up').tone).toBe('pqc')

    // And the reverse: the presence flag always denotes a static one, without
    // carrying the value across the IPC boundary.
    const manual = profile({ has_static_psk: true })
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

  it('announces the mode about to be negotiated rather than the legacy guess', () => {
    // Helios never substitutes another mode: what the profile requests is a
    // sound announcement — but still an announcement, hence `pending`.
    expect(protectionMeta(negotiating('ml_kem'), null, 'down').tone).toBe('pending')
    expect(protectionMeta(negotiating('static_psk'), null, 'down').tone).toBe('static')
    expect(protectionMeta(negotiating('classic'), null, 'down').tone).toBe('classic')

    // The negotiated mode wins over the legacy internal-URL clue: a profile
    // that negotiates in classic mode must not be shown as awaiting a PQC PSK.
    const both = negotiating('classic')
    both.heliosd_url = 'http://100.64.0.1:8080'
    expect(protectionMeta(both, null, 'down').tone).toBe('classic')

    // And the event still overrides everything.
    expect(protectionMeta(negotiating('ml_kem'), 'none', 'up').tone).toBe('classic')
  })

  it('only lets a mode be chosen at or above the floor', () => {
    // The client refuses a mode below its floor before touching the network,
    // exactly as the gateway does; the screen must not offer it.
    expect(modeLevel('classic')).toBeLessThan(modeLevel('static_psk'))
    expect(modeLevel('static_psk')).toBeLessThan(modeLevel('ml_kem'))

    expect(modeAllowed('ml_kem', 'ml_kem')).toBe(true)
    expect(modeAllowed('static_psk', 'ml_kem')).toBe(false)
    expect(modeAllowed('classic', 'ml_kem')).toBe(false)
    expect(modeAllowed('classic', 'classic')).toBe(true)
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
