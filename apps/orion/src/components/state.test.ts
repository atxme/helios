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

describe('état de l’interface Orion', () => {
  it('n’indique le trafic actif que sur un handshake WireGuard frais', () => {
    expect(stateMeta('up')).toMatchObject({ active: true, transitioning: false })
    for (const state of ['down', 'connecting', 'failed', 'captive_portal'] as const) {
      expect(stateMeta(state).active).toBe(false)
    }
  })

  it('ne signale « exposé » que si l’adaptateur est démonté', () => {
    // L'invariante fail-open d'Orion (ADR-001 §3 bis) : adaptateur monté =
    // WireGuard jette les paquets, quel que soit l'état du tunnel.
    for (const state of ['down', 'connecting', 'up', 'failed', 'captive_portal'] as const) {
      expect(postureMeta(state, false).posture).toBe('exposed')
    }
    expect(postureMeta('up', true).posture).toBe('protected')
    for (const state of ['down', 'connecting', 'failed', 'captive_portal'] as const) {
      expect(postureMeta(state, true).posture).toBe('held')
    }
  })

  it('ne confond pas un PSK statique avec un PSK PQC', () => {
    // Le même slot WireGuard, deux faits différents : l'un ne tourne jamais.
    expect(protectionMeta(profile(), 'ml_kem', 'up').tone).toBe('pqc')
    expect(protectionMeta(profile(), 'static', 'up').tone).toBe('static')
    expect(protectionMeta(profile(), 'none', 'up').tone).toBe('classic')

    const pqc = protectionMeta(profile(), 'ml_kem', 'up')
    expect(pqc.label).toContain('ML-KEM-768')
    expect(protectionMeta(profile(), 'static', 'up').label).not.toContain('ML-KEM')
  })

  it('lit le PSK PQC de l’événement, jamais du profil', () => {
    // Un tunnel PQC parfaitement établi montre `preshared_key: null` — le
    // secret n'est pas persisté. Déduire la protection du profil afficherait
    // « sans PSK » sur le cas le mieux protégé.
    const helios = profile({ heliosd_url: 'http://100.64.0.1:8080' })
    expect(protectionMeta(helios, 'ml_kem', 'up').tone).toBe('pqc')

    // Et l'inverse : un `preshared_key` renseigné désigne toujours un statique.
    const manuel = profile({ preshared_key: 'cHNr' })
    expect(protectionMeta(manuel, null, 'down').tone).toBe('static')
  })

  it('annonce l’attente plutôt que l’acquis tant que rien n’est tranché', () => {
    const helios = profile({ heliosd_url: 'http://100.64.0.1:8080' })
    expect(protectionMeta(helios, null, 'connecting').tone).toBe('pending')
    expect(protectionMeta(helios, null, 'down').tone).toBe('pending')
    // Sans URL interne, aucune négociation n'aura lieu : rien à attendre.
    expect(protectionMeta(profile(), null, 'down').tone).toBe('classic')
    expect(protectionMeta(null, null, 'down').tone).toBe('classic')
  })

  it('formate une durée sans valeur négative', () => {
    expect(elapsed(null, 1_000)).toBeNull()
    expect(elapsed(10_000, 9_000)).toBe('00:00:00')
    expect(elapsed(0, 3_661_000)).toBe('01:01:01')
  })

  it('formate les débits dans l’unité attendue', () => {
    expect(formatBps(42)).toBe('42 B/s')
    expect(formatBps(12_500)).toBe('13 KB/s')
    expect(formatBps(1_500_000)).toBe('1.5 MB/s')
  })
})
