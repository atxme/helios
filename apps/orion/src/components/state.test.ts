import { describe, expect, it } from 'vitest'

import { elapsed, formatBps, stateMeta } from './state'

describe('état de l’interface Orion', () => {
  it('n’indique le trafic actif que sur un handshake WireGuard frais', () => {
    expect(stateMeta('up')).toMatchObject({ active: true, transitioning: false })
    for (const state of ['down', 'connecting', 'failed', 'captive_portal'] as const) {
      expect(stateMeta(state).active).toBe(false)
    }
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
